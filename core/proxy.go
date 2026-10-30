package core

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

func (s *Session) startProxies(socks, httpAddress string) error {
	l, e := net.Listen("tcp4", socks)
	if e != nil {
		return errors.New("SOCKS5 loopback port unavailable")
	}
	s.listeners = append(s.listeners, l)
	if httpAddress != "" {
		h, e := net.Listen("tcp4", httpAddress)
		if e != nil {
			return errors.New("HTTP loopback port unavailable")
		}
		s.listeners = append(s.listeners, h)
		server := &http.Server{Handler: http.HandlerFunc(s.serveHTTP), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, MaxHeaderBytes: 32 * 1024, ConnContext: func(ctx context.Context, c net.Conn) context.Context { return ctx }}
		s.servers = append(s.servers, server)
		s.wg.Add(1)
		go func() { defer s.wg.Done(); _ = server.Serve(&limitedListener{Listener: h, limit: s.limit}) }()
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			select {
			case s.limit <- struct{}{}:
				if !s.track(c) {
					<-s.limit
					continue
				}
				s.wg.Add(1)
				go func() { defer s.wg.Done(); defer func() { <-s.limit; s.untrack(c) }(); s.serveSOCKS(c) }()
			default:
				c.Close()
			}
		}
	}()
	return nil
}
func (s *Session) serveSOCKS(client net.Conn) {
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReaderSize(client, 4096)
	var h [2]byte
	if _, e := io.ReadFull(r, h[:]); e != nil || h[0] != 5 || h[1] == 0 {
		return
	}
	methods := make([]byte, int(h[1]))
	if _, e := io.ReadFull(r, methods); e != nil {
		return
	}
	accept := false
	for _, m := range methods {
		if m == 0 {
			accept = true
		}
	}
	if !accept {
		client.Write([]byte{5, 255})
		return
	}
	if _, e := client.Write([]byte{5, 0}); e != nil {
		return
	}
	var req [4]byte
	if _, e := io.ReadFull(r, req[:]); e != nil || req[0] != 5 || req[2] != 0 {
		return
	}
	if req[1] != 1 {
		socksReply(client, 7)
		return
	}
	var host string
	switch req[3] {
	case 1:
		b := make([]byte, 4)
		if _, e := io.ReadFull(r, b); e != nil {
			return
		}
		host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		if _, e := io.ReadFull(r, b); e != nil {
			return
		}
		host = net.IP(b).String()
	case 3:
		n, e := r.ReadByte()
		if e != nil || n == 0 {
			return
		}
		b := make([]byte, int(n))
		if _, e := io.ReadFull(r, b); e != nil {
			return
		}
		host = string(b)
		if strings.ContainsAny(host, "\x00\r\n") {
			socksReply(client, 8)
			return
		}
	default:
		socksReply(client, 8)
		return
	}
	var p [2]byte
	if _, e := io.ReadFull(r, p[:]); e != nil {
		return
	}
	port := binary.BigEndian.Uint16(p[:])
	if port == 0 {
		socksReply(client, 1)
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	remote, e := s.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if e != nil {
		socksReply(client, 4)
		return
	}
	if !s.track(remote) {
		return
	}
	defer s.untrack(remote)
	if e = socksReply(client, 0); e != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	s.relay(client, remote, r)
}
func socksReply(c net.Conn, code byte) error {
	_, e := c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return e
}
func (s *Session) relay(a, b net.Conn, source io.Reader) {
	relayWithIdle(a, b, source, 5*time.Minute)
}

// Successful traffic in either direction refreshes the shared idle deadline.
// This permits active long-running transfers without leaving idle sockets open.
func relayWithIdle(a, b net.Conn, source io.Reader, idle time.Duration) {
	activity := &relayActivity{a: a, b: b, idle: idle}
	activity.touch()
	var wg sync.WaitGroup
	wg.Add(2)
	copySide := func(dst net.Conn, src io.Reader) {
		defer wg.Done()
		_, _ = io.Copy(&activityConn{Conn: dst, activity: activity}, &activityReader{Reader: src, activity: activity})
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go copySide(b, source)
	go copySide(a, b)
	wg.Wait()
}

type relayActivity struct {
	mu   sync.Mutex
	a, b net.Conn
	idle time.Duration
}

func (a *relayActivity) touch() {
	a.mu.Lock()
	defer a.mu.Unlock()
	deadline := time.Now().Add(a.idle)
	_ = a.a.SetDeadline(deadline)
	_ = a.b.SetDeadline(deadline)
}

type activityReader struct {
	io.Reader
	activity *relayActivity
}

func (r *activityReader) Read(p []byte) (int, error) {
	n, e := r.Reader.Read(p)
	if n > 0 {
		r.activity.touch()
	}
	return n, e
}

type activityConn struct {
	net.Conn
	activity *relayActivity
}

func (c *activityConn) Write(p []byte) (int, error) {
	n, e := c.Conn.Write(p)
	if n > 0 {
		c.activity.touch()
	}
	return n, e
}
func removeHop(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, k := range strings.Split(v, ",") {
			h.Del(strings.TrimSpace(k))
		}
	}
	for _, k := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(k)
	}
}
func (s *Session) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		if r.URL.Scheme != "" || r.URL.Path != "" || r.URL.RawQuery != "" {
			http.Error(w, "invalid CONNECT target", 400)
			return
		}
		address := r.Host
		if _, _, e := net.SplitHostPort(address); e != nil {
			http.Error(w, "CONNECT requires host:port", 400)
			return
		}
		ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
		defer cancel()
		remote, e := s.DialContext(ctx, "tcp", address)
		if e != nil {
			http.Error(w, "tunnel destination unavailable", 502)
			return
		}
		if !s.track(remote) {
			http.Error(w, "tunnel stopped", 503)
			return
		}
		defer s.untrack(remote)
		hijack, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "CONNECT unavailable", 500)
			return
		}
		client, rw, e := hijack.Hijack()
		if e != nil {
			return
		}
		if !s.track(client) {
			return
		}
		defer s.untrack(client)
		if _, e = fmt.Fprint(rw, "HTTP/1.1 200 Connection Established\r\n\r\n"); e != nil {
			return
		}
		if e = rw.Flush(); e != nil {
			return
		}
		s.relay(client, remote, rw.Reader)
		return
	}
	if r.URL.Scheme != "http" || r.URL.Host == "" || r.URL.User != nil {
		http.Error(w, "absolute HTTP URL required", 400)
		return
	}
	request := r.Clone(r.Context())
	request.RequestURI = ""
	request.Header = r.Header.Clone()
	removeHop(request.Header)
	tr := &http.Transport{Proxy: nil, DialContext: s.DialContext, DisableKeepAlives: true, ResponseHeaderTimeout: 15 * time.Second, MaxResponseHeaderBytes: 32 * 1024}
	defer tr.CloseIdleConnections()
	response, e := tr.RoundTrip(request)
	if e != nil {
		http.Error(w, "tunnel destination unavailable", 502)
		return
	}
	defer response.Body.Close()
	removeHop(response.Header)
	for k, v := range response.Header {
		for _, value := range v {
			w.Header().Add(k, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

// Limit accepted HTTP connections before net/http starts reading headers.
// SOCKS and HTTP share one hard bound, including idle/slowloris sockets.
type limitedListener struct {
	net.Listener
	limit chan struct{}
}
type limitedConn struct {
	net.Conn
	limit chan struct{}
	once  sync.Once
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		c, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		select {
		case l.limit <- struct{}{}:
			return &limitedConn{Conn: c, limit: l.limit}, nil
		default:
			c.Close()
		}
	}
}
func (c *limitedConn) Close() error { e := c.Conn.Close(); c.once.Do(func() { <-c.limit }); return e }
