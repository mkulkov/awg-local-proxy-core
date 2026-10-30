package core

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

type Status struct {
	State          string     `json:"state"`
	Demo           bool       `json:"demo"`
	ListenerReady  bool       `json:"listener_ready"`
	TunnelVerified bool       `json:"tunnel_verified"`
	HandshakeAt    *time.Time `json:"handshake_at,omitempty"`
	Message        string     `json:"message"`
	SOCKSAddress   string     `json:"socks_address,omitempty"`
	HTTPAddress    string     `json:"http_address,omitempty"`
}
type ConnectOptions struct {
	Config         string `json:"config"`
	SOCKSAddress   string `json:"socks_address"`
	HTTPAddress    string `json:"http_address"`
	ProbeURL       string `json:"probe_url"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}
type Session struct {
	dev       *device.Device
	peer      *device.Peer
	net       *netstack.Net
	config    *Config
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	listeners []net.Listener
	conns     map[net.Conn]struct{}
	servers   []*http.Server
	status    Status
	probeURL  string
	once      sync.Once
	limit     chan struct{}
	wg        sync.WaitGroup
}

func endpoint(ctx context.Context, raw string) (string, error) {
	host, port, e := net.SplitHostPort(raw)
	if e != nil {
		return "", ErrConfig
	}
	if ip, e := netip.ParseAddr(host); e == nil {
		return net.JoinHostPort(ip.String(), port), nil
	}
	ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if e != nil || len(ips) == 0 {
		return "", errors.New("endpoint bootstrap DNS failed")
	}
	return net.JoinHostPort(ips[0].String(), port), nil
}
func makeSession(ctx context.Context, c *Config, resolve bool) (*Session, error) {
	ep := c.fields["peer.endpoint"]
	var e error
	if resolve {
		ep, e = endpoint(ctx, ep)
		if e != nil {
			return nil, e
		}
	} else {
		host, port, _ := net.SplitHostPort(ep)
		if _, e := netip.ParseAddr(host); e != nil {
			ep = net.JoinHostPort("192.0.2.1", port)
		}
	}
	tun, tn, e := netstack.CreateNetTUN(c.Addresses, c.DNS, c.MTU)
	if e != nil {
		return nil, errors.New("userspace stack creation failed")
	}
	d := device.NewDevice(tun, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	if e = d.IpcSet(c.UAPI(ep)); e != nil {
		d.Close()
		return nil, ErrConfig
	}
	// Drop all textual keys/configuration once the engine has consumed UAPI.
	c.fields = nil
	child, cancel := context.WithCancel(context.Background())
	return &Session{dev: d, peer: d.LookupPeer(c.peerKey), net: tn, config: c, ctx: child, cancel: cancel, conns: map[net.Conn]struct{}{}, limit: make(chan struct{}, 128), status: Status{State: "Starting", Message: "Userspace tunnel starting"}}, nil
}
func ValidateConfig(input string) error {
	c, e := ParseConfig(input)
	if e != nil {
		return e
	}
	s, e := makeSession(context.Background(), c, false)
	if e != nil {
		return e
	}
	s.Close()
	return nil
}

func Connect(ctx context.Context, o ConnectOptions) (*Session, error) {
	c, e := ParseConfig(o.Config)
	if e != nil {
		return nil, e
	}
	if o.SOCKSAddress == "" {
		o.SOCKSAddress = "127.0.0.1:1080"
	}
	if validateListen(o.SOCKSAddress) != nil || o.HTTPAddress != "" && validateListen(o.HTTPAddress) != nil || o.HTTPAddress == o.SOCKSAddress {
		return nil, errors.New("invalid loopback listener settings")
	}
	u, e := url.Parse(o.ProbeURL)
	if e != nil || u == nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" || len(o.ProbeURL) > 2048 {
		return nil, errors.New("explicit HTTP(S) tunnel probe URL required")
	}
	s, e := makeSession(ctx, c, true)
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()
	if e = s.dev.Up(); e != nil {
		return nil, errors.New("userspace device startup failed")
	}
	s.mu.Lock()
	s.status.State = "Connecting"
	s.mu.Unlock()
	if s.peer == nil || s.peer.SendHandshakeInitiation(false) != nil {
		return nil, errors.New("handshake initiation failed")
	}
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for s.handshake() == nil {
		select {
		case <-ctx.Done():
			return nil, errors.New("handshake timed out")
		case <-tick.C:
		}
	}
	s.probeURL = o.ProbeURL
	if e = s.probe(ctx); e != nil {
		return nil, e
	}
	hs := s.handshake()
	if hs == nil {
		return nil, errors.New("tunnel handshake unconfirmed")
	}
	if e = s.startProxies(o.SOCKSAddress, o.HTTPAddress); e != nil {
		return nil, e
	}
	s.mu.Lock()
	s.status = Status{State: "Connected", ListenerReady: true, TunnelVerified: true, HandshakeAt: hs, Message: "Handshake and explicit tunnel probe confirmed", SOCKSAddress: o.SOCKSAddress, HTTPAddress: o.HTTPAddress}
	s.mu.Unlock()
	ok = true
	return s, nil
}

func (s *Session) probe(ctx context.Context) error {
	transport := &http.Transport{Proxy: nil, DialContext: s.DialContext, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 32 * 1024, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	probe, e := http.NewRequestWithContext(ctx, http.MethodGet, s.probeURL, nil)
	if e != nil {
		return errors.New("invalid probe")
	}
	response, e := transport.RoundTrip(probe)
	if e != nil {
		return errors.New("tunnel probe failed")
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 400 {
		return errors.New("tunnel probe rejected")
	}
	hs := s.handshake()
	if hs == nil {
		return errors.New("tunnel handshake unconfirmed")
	}
	s.mu.Lock()
	s.status.State = "Connected"
	s.status.TunnelVerified = true
	s.status.HandshakeAt = hs
	s.status.Message = "Handshake and explicit tunnel probe confirmed"
	s.mu.Unlock()
	return nil
}

func (s *Session) CheckTunnel(ctx context.Context) error {
	if e := s.probe(ctx); e != nil {
		s.Close()
		return e
	}
	return nil
}
func (s *Session) degraded() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status.ListenerReady {
		s.status.State = "Degraded"
		s.status.TunnelVerified = false
		s.status.Message = "Tunnel traffic failed; no direct fallback"
	}
}
func validateListen(address string) error {
	h, p, e := net.SplitHostPort(address)
	if e != nil || h != "127.0.0.1" {
		return errors.New("IPv4 loopback required")
	}
	n, e := strconv.Atoi(p)
	if e != nil || n < 1 || n > 65535 {
		return errors.New("invalid listener port")
	}
	return nil
}
func (s *Session) handshake() *time.Time {
	w := &handshakeWriter{}
	defer clear(w.line)
	if s.dev.IpcGetOperation(w) != nil || w.seconds <= 0 {
		return nil
	}
	t := time.Unix(w.seconds, 0).UTC()
	return &t
}

// Consume and clear secret-bearing UAPI lines instead of constructing/retaining
// an entire dump just to obtain an allowlisted handshake timestamp.
type handshakeWriter struct {
	line    []byte
	seconds int64
}

func (w *handshakeWriter) Write(p []byte) (int, error) {
	for _, b := range p {
		if b == '\n' {
			prefix := []byte("last_handshake_time_sec=")
			if bytes.HasPrefix(w.line, prefix) {
				w.seconds, _ = strconv.ParseInt(string(w.line[len(prefix):]), 10, 64)
			}
			clear(w.line)
			w.line = w.line[:0]
		} else {
			if len(w.line) >= 8192 {
				return 0, errors.New("UAPI line exceeded safe limit")
			}
			w.line = append(w.line, b)
		}
	}
	return len(p), nil
}
func (s *Session) Status() Status { s.mu.Lock(); defer s.mu.Unlock(); return s.status }
func (s *Session) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errors.New("only tunneled TCP is supported")
	}
	select {
	case <-s.ctx.Done():
		return nil, errors.New("tunnel stopped")
	default:
	}
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return nil, errors.New("invalid destination")
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 {
		return nil, errors.New("invalid destination")
	}
	var ips []netip.Addr
	if ip, e := netip.ParseAddr(host); e == nil {
		ips = []netip.Addr{ip}
	} else {
		if len(s.config.DNS) == 0 {
			s.degraded()
			return nil, errors.New("numeric tunnel DNS is required for domains")
		}
		names, e := s.net.LookupContextHost(ctx, host)
		if e != nil {
			s.degraded()
			return nil, errors.New("tunnel DNS failed")
		}
		for _, name := range names {
			if ip, e := netip.ParseAddr(name); e == nil {
				ips = append(ips, ip)
			}
		}
	}
	for _, ip := range ips {
		if !s.config.Allows(ip) || network == "tcp4" && !ip.Is4() || network == "tcp6" && ip.Is4() {
			continue
		}
		c, e := s.net.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if e == nil {
			return c, nil
		}
	}
	s.degraded()
	return nil, errors.New("tunneled destination unreachable or disallowed")
}
func (s *Session) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.ctx.Done():
		c.Close()
		return false
	default:
		s.conns[c] = struct{}{}
		return true
	}
}
func (s *Session) untrack(c net.Conn) { s.mu.Lock(); delete(s.conns, c); s.mu.Unlock(); c.Close() }
func (s *Session) Close() {
	s.once.Do(func() {
		s.cancel()
		s.mu.Lock()
		for _, l := range s.listeners {
			l.Close()
		}
		for _, h := range s.servers {
			h.Close()
		}
		for c := range s.conns {
			c.Close()
		}
		s.status = Status{State: "Stopped", Message: "Stopped"}
		s.mu.Unlock()
		s.dev.Close()
		s.wg.Wait()
	})
}
