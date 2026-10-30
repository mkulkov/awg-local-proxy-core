package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"golang.org/x/net/dns/dnsmessage"
)

const awgLab = "jc=1\njmin=5\njmax=10\ns1=10\ns2=20\ns3=10\ns4=10\nh1=100001\nh2=100002\nh3=100003\nh4=100004\n"

type lab struct {
	config         string
	dev            *device.Device
	close          func()
	dnsQueries     atomic.Int32
	dnsResponses   atomic.Int32
	dnsParseErrors atomic.Int32
	dnsWriteErrors atomic.Int32
	rejectProbe    atomic.Bool
}

func port(t *testing.T, network string) int {
	t.Helper()
	if network == "udp" {
		c, e := net.ListenPacket("udp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr).Port
	}
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
func setupLab(t *testing.T) *lab {
	t.Helper()
	client, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	server, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	udp := port(t, "udp")
	tun, tn, e := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.201.0.1")}, nil, 1420)
	if e != nil {
		t.Fatal(e)
	}
	// Model an unmodified official Go peer deterministically: its first TUN
	// read has captured the default S4 before IpcSet. No server startup adapter
	// is applied, so the client must tolerate its first lost padded reply using
	// the pinned resolver's existing bounded, tunnel-only DNS retransmission.
	legacyTun := &firstReadSignalTun{Device: tun, started: make(chan int, 1)}
	d := device.NewDevice(legacyTun, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	select {
	case offset := <-legacyTun.started:
		if offset != device.MessageTransportHeaderSize {
			d.Close()
			t.Fatal("legacy peer did not capture the default offset")
		}
	case <-time.After(3 * time.Second):
		d.Close()
		t.Fatal("legacy peer reader did not start")
	}
	uapi := fmt.Sprintf("private_key=%s\nlisten_port=%d\n%sreplace_peers=true\npublic_key=%s\nallowed_ip=10.201.0.2/32\n", hex.EncodeToString(server.Bytes()), udp, awgLab, hex.EncodeToString(client.PublicKey().Bytes()))
	if e = d.IpcSet(uapi); e != nil {
		d.Close()
		t.Fatal("lab server configuration failed")
	}
	if e = d.Up(); e != nil {
		d.Close()
		t.Fatal(e)
	}
	lab := &lab{dev: d}
	listener, e := tn.ListenTCP(&net.TCPAddr{IP: net.ParseIP("10.201.0.1"), Port: 80})
	if e != nil {
		d.Close()
		t.Fatal(e)
	}
	hs := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if lab.rejectProbe.Load() {
			http.Error(w, "test probe rejected", 503)
			return
		}
		w.Header().Set("X-Lab", "userspace-awg")
		io.WriteString(w, "real encrypted userspace lab")
	})}
	go hs.Serve(listener)
	dns, e := tn.ListenUDP(&net.UDPAddr{IP: net.ParseIP("10.201.0.1"), Port: 53})
	if e != nil {
		d.Close()
		t.Fatal(e)
	}
	go func() {
		b := make([]byte, 1500)
		for {
			n, addr, e := dns.ReadFrom(b)
			if e != nil {
				return
			}
			lab.dnsQueries.Add(1)
			var msg dnsmessage.Message
			if msg.Unpack(b[:n]) != nil || len(msg.Questions) != 1 {
				lab.dnsParseErrors.Add(1)
				continue
			}
			q := msg.Questions[0]
			resp := dnsmessage.Message{Header: dnsmessage.Header{ID: msg.ID, Response: true, RecursionDesired: true, RecursionAvailable: true}, Questions: msg.Questions}
			if q.Name.String() == "lab.invalid." {
				if q.Type == dnsmessage.TypeA {
					resp.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: [4]byte{10, 201, 0, 1}}}}
				}
			} else {
				resp.Header.RCode = dnsmessage.RCodeNameError
			}
			out, e := resp.Pack()
			if e == nil {
				if _, e = dns.WriteTo(out, addr); e != nil {
					lab.dnsWriteErrors.Add(1)
				} else {
					lab.dnsResponses.Add(1)
				}
			} else {
				lab.dnsParseErrors.Add(1)
			}
		}
	}()
	lab.config = fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.201.0.2/32\nDNS = 10.201.0.1\nJc = 1\nJmin = 5\nJmax = 10\nS1 = 10\nS2 = 20\nS3 = 10\nS4 = 10\nH1 = 100001\nH2 = 100002\nH3 = 100003\nH4 = 100004\n[Peer]\nPublicKey = %s\nEndpoint = 127.0.0.1:%d\nAllowedIPs = 0.0.0.0/0\n", base64.StdEncoding.EncodeToString(client.Bytes()), base64.StdEncoding.EncodeToString(server.PublicKey().Bytes()), udp)
	lab.close = func() { dns.Close(); hs.Close(); d.Close() }
	t.Cleanup(lab.close)
	return lab
}
func TestRealAWGSOCKSHTTPAndFailClosed(t *testing.T) {
	lab := setupLab(t)
	socks := fmt.Sprintf("127.0.0.1:%d", port(t, "tcp"))
	httpAddr := fmt.Sprintf("127.0.0.1:%d", port(t, "tcp"))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s, e := Connect(ctx, ConnectOptions{Config: lab.config, SOCKSAddress: socks, HTTPAddress: httpAddr, ProbeURL: "http://lab.invalid/"})
	if e != nil {
		t.Fatalf("%v (synthetic DNS: queries=%d responses=%d parse_errors=%d write_errors=%d)", e, lab.dnsQueries.Load(), lab.dnsResponses.Load(), lab.dnsParseErrors.Load(), lab.dnsWriteErrors.Load())
	}
	defer s.Close()
	if st := s.Status(); st.State != "Connected" || !st.TunnelVerified || st.HandshakeAt == nil || !st.ListenerReady {
		t.Fatalf("unverified status %#v", st)
	}
	if lab.dnsQueries.Load() != 2 {
		t.Fatalf("legacy peer should require exactly the two existing tunneled DNS attempts, got %d", lab.dnsQueries.Load())
	}
	// HTTP forwarding and CONNECT both cross the actual encrypted AWG pair.
	proxyURL, _ := url.Parse("http://" + httpAddr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	resp, e := client.Get("http://lab.invalid/")
	if e != nil {
		t.Fatal(e)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "real encrypted userspace lab" || resp.Header.Get("X-Lab") != "userspace-awg" {
		t.Fatal("wrong forward response")
	}
	c, e := net.DialTimeout("tcp", httpAddr, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(c, "CONNECT lab.invalid:80 HTTP/1.1\r\nHost: lab.invalid:80\r\n\r\n")
	r := bufio.NewReader(c)
	line, _ := r.ReadString('\n')
	if !strings.Contains(line, "200") {
		t.Fatalf("CONNECT failed %q", line)
	}
	for {
		line, _ = r.ReadString('\n')
		if line == "\r\n" {
			break
		}
	}
	fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: lab.invalid\r\nConnection: close\r\n\r\n")
	response, e := http.ReadResponse(r, nil)
	if e != nil {
		t.Fatal(e)
	}
	body, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if string(body) != "real encrypted userspace lab" {
		t.Fatal("wrong CONNECT response")
	}
	sc := dialSOCKS(t, socks, "lab.invalid", 80)
	fmt.Fprint(sc, "GET / HTTP/1.1\r\nHost: lab.invalid\r\nConnection: close\r\n\r\n")
	sr, e := http.ReadResponse(bufio.NewReader(sc), nil)
	if e != nil {
		t.Fatal(e)
	}
	body, _ = io.ReadAll(sr.Body)
	sr.Body.Close()
	sc.Close()
	if string(body) != "real encrypted userspace lab" {
		t.Fatal("wrong SOCKS response")
	}
	// A host loopback listener is unreachable from the userspace route: no DIRECT.
	hostListener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer hostListener.Close()
	var accepted atomic.Bool
	go func() {
		c, e := hostListener.Accept()
		if e == nil {
			accepted.Store(true)
			c.Close()
		}
	}()
	failctx, fc := context.WithTimeout(context.Background(), time.Second)
	defer fc()
	if c, e := s.DialContext(failctx, "tcp", hostListener.Addr().String()); e == nil {
		c.Close()
		t.Fatal("host fallback")
	}
	if accepted.Load() {
		t.Fatal("host listener was reached")
	}
	// Peer loss must fail and never fall back; explicit verification closes session.
	lab.dev.Close()
	lost, lc := context.WithTimeout(context.Background(), time.Second)
	defer lc()
	if s.CheckTunnel(lost) == nil {
		t.Fatal("dead peer probe succeeded")
	}
	s.Close()
	if c, e := net.DialTimeout("tcp", socks, 100*time.Millisecond); e == nil {
		c.Close()
		t.Fatal("listener survived disconnect")
	}
}
func dialSOCKS(t *testing.T, address, host string, port uint16) net.Conn {
	t.Helper()
	c, e := net.DialTimeout("tcp", address, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte{5, 1, 0})
	var reply [2]byte
	if _, e = io.ReadFull(c, reply[:]); e != nil || reply != [2]byte{5, 0} {
		c.Close()
		t.Fatal("SOCKS negotiation failed")
	}
	request := append([]byte{5, 1, 0, 3, byte(len(host))}, []byte(host)...)
	request = append(request, byte(port>>8), byte(port))
	c.Write(request)
	var result [10]byte
	if _, e = io.ReadFull(c, result[:]); e != nil || result[1] != 0 {
		c.Close()
		t.Fatal("SOCKS connect failed")
	}
	return c
}
func TestParserAndControlBoundaries(t *testing.T) {
	lab := setupLab(t)
	if ValidateConfig(lab.config) != nil {
		t.Fatal("valid lab rejected")
	}
	for _, bad := range []string{lab.config + "[Peer]\n", strings.Replace(lab.config, "Jc = 1", "PostUp = arbitrary.exe", 1), strings.Replace(lab.config, "Jc = 1", "Jc = 1 # secret", 1), strings.Replace(lab.config, "Jc = 1", "Jc = 4294967295", 1), strings.Replace(lab.config, "Jc = 1", "Unknown = value", 1), strings.Repeat("x", MaxConfigBytes+1)} {
		if Parse, badErr := ParseConfig(bad); badErr == nil {
			_ = Parse
			t.Fatal("unsafe config accepted")
		}
	}
	for _, address := range []string{"0.0.0.0:1080", "[::]:1080", "localhost:1080", "127.0.0.1:0"} {
		if validateListen(address) == nil {
			t.Fatal("unsafe listener accepted")
		}
	}
	for _, raw := range []string{`{"protocol_version":1,"protocol_version":1,"type":"hello","id":"1","payload":{}}`, `{"protocol_version":2,"PROTOCOL_VERSION":1,"type":"hello","id":"1","payload":{}}`, strings.Repeat("x", MaxMessageBytes+1)} {
		if _, e := ReadMessage(bufio.NewReader(strings.NewReader(raw + "\n"))); e == nil {
			t.Fatal("bad envelope accepted")
		}
	}
	var opts ConnectOptions
	if strictJSON([]byte(`{"Config":"secret"}`), &opts) == nil {
		t.Fatal("case-aliased payload accepted")
	}
	var output bytes.Buffer
	if e := Serve(strings.NewReader(`{"protocol_version":1,"type":"hello","id":"1","payload":{}}`+"\n"), &output); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(output.String(), "private") || !strings.Contains(output.String(), "real_core") {
		t.Fatal("bad hello")
	}
}

func TestHundredRealConnectDisconnectCycles(t *testing.T) {
	lab := setupLab(t)
	address := fmt.Sprintf("127.0.0.1:%d", port(t, "tcp"))
	for i := 0; i < 100; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		s, e := Connect(ctx, ConnectOptions{Config: lab.config, SOCKSAddress: address, ProbeURL: "http://10.201.0.1/"})
		cancel()
		if e != nil {
			t.Fatalf("cycle %d: %v", i, e)
		}
		s.Close()
		if c, e := net.DialTimeout("tcp", address, 50*time.Millisecond); e == nil {
			c.Close()
			t.Fatalf("cycle %d listener retained", i)
		}
	}
}

func TestIPacketSafetyGuard(t *testing.T) {
	for _, v := range []string{"SSH_PASSWORD", "<r -1>", "<dz -1>", "<r 2147483647>", "<dz 0>", "<dz 9>", "<r 4096><r 1>", "<b 0xzz>", "<t ignored>", "<r 1 extra>", "junk<b 0x00>", strings.Repeat("<r 1>", 33)} {
		if validateIPacket(v) {
			t.Fatalf("unsafe I packet accepted %q", v)
		}
	}
	for _, v := range []string{"<b 0x0102><t><r 16><rc 8><rd 4><dz 2><d><ds>", "<r 0>", "<b aabb> <t>"} {
		if !validateIPacket(v) {
			t.Fatalf("valid I packet rejected %q", v)
		}
	}
	lab := setupLab(t)
	cfg := strings.Replace(lab.config, "Jc = 1", "I1 = <b 0x010203><r 8><t>\nJc = 1", 1)
	if ValidateConfig(cfg) != nil {
		t.Fatal("bounded I packet rejected by engine")
	}
	for _, bad := range []string{strings.Replace(lab.config, "S4 = 10", "S4 = 3000", 1), strings.Replace(lab.config, "S4 = 10", "MTU = 1984\nS4 = 1", 1), strings.Replace(lab.config, "S1 = 10", "S1 = 1900", 1), strings.Replace(lab.config, "S2 = 20", "S2 = 1930", 1), strings.Replace(lab.config, "S3 = 10", "S3 = 2000", 1), strings.Replace(lab.config, "Jmax = 10\n", "", 1), strings.Replace(lab.config, "Jmax = 10", "Jmax = 5", 1), strings.Replace(lab.config, "H1 = 100001", "H1 = 0-4294967295", 1)} {
		if _, e := ParseConfig(bad); e == nil {
			t.Fatal("unsafe Windows packet bounds accepted")
		}
	}
	if lab.dev.IpcSet("h1=200001-200010\nh2=200020-200030\n") != nil {
		t.Fatal("lab range setup")
	}
	cfg = strings.Replace(cfg, "H1 = 100001", "H1 = 200001-200010", 1)
	cfg = strings.Replace(cfg, "H2 = 100002", "H2 = 200020-200030", 1)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s, e := Connect(ctx, ConnectOptions{Config: cfg, SOCKSAddress: fmt.Sprintf("127.0.0.1:%d", port(t, "tcp")), ProbeURL: "http://10.201.0.1/"})
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
}

func TestHTTPAcceptedConnectionCap(t *testing.T) {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	limit := make(chan struct{}, 1)
	limited := &limitedListener{Listener: l, limit: limit}
	accepted := make(chan net.Conn, 2)
	go func() {
		for {
			c, e := limited.Accept()
			if e != nil {
				return
			}
			accepted <- c
		}
	}()
	first, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer first.Close()
	server := <-accepted
	second, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer second.Close()
	second.SetReadDeadline(time.Now().Add(time.Second))
	if _, e = second.Read(make([]byte, 1)); e == nil {
		t.Fatal("excess socket not refused")
	} else if ne, ok := e.(net.Error); ok && ne.Timeout() {
		t.Fatal("excess socket remained open")
	}
	if len(limit) != 1 {
		t.Fatal("wrong capacity accounting")
	}
	server.Close()
	server.Close()
	if len(limit) != 0 {
		t.Fatal("capacity not released exactly once")
	}
}

func TestManagedChildEOFClosesRealListeners(t *testing.T) {
	lab := setupLab(t)
	exe := filepath.Join(t.TempDir(), "awg-proxy-core.exe")
	goName := "go"
	if runtime.GOOS == "windows" {
		goName += ".exe"
	}
	build := exec.Command(filepath.Join(runtime.GOROOT(), "bin", goName), "build", "-o", exe, "../cmd/awg-proxy-core")
	if output, e := build.CombinedOutput(); e != nil {
		t.Fatalf("build core: %v %s", e, output)
	}
	cmd := exec.Command(exe, "--control-stdio")
	in, e := cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	out, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		in.Close()
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
		}
	})
	address := fmt.Sprintf("127.0.0.1:%d", port(t, "tcp"))
	httpAddress := fmt.Sprintf("127.0.0.1:%d", port(t, "tcp"))
	if e = writeMessage(in, "connect", "1", ConnectOptions{Config: lab.config, SOCKSAddress: address, HTTPAddress: httpAddress, ProbeURL: "http://10.201.0.1/", TimeoutSeconds: 15}); e != nil {
		t.Fatal(e)
	}
	result := make(chan error, 1)
	reader := bufio.NewReader(out)
	go func() {
		m, e := ReadMessage(reader)
		if e == nil && m.Type != "status" {
			e = fmt.Errorf("unexpected %s: %s", m.Type, string(m.Payload))
		}
		if e == nil {
			var st Status
			if json.Unmarshal(m.Payload, &st) != nil || st.State != "Connected" || st.HandshakeAt == nil || !st.ListenerReady || !st.TunnelVerified || st.Demo {
				e = fmt.Errorf("unverified child status")
			}
		}
		result <- e
	}()
	select {
	case e := <-result:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("child connect hung")
	}
	sc := dialSOCKS(t, address, "lab.invalid", 80)
	fmt.Fprint(sc, "GET / HTTP/1.1\r\nHost: lab.invalid\r\nConnection: close\r\n\r\n")
	response, e := http.ReadResponse(bufio.NewReader(sc), nil)
	if e != nil {
		sc.Close()
		t.Fatal(e)
	}
	b, _ := io.ReadAll(response.Body)
	response.Body.Close()
	sc.Close()
	if string(b) != "real encrypted userspace lab" {
		t.Fatal("child SOCKS did not traverse AWG")
	}
	proxyURL, _ := url.Parse("http://" + httpAddress)
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	hr, e := client.Get("http://lab.invalid/")
	if e != nil {
		t.Fatal(e)
	}
	b, _ = io.ReadAll(hr.Body)
	hr.Body.Close()
	tr.CloseIdleConnections()
	if string(b) != "real encrypted userspace lab" {
		t.Fatal("child HTTP did not traverse AWG")
	}
	if e = writeMessage(in, "check_tunnel", "2", struct{}{}); e != nil {
		t.Fatal(e)
	}
	checked, e := ReadMessage(reader)
	if e != nil || checked.Type != "status" {
		t.Fatal("child explicit check failed")
	}
	lab.rejectProbe.Store(true)
	if e = writeMessage(in, "check_tunnel", "3", struct{}{}); e != nil {
		t.Fatal(e)
	}
	failed, e := ReadMessage(reader)
	var failedStatus Status
	if e != nil || failed.Type != "status" || json.Unmarshal(failed.Payload, &failedStatus) != nil || failedStatus.State != "Error" || failedStatus.ListenerReady || failedStatus.TunnelVerified {
		t.Fatal("failed child probe not fail-closed")
	}
	if c, e := net.DialTimeout("tcp", address, 100*time.Millisecond); e == nil {
		c.Close()
		t.Fatal("child retained listener after failed check")
	}
	lab.rejectProbe.Store(false)
	if e = writeMessage(in, "connect", "4", ConnectOptions{Config: lab.config, SOCKSAddress: address, HTTPAddress: httpAddress, ProbeURL: "http://10.201.0.1/", TimeoutSeconds: 15}); e != nil {
		t.Fatal(e)
	}
	again, e := ReadMessage(reader)
	if e != nil || again.Type != "status" {
		t.Fatal("child could not reconnect after failed check")
	}
	in.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("child did not exit on EOF")
	}
	if c, e := net.DialTimeout("tcp", address, 100*time.Millisecond); e == nil {
		c.Close()
		t.Fatal("listener survived child EOF")
	}
}

func TestConnectFailuresLeavePortsAndOtherProcessesAlone(t *testing.T) {
	lab := setupLab(t)
	address := fmt.Sprintf("127.0.0.1:%d", port(t, "tcp"))
	cfg, e := ParseConfig(lab.config)
	if e != nil {
		t.Fatal(e)
	}
	old := cfg.fields["peer.endpoint"]
	bad := strings.Replace(lab.config, old, fmt.Sprintf("127.0.0.1:%d", port(t, "udp")), 1)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	s, e := Connect(ctx, ConnectOptions{Config: bad, SOCKSAddress: address, ProbeURL: "http://10.201.0.1/"})
	cancel()
	if e == nil || s != nil {
		if s != nil {
			s.Close()
		}
		t.Fatal("unreachable peer reported success")
	}
	free, e := net.Listen("tcp4", address)
	if e != nil {
		t.Fatal("failed connect retained port")
	}
	defer free.Close()
	ctx, cancel = context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s, e = Connect(ctx, ConnectOptions{Config: lab.config, SOCKSAddress: address, ProbeURL: "http://10.201.0.1/"})
	if e == nil || s != nil {
		if s != nil {
			s.Close()
		}
		t.Fatal("occupied port accepted")
	}
	if c, e := net.DialTimeout("tcp", address, time.Second); e != nil {
		t.Fatal("other listener was terminated")
	} else {
		c.Close()
	}
}

func TestSOCKSUnsupportedCommandsFailExplicitly(t *testing.T) {
	lab := setupLab(t)
	address := fmt.Sprintf("127.0.0.1:%d", port(t, "tcp"))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s, e := Connect(ctx, ConnectOptions{Config: lab.config, SOCKSAddress: address, ProbeURL: "http://10.201.0.1/"})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	for _, command := range []byte{2, 3} {
		c, e := net.DialTimeout("tcp", address, time.Second)
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(time.Second))
		c.Write([]byte{5, 1, 0})
		var negotiation [2]byte
		io.ReadFull(c, negotiation[:])
		c.Write([]byte{5, command, 0, 1, 10, 201, 0, 1, 0, 80})
		var response [10]byte
		_, e = io.ReadFull(c, response[:])
		c.Close()
		if e != nil || response[1] != 7 {
			t.Fatal("unsupported SOCKS command not refused")
		}
	}
	c, e := net.DialTimeout("tcp", address, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	c.Write([]byte{5, 1, 2})
	var response [2]byte
	if _, e = io.ReadFull(c, response[:]); e != nil || response != [2]byte{5, 255} {
		t.Fatal("unsupported authentication not refused")
	}
}

func FuzzParseConfig(f *testing.F) {
	a, b := make([]byte, 32), make([]byte, 32)
	for i := range a {
		a[i] = 1
		b[i] = 2
	}
	f.Add(fmt.Sprintf("[Interface]\nPrivateKey=%s\nAddress=10.0.0.2/32\n[Peer]\nPublicKey=%s\nEndpoint=192.0.2.1:51820\nAllowedIPs=0.0.0.0/0\n", base64.StdEncoding.EncodeToString(a), base64.StdEncoding.EncodeToString(b)))
	f.Add("vpn://invalid")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > MaxConfigBytes+1 {
			t.Skip()
		}
		_, _ = ParseConfig(s)
	})
}
func FuzzControlEnvelope(f *testing.F) {
	f.Add(`{"protocol_version":1,"type":"hello","id":"1","payload":{}}`)
	f.Add(`{"protocol_version":1,"type":"hello","id":"1","payload":null}`)
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > MaxMessageBytes+1 {
			t.Skip()
		}
		_, _ = ReadMessage(bufio.NewReader(strings.NewReader(s + "\n")))
	})
}

func TestRelayRefreshesIdleDuringOneWayTraffic(t *testing.T) {
	client, left := net.Pipe()
	right, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	defer left.Close()
	defer right.Close()
	idle := 150 * time.Millisecond
	done := make(chan struct{})
	go func() { relayWithIdle(left, right, left, idle); close(done) }()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	server.SetDeadline(time.Now().Add(3 * time.Second))
	for i := 0; i < 20; i++ {
		if _, e := server.Write([]byte{byte(i)}); e != nil {
			t.Fatalf("active transfer stopped at %d: %v", i, e)
		}
		var b [1]byte
		if _, e := io.ReadFull(client, b[:]); e != nil || b[0] != byte(i) {
			t.Fatalf("active transfer corrupted at %d: %v", i, e)
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case <-done:
		t.Fatal("active relay ended at absolute timeout")
	default:
	}
	select {
	case <-done:
	case <-time.After(4*idle + 100*time.Millisecond):
		t.Fatal("truly idle relay did not terminate")
	}
}

func TestProductRealSupervisorUserspaceLab(t *testing.T) {
	helper := os.Getenv("AWG_PRODUCT_LAB_HELPER")
	if helper == "" {
		t.Skip("product test helper not supplied")
	}
	if !filepath.IsAbs(helper) {
		t.Fatal("helper must have absolute path")
	}
	lab := setupLab(t)
	exe := filepath.Join(t.TempDir(), "awg-proxy-core.exe")
	goName := "go"
	if runtime.GOOS == "windows" {
		goName += ".exe"
	}
	build := exec.Command(filepath.Join(runtime.GOROOT(), "bin", goName), "build", "-o", exe, "../cmd/awg-proxy-core")
	if b, e := build.CombinedOutput(); e != nil {
		t.Fatalf("core build: %v %s", e, b)
	}
	binary, e := os.ReadFile(exe)
	if e != nil {
		t.Fatal(e)
	}
	hash := sha256.Sum256(binary)
	clear(binary)
	cmd := exec.Command(helper, "-test.run=^TestRealSupervisorLabHelper$")
	in, e := cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	out, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		in.Close()
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
		}
	})
	socks := fmt.Sprintf("127.0.0.1:%d", port(t, "tcp"))
	httpAddress := fmt.Sprintf("127.0.0.1:%d", port(t, "tcp"))
	request := struct {
		CoreExecutable string         `json:"core_executable"`
		CoreSHA256     string         `json:"core_sha256"`
		Connect        ConnectOptions `json:"connect"`
	}{exe, hex.EncodeToString(hash[:]), ConnectOptions{Config: lab.config, SOCKSAddress: socks, HTTPAddress: httpAddress, ProbeURL: "http://10.201.0.1/", TimeoutSeconds: 15}}
	if e = json.NewEncoder(in).Encode(request); e != nil {
		t.Fatal(e)
	}
	request.Connect.Config = ""
	ready := make(chan error, 1)
	go func() {
		var response struct {
			Ready bool `json:"ready"`
		}
		e := json.NewDecoder(out).Decode(&response)
		if e == nil && !response.Ready {
			e = fmt.Errorf("helper not ready")
		}
		ready <- e
	}()
	select {
	case e := <-ready:
		if e != nil {
			t.Fatalf("product helper: %v", e)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("product supervisor connect timed out")
	}
	sc := dialSOCKS(t, socks, "lab.invalid", 80)
	fmt.Fprint(sc, "GET / HTTP/1.1\r\nHost: lab.invalid\r\nConnection: close\r\n\r\n")
	resp, e := http.ReadResponse(bufio.NewReader(sc), nil)
	if e != nil {
		sc.Close()
		t.Fatal(e)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	sc.Close()
	if string(body) != "real encrypted userspace lab" {
		t.Fatal("product SOCKS path was not AWG lab")
	}
	proxyURL, _ := url.Parse("http://" + httpAddress)
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, e = client.Get("http://lab.invalid/")
	if e != nil {
		t.Fatal(e)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	tr.CloseIdleConnections()
	if string(body) != "real encrypted userspace lab" {
		t.Fatal("product HTTP path was not AWG lab")
	}
	in.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case e := <-done:
		if e != nil {
			t.Fatalf("product helper exit: %v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("product helper did not close owned core")
	}
	if c, e := net.DialTimeout("tcp", socks, 100*time.Millisecond); e == nil {
		c.Close()
		t.Fatal("product supervisor retained core listener")
	}
}
