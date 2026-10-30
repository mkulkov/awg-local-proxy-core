package core

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Synthetic values only; these are not a user's server or profile.
func awg3Fields() (string, string) {
	key := bytes.Repeat([]byte{0x35}, 32)
	ini := "S1=12\nS2=16\nS3=20\nS4=24\nH1=100001-100011\nH2=100021-100031\nH3=100041-100051\nH4=100061-100071\n" +
		"HeaderProtectionKey=" + base64.StdEncoding.EncodeToString(key) + "\nContentPaddingAddition=8-16\nRekeyAfterTime=120-121\nRekeyTimeout=5-6\nRejectAfterTime=180-181\nKeepaliveTimeout=10-11\nMaxHandshakeAttempts=4-5\nRandomTrailers=true\nDisableCookies=true\n"
	uapi := "s1=12\ns2=16\ns3=20\ns4=24\nh1=100001-100011\nh2=100021-100031\nh3=100041-100051\nh4=100061-100071\n" +
		"header_protection_key=" + hex.EncodeToString(key) + "\ncontent_padding_addition=8-16\nrekey_after_time=120-121\nrekey_timeout=5-6\nreject_after_time=180-181\nkeepalive_timeout=10-11\nmax_handshake_attempts=4-5\nrandom_trailers=true\ndisable_cookies=true\n"
	return uapi, ini
}

func syntheticAWG3Config() string {
	_, ini := awg3Fields()
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	return "[Interface]\nPrivateKey=" + key + "\nAddress=10.201.0.2/32\n" + ini + "[Peer]\nPublicKey=" + key + "\nEndpoint=127.0.0.1:12345\nAllowedIPs=0.0.0.0/0\nPersistentKeepalive=20-21\n"
}

func TestAWG3ConfigPreservesOfficialFields(t *testing.T) {
	c, err := ParseConfig(syntheticAWG3Config())
	if err != nil {
		t.Fatal("official AWG3 fields rejected:", err)
	}
	want, _ := awg3Fields()
	uapi := c.UAPI("127.0.0.1:12345")
	for _, line := range strings.Split(strings.TrimSpace(want), "\n") {
		if !strings.Contains(uapi, line+"\n") {
			t.Fatal("official AWG3 field was not preserved:", strings.SplitN(line, "=", 2)[0])
		}
	}
	if !strings.Contains(uapi, "persistent_keepalive_interval"+"=20-21\n") {
		t.Fatal("keepalive range was not preserved")
	}
	if err = ValidateConfig(syntheticAWG3Config()); err != nil {
		t.Fatal("pinned engine rejected validated AWG3 fields:", err)
	}
}

func TestAWG3RejectsUnsafeParameters(t *testing.T) {
	base := syntheticAWG3Config()
	zeroKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	_, fields := awg3Fields()
	var protectionLine string
	for _, line := range strings.Split(fields, "\n") {
		if strings.HasPrefix(line, "HeaderProtectionKey=") {
			protectionLine = line
		}
	}
	tests := []struct{ old, replacement string }{
		{"HeaderProtectionKey=", "HeaderProtectionKey=invalid"},
		{protectionLine, "HeaderProtectionKey=" + zeroKey},
		{"S1=12\n", ""},
		{"S1=12", "S1=11"}, {"S2=16", "S2=11"}, {"S3=20", "S3=11"}, {"S4=24", "S4=11"},
		{"ContentPaddingAddition=8-16", "ContentPaddingAddition=0-4294967295"},
		{"ContentPaddingAddition=8-16", "ContentPaddingAddition=2017"},
		{"ContentPaddingAddition=8-16", "ContentPaddingAddition=541"}, // 1420+24+32+541 > 2016
		{"ContentPaddingAddition=8-16", "ContentPaddingAddition=16-8"},
		{"RekeyAfterTime=120-121", "RekeyAfterTime=0-120"},
		{"RekeyTimeout=5-6", "RekeyTimeout=4294967296"},
		{"RejectAfterTime=180-181", "RejectAfterTime=0-4294967295"},
		{"RejectAfterTime=180-181", "RejectAfterTime=3074457346"},
		{"KeepaliveTimeout=10-11", "KeepaliveTimeout=-1"},
		{"MaxHandshakeAttempts=4-5", "MaxHandshakeAttempts=0-5"},
		{"MaxHandshakeAttempts=4-5", "MaxHandshakeAttempts=4294967294"},
		{"PersistentKeepalive=20-21", "PersistentKeepalive=0-21"},
		{"RandomTrailers=true", "RandomTrailers=yes"},
		{"DisableCookies=true", "DisableCookies=maybe"},
		{"RandomTrailers=true", "UnknownFutureField=true"},
		{"RandomTrailers=true", "random_trailers=true"},
	}
	for _, addition := range []string{"0", "0-16", "540"} {
		if _, err := ParseConfig(strings.Replace(base, "ContentPaddingAddition=8-16", "ContentPaddingAddition="+addition, 1)); err != nil {
			t.Fatal("safe padding boundary rejected:", addition)
		}
	}
	for i, tt := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if _, err := ParseConfig(strings.Replace(base, tt.old, tt.replacement, 1)); err == nil {
				t.Fatal("unsafe or unsupported parameter accepted:", strings.SplitN(tt.replacement, "=", 2)[0])
			}
		})
	}
	for _, field := range []string{"RekeyAfterTime=120-121", "RekeyTimeout=5-6", "RejectAfterTime=180-181", "KeepaliveTimeout=10-11", "MaxHandshakeAttempts=4-5", "PersistentKeepalive=20-21"} {
		upper := "4294967295"
		if strings.HasPrefix(field, "RejectAfterTime=") {
			upper = "3074457345"
		} else if strings.HasPrefix(field, "MaxHandshakeAttempts=") {
			upper = "4294967293"
		}
		for _, accepted := range []string{"0", "0-0", "1", upper, "1-" + upper} {
			key := strings.SplitN(field, "=", 2)[0]
			if _, err := ParseConfig(strings.Replace(base, field, key+"="+accepted, 1)); err != nil {
				t.Fatal("safe pinned uint32 range rejected:", key, accepted)
			}
		}
	}
}

func TestAWG3EncryptedUserspaceAndFailClosed(t *testing.T) {
	uapi, ini := awg3Fields()
	lab := setupLabWithFields(t, uapi, ini)
	lab.config += "PersistentKeepalive=20-21\n"
	socks := fmt.Sprintf("127.0.0.1:%d", port(t, "tcp"))
	httpAddr := fmt.Sprintf("127.0.0.1:%d", port(t, "tcp"))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s, err := Connect(ctx, ConnectOptions{Config: lab.config, SOCKSAddress: socks, HTTPAddress: httpAddr, ProbeURL: "http://lab.invalid/"})
	if err != nil {
		t.Fatal("AWG3 encrypted handshake/probe:", err)
	}
	defer s.Close()
	if status := s.Status(); !status.TunnelVerified || !status.ListenerReady || status.HandshakeAt == nil {
		t.Fatal("AWG3 connection was not verified")
	}
	proxyURL, _ := url.Parse("http://" + httpAddr)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	// The long request crosses multiple full-sized netstack TCP segments,
	// exercising protected transport headers and padding beyond tiny probes.
	resp, err := client.Get("http://lab.invalid/" + strings.Repeat("p", 6000))
	if err != nil {
		t.Fatal("AWG3 HTTP forwarding:", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "real encrypted userspace lab" {
		t.Fatal("AWG3 HTTP payload mismatch")
	}
	c := dialSOCKS(t, socks, "lab.invalid", 80)
	fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: lab.invalid\r\nConnection: close\r\n\r\n")
	resp, err = http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		c.Close()
		t.Fatal("AWG3 SOCKS forwarding:", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	c.Close()
	if string(body) != "real encrypted userspace lab" {
		t.Fatal("AWG3 SOCKS payload mismatch")
	}
	s.Close()
	// A mismatched protection key cannot establish a tunnel, and cannot expose
	// listeners or a direct proxy while the encrypted handshake is unavailable.
	wrong := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x36}, 32))
	correct := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x35}, 32))
	bad := strings.Replace(lab.config, correct, wrong, 1)
	failed, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if session, err := Connect(failed, ConnectOptions{Config: bad, SOCKSAddress: socks, HTTPAddress: httpAddr, ProbeURL: "http://lab.invalid/"}); err == nil {
		session.Close()
		t.Fatal("wrong header protection key established a tunnel")
	}
	for _, address := range []string{socks, httpAddr} {
		if c, err := net.DialTimeout("tcp", address, 100*time.Millisecond); err == nil {
			c.Close()
			t.Fatal("failed AWG3 handshake left proxy listener open")
		}
	}
}
