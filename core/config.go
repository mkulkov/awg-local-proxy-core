// Package core contains the original managed proxy around the official AWG engine.
package core

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
)

const MaxConfigBytes = 48 * 1024

// The pinned Windows engine uses a 2016-byte message buffer. Keep this target
// invariant on every build platform so imported profiles behave consistently.
const maxDatagramBytes = 2016

var ErrConfig = errors.New("unsupported or invalid client configuration")

// Official AWG3 INI names (case-insensitive) and the pinned engine's UAPI names.
// Keep aliases explicit: accepting arbitrary future fields would silently alter
// the meaning of an imported configuration.
var awg3FieldNames = map[string]string{
	"contentpaddingaddition": "content_padding_addition",
	"rekeyaftertime":         "rekey_after_time",
	"rekeytimeout":           "rekey_timeout",
	"rejectaftertime":        "reject_after_time",
	"keepalivetimeout":       "keepalive_timeout",
	"maxhandshakeattempts":   "max_handshake_attempts",
	"randomtrailers":         "random_trailers",
	"disablecookies":         "disable_cookies",
}

type Config struct {
	Addresses, DNS []netip.Addr
	Allowed        []netip.Prefix
	MTU            int
	fields         map[string]string
	peerKey        device.NoisePublicKey
}

func ParseConfig(input string) (*Config, error) {
	if len(input) == 0 || len(input) > MaxConfigBytes || !utf8.ValidString(input) {
		return nil, ErrConfig
	}
	c := &Config{MTU: 1420, fields: map[string]string{}}
	section := ""
	sections := map[string]bool{}
	iface := map[string]bool{"privatekey": true, "address": true, "dns": true, "mtu": true, "jc": true, "jmin": true, "jmax": true, "s1": true, "s2": true, "s3": true, "s4": true, "h1": true, "h2": true, "h3": true, "h4": true, "i1": true, "i2": true, "i3": true, "i4": true, "i5": true}
	iface["headerprotectionkey"] = true
	for key := range awg3FieldNames {
		iface[key] = true
	}
	peer := map[string]bool{"publickey": true, "presharedkey": true, "endpoint": true, "allowedips": true, "persistentkeepalive": true}
	for _, line := range strings.Split(strings.TrimPrefix(input, "\ufeff"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if len(line) > 4096 || strings.ContainsAny(line, "\x00\r\t#;") {
			return nil, ErrConfig
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return nil, ErrConfig
			}
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if (section != "interface" && section != "peer") || sections[section] {
				return nil, ErrConfig
			}
			sections[section] = true
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if !ok || v == "" || (section == "interface" && !iface[k]) || (section == "peer" && !peer[k]) || section == "" {
			return nil, ErrConfig
		}
		key := section + "." + k
		if _, ok := c.fields[key]; ok {
			return nil, ErrConfig
		}
		c.fields[key] = v
	}
	for _, k := range []string{"interface.privatekey", "interface.address", "peer.publickey", "peer.endpoint", "peer.allowedips"} {
		if c.fields[k] == "" {
			return nil, ErrConfig
		}
	}
	for _, k := range []string{"interface.privatekey", "peer.publickey", "peer.presharedkey", "interface.headerprotectionkey"} {
		if v := c.fields[k]; v != "" {
			b, e := base64.StdEncoding.Strict().DecodeString(v)
			if e != nil || len(b) != 32 {
				return nil, ErrConfig
			}
			var z byte
			for _, x := range b {
				z |= x
			}
			clear(b)
			if z == 0 {
				return nil, ErrConfig
			}
		}
	}
	public, _ := base64.StdEncoding.Strict().DecodeString(c.fields["peer.publickey"])
	copy(c.peerKey[:], public)
	clear(public)
	for _, v := range strings.Split(c.fields["interface.address"], ",") {
		p, e := netip.ParsePrefix(strings.TrimSpace(v))
		if e != nil || p.Addr().IsUnspecified() || p.Addr().IsMulticast() {
			return nil, ErrConfig
		}
		c.Addresses = append(c.Addresses, p.Addr())
	}
	for _, v := range strings.Split(c.fields["peer.allowedips"], ",") {
		p, e := netip.ParsePrefix(strings.TrimSpace(v))
		if e != nil {
			return nil, ErrConfig
		}
		c.Allowed = append(c.Allowed, p.Masked())
	}
	if v := c.fields["interface.dns"]; v != "" {
		for _, s := range strings.Split(v, ",") {
			ip, e := netip.ParseAddr(strings.TrimSpace(s))
			if e != nil || ip.IsUnspecified() || ip.IsMulticast() || !c.Allows(ip) {
				return nil, ErrConfig
			}
			c.DNS = append(c.DNS, ip)
		}
	}
	if v := c.fields["interface.mtu"]; v != "" {
		n, e := strconv.Atoi(v)
		if e != nil || n < 576 || n > maxDatagramBytes-device.MessageTransportSize {
			return nil, ErrConfig
		}
		c.MTU = n
	}
	host, port, e := net.SplitHostPort(c.fields["peer.endpoint"])
	if e != nil || host == "" || len(host) > 253 {
		return nil, ErrConfig
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 {
		return nil, ErrConfig
	}
	// Endpoint hostnames are the sole documented host-resolver exception; reject
	// ambiguous/non-DNS syntax before bootstrap resolution.
	if _, e := netip.ParseAddr(host); e != nil {
		for _, r := range host {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
				return nil, ErrConfig
			}
		}
	}
	for _, k := range []string{"peer.persistentkeepalive", "interface.rekeyaftertime", "interface.rekeytimeout", "interface.rejectaftertime", "interface.keepalivetimeout", "interface.maxhandshakeattempts"} {
		if v := c.fields[k]; v != "" {
			var r device.UintRange
			// A single zero selects the engine default/off value. A mixed zero
			// range can select immediate timers and create a busy retry loop.
			if r.FromString(v) != nil || r.Lo() == 0 && r.Hi() != 0 {
				return nil, ErrConfig
			}
			// The pinned timer code multiplies RejectAfterTime by three and
			// increments/logs MaxHandshakeAttempts by up to two.
			if k == "interface.rejectaftertime" && r.Hi() > 3074457345 || k == "interface.maxhandshakeattempts" && r.Hi() > ^uint32(0)-2 {
				return nil, ErrConfig
			}
		}
	}
	for _, k := range []string{"randomtrailers", "disablecookies"} {
		if v := c.fields["interface."+k]; v != "" {
			if _, e := strconv.ParseBool(v); e != nil {
				return nil, ErrConfig
			}
		}
	}
	var addition device.UintRange
	if v := c.fields["interface.contentpaddingaddition"]; v != "" {
		if addition.FromString(v) != nil || addition.Hi() > maxDatagramBytes {
			return nil, ErrConfig
		}
	}
	for _, k := range []string{"jc", "jmin", "jmax", "s1", "s2", "s3", "s4"} {
		if v := c.fields["interface."+k]; v != "" {
			bits := 16
			if strings.HasPrefix(k, "j") {
				bits = 32
			}
			n, e := strconv.ParseUint(v, 10, bits)
			if e != nil {
				return nil, ErrConfig
			}
			if k == "jc" && n > 128 || k != "jc" && n > maxDatagramBytes {
				return nil, ErrConfig
			}
		}
	}
	value := func(key string) uint64 { v, _ := strconv.ParseUint(c.fields["interface."+key], 10, 32); return v }
	if value("jmin") > value("jmax") {
		return nil, ErrConfig
	}
	if value("jc") > 0 && (c.fields["interface.jmin"] == "" || c.fields["interface.jmax"] == "" || value("jmin") >= value("jmax")) {
		return nil, ErrConfig
	}
	if value("s1")+device.MessageInitiationSize > maxDatagramBytes || value("s2")+device.MessageResponseSize > maxDatagramBytes || value("s3")+device.MessageCookieReplySize > maxDatagramBytes || uint64(c.MTU)+value("s4")+device.MessageTransportSize+uint64(addition.Hi()) > maxDatagramBytes {
		return nil, ErrConfig
	}
	if c.fields["interface.headerprotectionkey"] != "" {
		for _, k := range []string{"s1", "s2", "s3", "s4"} {
			if value(k) < device.HeaderCipherNonceSize {
				return nil, ErrConfig
			}
		}
	}
	for _, k := range []string{"h1", "h2", "h3", "h4"} {
		if v := c.fields["interface."+k]; v != "" {
			var r device.UintRange
			if r.FromString(v) != nil || r.Lo() == 0 && r.Hi() == ^uint32(0) {
				return nil, ErrConfig
			}
		}
	}
	for _, k := range []string{"i1", "i2", "i3", "i4", "i5"} {
		if v := c.fields["interface."+k]; v != "" && !validateIPacket(v) {
			return nil, ErrConfig
		}
	}
	// The bounded I packet grammar is then checked by the pinned engine via IpcSet.
	return c, nil
}
func (c *Config) Allows(ip netip.Addr) bool {
	for _, p := range c.Allowed {
		if p.Contains(ip.Unmap()) {
			return true
		}
	}
	return false
}
func (c *Config) UAPI(endpoint string) string {
	var b strings.Builder
	key := func(dst, src string) {
		if v := c.fields[src]; v != "" {
			d, _ := base64.StdEncoding.Strict().DecodeString(v)
			b.WriteString(dst + "=" + hex.EncodeToString(d) + "\n")
			clear(d)
		}
	}
	key("private_key", "interface.privatekey")
	key("header_protection_key", "interface.headerprotectionkey")
	for src, dst := range awg3FieldNames {
		if v := c.fields["interface."+src]; v != "" {
			b.WriteString(dst + "=" + v + "\n")
		}
	}
	for _, k := range []string{"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5"} {
		if v := c.fields["interface."+k]; v != "" {
			b.WriteString(k + "=" + v + "\n")
		}
	}
	b.WriteString("replace_peers=true\n")
	key("public_key", "peer.publickey")
	key("preshared_key", "peer.presharedkey")
	b.WriteString("endpoint=" + endpoint + "\nreplace_allowed_ips=true\n")
	for _, p := range c.Allowed {
		b.WriteString("allowed_ip=" + p.String() + "\n")
	}
	if v := c.fields["peer.persistentkeepalive"]; v != "" {
		b.WriteString("persistent_keepalive_interval=" + v + "\n")
	}
	return b.String()
}
