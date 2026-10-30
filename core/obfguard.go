package core

import (
	"encoding/hex"
	"strconv"
	"strings"
)

// validateIPacket bounds the pinned engine's otherwise permissive I-packet
// builders. It is an input safety guard, not a cryptographic implementation.
func validateIPacket(spec string) bool {
	if len(spec) == 0 || len(spec) > 4096 {
		return false
	}
	remaining := strings.TrimSpace(spec)
	tags, budget := 0, 0
	for remaining != "" {
		if !strings.HasPrefix(remaining, "<") {
			return false
		}
		end := strings.IndexByte(remaining, '>')
		if end < 0 {
			return false
		}
		parts := strings.Fields(remaining[1:end])
		if len(parts) == 0 || len(parts) > 2 {
			return false
		}
		tags++
		if tags > 32 {
			return false
		}
		switch parts[0] {
		case "t", "d", "ds":
			if len(parts) != 1 {
				return false
			}
			if parts[0] == "t" {
				budget += 4
			}
		case "b":
			if len(parts) != 2 {
				return false
			}
			v := strings.TrimPrefix(parts[1], "0x")
			if len(v) == 0 || len(v)%2 != 0 {
				return false
			}
			b, e := hex.DecodeString(v)
			if e != nil {
				return false
			}
			budget += len(b)
		case "r", "rc", "rd", "dz":
			if len(parts) != 2 {
				return false
			}
			for _, r := range parts[1] {
				if r < '0' || r > '9' {
					return false
				}
			}
			n, e := strconv.Atoi(parts[1])
			if e != nil || n > 4096 {
				return false
			}
			if parts[0] == "dz" && (n < 1 || n > 8) {
				return false
			}
			budget += n
		default:
			return false
		}
		if budget > maxDatagramBytes {
			return false
		}
		remaining = strings.TrimSpace(remaining[end+1:])
	}
	return tags > 0
}
