# Core verification — 2026-10-30

Environment: Windows amd64, Go 1.27.3, official AmneziaWG Go
`v3.1.20260828`, source commit `b5928efb6ca19f0153958460c3d141f04abc5c2e`.
The runtime explicitly uses the official ordinary UDP `conn.NewStdNetBind`;
the specialized Windows RIO bind path is excluded. No production profile or
user server was involved. Tests generate ephemeral X25519 keys in memory.

Passed:

- `go test -v ./... -count=1 -timeout 300s`: full core suite, 100.5 seconds.
  Real client/server userspace AWG handshake, J/S/H parameters, DNS inside the
  server netstack, SOCKS5 domain CONNECT, HTTP forward and CONNECT, negative
  host-loopback fallback test, peer-loss failure, parser/protocol guards,
  occupied-port preservation, unsupported SOCKS BIND/UDP/authentication and
  managed-process EOF cleanup.
- The full suite includes **100 real connect/handshake/probe/disconnect cycles**
  with repeated port reuse, 85.6 seconds. This does not measure heap, handle or
  goroutine trends and is not evidence of zero resource growth.
- `go vet ./...` and `go mod verify` (all modules verified).
- `go test -race -v ./core -run 'TestRealAWG|TestIPacket|TestHTTPAccepted|TestManagedChild|TestConnectFailures|TestSOCKSUnsupported|TestParser' -count=1 -timeout 180s`:
  pass, 25.7 seconds test runtime, no race findings. The 100-cycle test was not
  repeated under the race detector.
- Parser fuzz smoke, 3 seconds / 2 workers: 8,605 executions, pass.
- Control-envelope fuzz smoke, 3 seconds / 2 workers: 7,679 executions, pass.

After replacing the absolute relay deadline with a refreshed shared idle timeout:

- Targeted real AWG, actual CLI IPC, relay and product-supervisor tests passed,
  38.6 seconds. The idle regression transmits one-way data for longer than the
  configured test idle period, then verifies shutdown during real inactivity.
- `TestManagedChildEOFClosesRealListeners` builds the real core executable,
  launches `--control-stdio`, sends configuration through stdin, verifies the
  Connected reply, performs SOCKS/HTTP requests, checks explicit verification,
  forces a probe rejection and confirms listener closure, reconnects and then
  verifies cleanup on stdin EOF.
- `TestProductRealSupervisorUserspaceLab` passed with the actual desktop
  product's `RealSupervisor` test helper. The product supervisor verifies and
  launches the real core, sends the synthetic profile via stdin, reaches the
  userspace server through both SOCKS and HTTP, and closes the owned core.
  Only the helper executable path is supplied in `AWG_PRODUCT_LAB_HELPER`;
  configuration and keys never enter process arguments, environment or files.
  Without that variable, this integration test explicitly skips.
- Targeted `-race` after the relay change passed for both the idle regression
  and actual product-supervisor lab (31.4 seconds), followed by `go vet ./...`.

Safety regressions cover exact JSON property casing, duplicates, bounded
messages, pre-header HTTP connection limits, hostile I-packet lengths/tags,
effective junk defaults and Windows 2016-byte composite buffer limits.

Not established: connection to the user's server, a complete version matrix for
AWG families, external physical-egress capture, cross-network sleep/resume,
all 100 cycles under race, or long-term handle/heap trends. The selected runtime
works in the controlled lab; these results do not establish those other claims.
