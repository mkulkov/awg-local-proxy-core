# AWG Local Proxy Core

Original Go control and loopback proxy process built around the official
`github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260828` engine, source commit
`b5928efb6ca19f0153958460c3d141f04abc5c2e`. No code from
`synacker/amnezia-proxy` is used. This component has a separate source directory
and module from the desktop product.

The engine and its userspace netstack are MIT licensed. Its gVisor dependency is
Apache-2.0 licensed. The license of the original wrapper has not been assigned
on behalf of its owner. Dependency notices must accompany any distribution.

Run `awg-proxy-core.exe --control-stdio`. Configuration arrives exclusively in
bounded inherited stdin NDJSON, never command arguments, environment variables,
URLs or plaintext temporary files. Stdout is protocol only and the engine logger
is silent. EOF, disconnect, shutdown or a failed explicit verification closes the
owned engine/listeners. No host TUN adapter, driver, route, DNS, system proxy,
firewall or service is configured.

Only TCP SOCKS5 CONNECT and HTTP forward/CONNECT on literal IPv4 loopback are
supported. SOCKS BIND and UDP ASSOCIATE fail explicitly. Destination TCP and DNS
use only the userspace tunnel. Numeric DNS must be covered by AllowedIPs. The
VPN endpoint's bootstrap hostname resolution is the sole host-resolver exception;
a numeric endpoint avoids it. Proxy access is available to other local processes;
loopback is not an application allowlist. There is no DIRECT fallback.
Relay traffic in either direction refreshes a shared five-minute idle timeout;
active downloads are not cut off by an absolute five-minute session deadline.

`Connected` means the explicitly configured HTTP(S) probe and a real handshake
were confirmed. `get_status` does not poll websites or infer failure merely from
an old idle handshake. A failed actual destination dial changes status to
`Degraded`; `check_tunnel` performs a user-requested probe using the configured
URL and closes the session on failure. Listeners are opened only after successful
initial verification. A returned HTTP 2xx or 3xx is accepted, with no redirect
following; TLS verification uses Go's ordinary certificate verification.

The client `.conf` subset supports one Interface and Peer: PrivateKey, Address,
DNS, MTU, Jc/Jmin/Jmax, S1-S4, H1-H4, I1-I5, PublicKey, PresharedKey, Endpoint,
AllowedIPs and PersistentKeepalive. Unknown fields, hooks, duplicate sections or
fields, administrative exports, inline comments and ambiguous content fail.
The pinned Windows buffer is 2016 bytes: MTU + S4 + 32 must fit, handshake/cookie
padding must also fit. Jc <= 128; nonzero Jc requires explicit Jmin < Jmax and
sizes <= 2016. I packets allow at most 32 strict engine tags with a 2016-byte
fixed output budget. The complete profile is at most 48 KiB. Accepted values are
preserved; unsupported `.vpn` and newer engine fields are not silently discarded.

Build and verify with Go 1.25 or newer:

```text
go mod verify
go test ./... -timeout 300s
go vet ./...
go build -trimpath -o dist/awg-proxy-core.exe ./cmd/awg-proxy-core
```

Tests create ephemeral keys and userspace AWG peers on local UDP endpoints. They
do not use a user's configuration, production server or host routes. Passing lab
tests does not establish compatibility with a particular user's server or every
AmneziaWG protocol version.
