# AWG Local Proxy Core

Original Go control and loopback proxy process built around the official
`github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260828` engine, source commit
`b5928efb6ca19f0153958460c3d141f04abc5c2e`. No code from
`synacker/amnezia-proxy` is used. This component has a separate source directory
and module from the desktop product.

The original wrapper code is [MIT licensed](LICENSE). The official engine and
its userspace netstack are MIT licensed; gVisor is Apache-2.0 licensed.
Dependency licenses and notices must accompany any distribution. The MIT
license of this wrapper does not relicense third-party code.

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

The original startup TUN adapter coordinates initial configuration with the
pinned engine's constructor-started reader, so the first real packet uses the
configured S4 offset. It also suppresses the netstack's queued automatic EventUp;
only an explicit connection starts the UDP bind. A legacy unmodified Go peer's
first incorrectly padded reply is tolerated by the pinned resolver's existing
two bounded DNS attempts inside the tunnel; no extra probe or host retry is added.

`Connected` means the explicitly configured HTTP(S) probe and a real handshake
were confirmed. `get_status` does not poll websites or infer failure merely from
an old idle handshake. A failed actual destination dial changes status to
`Degraded`; `check_tunnel` performs a user-requested probe using the configured
URL and closes the session on failure. Listeners are opened only after successful
initial verification. A returned HTTP 2xx or 3xx is accepted, with no redirect
following; TLS verification uses Go's ordinary certificate verification.

The client `.conf` subset supports one Interface and Peer: PrivateKey, Address,
DNS, MTU, Jc/Jmin/Jmax, S1-S4, H1-H4, I1-I5, PublicKey, PresharedKey, Endpoint,
AllowedIPs and PersistentKeepalive. Official AWG3 fields supported by the pinned
engine are also preserved: HeaderProtectionKey, ContentPaddingAddition,
RekeyAfterTime, RekeyTimeout, RejectAfterTime, KeepaliveTimeout,
MaxHandshakeAttempts, RandomTrailers and DisableCookies. Unknown fields, hooks, duplicate sections or
fields, administrative exports, inline comments and ambiguous content fail.
The pinned Windows buffer is 2016 bytes: MTU + S4 + 32 + the maximum
ContentPaddingAddition must fit, handshake/cookie
padding must also fit. Jc <= 128; nonzero Jc requires explicit Jmin < Jmax and
sizes <= 2016. I packets allow at most 32 strict engine tags with a 2016-byte
fixed output budget. The complete profile is at most 48 KiB. Accepted values are
preserved; unsupported fields are not silently discarded. The desktop product
extracts supported client configuration from `.vpn`; this process receives INI
through the same bounded control channel.

Field names use the official INI spelling, case-insensitively, without UAPI
underscore aliases. HeaderProtectionKey must be a nonzero 32-byte standard
base64 key and requires all S1-S4 to be at least 12 bytes. H1-H4 and
ContentPaddingAddition accept unsigned decimal `N` or `lo-hi`, with ordered
uint32 endpoints; the full `0-4294967295` range is rejected to avoid the pinned
engine's range-width overflow. ContentPaddingAddition is additionally bounded
by the 2016-byte composite budget. Timing fields, MaxHandshakeAttempts and
PersistentKeepalive use that range syntax, accepting zero (`0` or `0-0`) for the
engine default/off behavior or strictly positive endpoints. RejectAfterTime
is at most 3074457345 seconds because the engine multiplies it by three;
MaxHandshakeAttempts is at most 4294967293 to keep its uint32 counter arithmetic
defined. Other timer/keepalive endpoints may reach uint32 maximum. Booleans use
Go's `strconv.ParseBool` spelling, including `true`, `false`, `1` and `0`.
DisableCookies explicitly disables the engine's cookie protection; ordinary
lab traffic does not verify behavior under a cookie or denial-of-service load.

These mappings are grounded in the pinned official
[UAPI](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/uapi.go),
[timers](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/timers.go)
and official [INI parser](https://github.com/amnezia-vpn/amneziawg-tools/blob/ee0f0a9aa34ff0a0da4b3433b9512781cfe02843/src/config.c).
Synthetic tests exercise a real encrypted userspace peer with header protection,
content padding, H ranges, timer/keepalive ranges and random trailers through
HTTP and SOCKS, and confirm that a mismatched header key leaves both listeners
closed. This establishes that tested pinned-engine feature set; a complete
AWG version/server matrix, expiration of long timer ranges and a connection to
the user's server remain untested.

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

[Core CI](.github/workflows/core-ci.yml) runs the synthetic suite, formatting,
module verification, vet and targeted race checks on Windows with Go 1.27.3.
It needs no VPN credentials and publishes no artifacts. The optional desktop
product supervisor lab requires an explicitly supplied test-helper executable;
it is skipped in this independent core workflow.
