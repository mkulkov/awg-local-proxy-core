# Stdio protocol version 1

One UTF-8 JSON object per line, at most 65536 bytes excluding newline. Envelope:

```json
{"protocol_version":1,"type":"hello","id":"1","payload":{}}
```

Exact lowercase property names, no duplicate/unknown properties, bounded IDs
(1-64 bytes), payload objects only. Malformed envelopes close the session. Errors
are `{code: string}` without reflecting configuration or arbitrary inputs.

| Command | Payload | Response |
|---|---|---|
| hello | `{}` | `hello`: protocol_version=1, core_version=`awg-local-core-0.1.0`, commit=`independent`, capabilities includes real_core |
| validate_config | `{config: string}` | `validated`: `{valid: true}`, or error invalid_config |
| connect | `{config: string, socks_address: string, http_address: string, probe_url: string, timeout_seconds: int}` | `status` only after handshake/probe; failure closes partial resources |
| get_status | `{}` | `status` without network probing |
| check_tunnel | `{}` | `status`; failed explicit probe closes session and returns Error |
| disconnect | `{}` | `status` Stopped |
| shutdown | `{}` | `shutdown` `{}`, then process exits |

SOCKS defaults to `127.0.0.1:1080`; empty HTTP means off. An explicit HTTP(S) probe
URL is required; no arbitrary external verification service is selected silently.
Connect timeout defaults to 15 seconds and must be 1-60. Check uses 10 seconds.

Status: state, demo=false, listener_ready, tunnel_verified, optional handshake_at,
message, optional socks_address and http_address. Connected requires verified
handshake, successful probe and opened listeners. Future async events are not
implemented; the desktop requests status. Response IDs correlate to requests;
connect/check are cancellable and may reply after a later stop command.
