# Bounded Telegram HTTPS evaluation (development CLI)

This command performs fresh Telegram **HTTPS** checks through selected VLESS
nodes using the existing `ExactNodeChecker`. It never applies a production route
or records node health/history. It is a diagnostic, not release acceptance.

Build `./cmd/nodeeval` for the target host. Run one invocation at a time, using
an unused loopback port and a new private workspace whose parent already exists:

```sh
nodeeval -root /opt/tmp/telegram-singbox-001 \
  -store /opt/etc/razvilka/nodes \
  -engine sing-box -binary /opt/bin/sing-box \
  -limit 12 -duration 8m -check-timeout 45s -port 19291

nodeeval -root /opt/tmp/telegram-xray-001 \
  -preset igareck-black-vless \
  -engine xray -binary /opt/tmp/pinned-xray/xray \
  -limit 12 -duration 8m -check-timeout 45s -port 19301
```

Paths above are examples; use the reviewed private NodeStore and verified runtime
paths for the host. `-binary` is an absolute path; omission uses existing checker
discovery. The command does not install or replace runtime binaries.

`-root` must not exist. Use exactly one of `-store` or `-preset`. Existing stores
must be private and available: the ordinary NodeStore OS lease is respected, so
a store already held by the application is refused. Reads do not modify the
private node document; opening a store may create its normal lease marker.
The checker and report workspace must be outside that store hierarchy, including
resolved parent aliases. A reviewed detached private copy can be used when the
live application holds the store. No automatic copying, restore or lease bypass
is provided.

Fresh feed mode accepts only the existing approved preset IDs. It creates its
own private store under the new workspace, fetches once using the actual feed
manager, and uses canonical parsing with partial acceptance. The history guard
is constructed only from the newly created empty store, pins both directory
identities, and calls its actual typed history reader before feed publication.
Requested and stored reader requirements must fit the compiled reader
capability. Unknown versions, corrupt state, cancellation, closed stores and
directory identity changes refuse publication. This grants no authority over
live history, controller/update compatibility, retained images or restores.
Imported nodes remain untrusted and unchecked; results never call `RecordCheck`.
Private feed material remains inside the private workspace; do not publish it.

`-limit` is the total number of enabled VLESS candidates attempted (1–128), not
the number of successful checks. Unsupported transports consume a candidate and
are reported as inconclusive; there is no conversion to another transport.
`-duration` bounds the whole invocation (30 seconds–1 hour), with 20 seconds
reserved for cleanup; `-check-timeout` is 1–60 seconds. A finite parent deadline
can shorten the budget. Each node obtains a new WAN profile; cached health only
chooses order. The exact checker also validates that network profile during the
check and after session cleanup.

The report contains safe identifiers, fixed diagnostic codes and counters on
stdout and in `<root>/results.jsonl`. It contains no endpoint, credential,
subscription URL, egress IP, raw error, process log or private evidence. A
positive candidate requires fresh matching node/service/network/engine identity,
service-level PASS, HTTP 2xx and confirmed exact-checker cleanup. The checker
tests `https://telegram.org/` by name and literal destination with the same TLS
hostname. HTTPS success does not establish MTProto, account login, media, voice,
LAN/TUN routing or production Selectable status.

Any cleanup acknowledgement gap stops the invocation before another candidate,
including a cleanup failure returned with a nil Go error. At most one bounded
`Recover` call is made; there is no retry/recovery loop. Recovery success after
such a gap does not upgrade that invocation to a completed result. Signal
cancellation stops work while cleanup retains the same finite overall deadline.

Exit codes: `0` means completed with at least one fresh HTTPS PASS; `2` means
completed with no fresh HTTPS PASS; `1` means refused or incomplete. For overall
acceptance, require a final summary with `finished: true` and a matching exit
code. Candidate rows in an incomplete report do not establish a completed run.
A one-hour release test window must be scheduled and assessed separately by
Root; this command stops when its candidate bound is exhausted.

## Separate MTProto QA proposal

No MTProto implementation or independent SOCKS proxy is included here.
The official [MTProto authorization flow](https://core.telegram.org/mtproto/auth_key)
starts with unauthenticated `req_pq_multi#be7e8ef1` and a random 128-bit nonce.
A well-formed `resPQ#05162463` with the same nonce demonstrates a protocol
response. It does **not** authenticate the remote server: RSA/DH verification
occurs later. It establishes neither account login nor media/voice access.

A separate Root-owned native-only test can wrap the original private
`serviceProbe` inside the dataplane package while its exact-node session is still
alive. Preserve the original HTTPS check and all checker identity/network/cleanup
guards; publish the MTProto observation separately from NodeCheck/HTTPS PASS.
The listener cannot safely be borrowed after `Check` returns because its session
has already been cleaned up. Use a reviewed numeric Telegram DC through that
owned SOCKS session, with no direct fallback and no additional proxy process.

Per the official [message envelope](https://core.telegram.org/mtproto/description)
and [abridged TCP transport](https://core.telegram.org/mtproto/mtproto-transports#abridged),
send the `0xef` transport marker, a bounded frame, `auth_key_id = 0`, a valid
message ID and the one TL request. Bound receive size and deadline before any
allocation. Require the expected constructor, echoed nonce, valid envelope/TL
lengths and vector bounds, with no trailing bytes. Reject malformed or oversized
frames, transport errors, wrong nonce, stalls and cancellation. Send no later
authorization or account methods. Tests must cover these refusals and unchanged
checker cleanup behavior before any native protocol-reachability claim.
