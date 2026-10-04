# CORE: qualified default forwarding and managed subnet FIB readback

04.10.2026. Shared forwarding validation now permits IPv4/IPv6 `/0` destinations
only when the existing full layout validator accepts a nonempty network
generation, NetworkDefault role, exact managed rule, ingress and matching grant.
Legacy/default-less/unmarked/mismatched or global-source shapes remain refused.
This is compiler shape validation, not a live forwarding/ownership grant.

`verifyPolicyEvidence` uses a bounded non-local source for managed CIDR rules even
without a userspace forwarding manifest. The checked immutable rule supplies
its ingress; the existing reverse FIB/unique directly connected main-table
observer checks each candidate and skips router-local addresses. The readonly
sample creates no forwarding manifest and cannot authorize filter/NAT cleanup.
Legacy CIDR evidence still requires its exact forwarding grant. Every managed
pair is observed, including IPv6 after four IPv4 cells, within the same 512-rule
bound; legacy unqualified sampling limits remain unchanged.

Regression tests cover both families, exact `/0` shape and rejection of missing
generation/role/mark/ingress, unrelated grants and global client sources. Stateful
modeled policy installation precedes readback. New subnet tests reject a local
router source, use the next non-local address with exact iif/managed mark, retain
nil Forwarding, and catch a bad fifth IPv6 result. Related Windows dataplane
models passed 0.903s; vet/diff RC0. No native or full D07 readiness is claimed.

NET owns WG source NAT and its common mixed effect compiler/readback callbacks;
userspace proxy NAT ACCEPT is not a WG source NAT substitute. Public delegated
IPv6 LAN prefix forwarding is not broadened by this change: existing private
subnet checks still apply. A full LAN classifier/consumer receipt is not proved
by these observations.

Root review held the first checkpoint because `/0` used the unspecified prefix
base. The follow-up selects one of four bounded public unicast literals per
family, inside the destination and outside the reviewed endpoint exclusions and
client subnet. It refuses unavailable/unqualified scope and never retries a
failed or wrong-interface FIB result. Selection sends no packets and is not
remote reachability evidence. The real command retains exact forwarded source,
ingress and managed mark, with `-6` for IPv6. Models cover both families, an
excluded first candidate, all candidates excluded, bad exclusion, missing
authority and a wrong device without fallback. Related dataplane tests passed
0.885s; vet/diff RC0. Native execution remains with Root, including actual
IPv4/IPv6 default FIB observations before promoting the held checkpoint.

Root's isolated native source54 then confirmed a separate readback mismatch:
`67: from 192.168.93.0/24 fwmark 0x20000000/0x28000000 iif rz-def-lan lookup 204`
and the equivalent IPv6 `from fd93::/64` omit `to` for the default destination.
The ownership parser now normalizes only fixed 5/7/9-token omitted-destination
forms into its existing 7/9/11-token exact grammar, inserting family-specific
canonical `/0`. Exact mark/mask, ingress, source family, numeric coordinates
and unknown-selector rejection remain required. No general token parser or
cleanup authority is added. Regressions compare omitted/explicit tuples in
both families, refuse near matches and run modeled apply/readback/cleanup with
the actual omitted form. The existing ingress test now checks every expected
full tuple at reserved priorities while leaving baseline rules outside those
priorities alone. Root remains responsible for repeating actual native kernel
verification after this parser correction.

Numeric route readback follow-up: the existing exact default-route parser now
accepts only `proto 3` as the numeric alias for `boot` and `scope 253` as the
numeric alias for `link`. The recorded deletion selector retains canonical
`boot`/`link` arguments so immutable receipt comparison does not change. Both
families and mixed symbolic/numeric forms are covered through the actual `-N`
read wrapper. Near values, duplicates, gateways and unknown attributes remain
refused. Related portable dataplane tests passed 24.829s; vet/diff RC0. This
does not change NET's full service-table ownership check or authorize native
execution; Root owns the native repeat.
