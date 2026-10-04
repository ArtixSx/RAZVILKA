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
