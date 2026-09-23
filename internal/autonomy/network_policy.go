package autonomy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
)

// These are inputs from a confirmed platform observation, never instructions
// supplied by a browser or permission to inspect arbitrary network segments.
type HomeSegment struct {
	ID, Interface string
	Prefixes      []netip.Prefix
	Home, WAN     bool
}
type DeviceBinding struct {
	ID, MAC, Interface, SegmentID string
	Confirmed                     bool
}
type ScopeObservation struct {
	BootID, NetworkID      string
	Revision               uint64
	ObservedAt, FreshUntil time.Time
	Segments               []HomeSegment
	Devices                []DeviceBinding
}
type ClientPacket struct {
	Address                   netip.Addr
	MAC, Interface, SegmentID string
}
type TrafficQuestion struct {
	Client               ClientPacket
	Domain               string
	Address              netip.Addr
	ServiceID            string
	ServiceSelected      bool
	ServiceSources       []string
	ExplicitBypass       bool // explicit override, never inferred from ServiceSelected
	ProtectedDestination bool
}
type NetworkDecision struct {
	Action         string `json:"action"` // base, bypass, or unavailable; no access proof
	Reason         string `json:"reason_code"`
	RuleID         string `json:"rule_id,omitempty"`
	RuleRevision   uint64 `json:"rule_revision,omitempty"`
	PolicyRevision uint64 `json:"policy_revision"`
	ScopeDigest    string `json:"scope_digest,omitempty"`
	DeviceID       string `json:"device_id,omitempty"`
}

func validMAC(value string) (string, bool) {
	mac, err := net.ParseMAC(value)
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" {
		return "", false
	}
	return mac.String(), true
}

func sameMAC(a, b string) bool {
	left, ok := validMAC(a)
	right, otherOK := validMAC(b)
	return ok && otherOK && left == right
}

func clientScope(p *config.NetworkPolicy, observation ScopeObservation, client ClientPacket, now time.Time) (string, string) {
	if observation.BootID == "" || observation.NetworkID == "" || observation.Revision == 0 || now.Before(observation.ObservedAt) || !now.Before(observation.FreshUntil) || observation.FreshUntil.Sub(observation.ObservedAt) > 2*time.Minute || len(observation.Segments) > 16 || len(observation.Devices) > 512 {
		return "SCOPE_UNAVAILABLE", ""
	}
	if !slices.Contains(p.Clients.SegmentIDs, client.SegmentID) {
		return "OUTSIDE_SCOPE", ""
	}
	if _, ok := validMAC(client.MAC); !ok {
		return "SCOPE_UNAVAILABLE", ""
	}
	var segment *HomeSegment
	for i := range observation.Segments {
		s := &observation.Segments[i]
		if s.ID == client.SegmentID {
			if segment != nil {
				return "SCOPE_UNAVAILABLE", ""
			}
			segment = s
		}
	}
	if segment == nil || !segment.Home || segment.WAN || segment.Interface == "" || segment.Interface != client.Interface || len(segment.Prefixes) == 0 || len(segment.Prefixes) > 16 {
		return "SCOPE_UNAVAILABLE", ""
	}
	inside := false
	for _, prefix := range segment.Prefixes {
		if prefix.Bits() == 0 || !prefix.IsValid() || prefix != prefix.Masked() {
			return "SCOPE_UNAVAILABLE", ""
		}
		if prefix.Contains(client.Address) {
			inside = true
		}
	}
	if !inside || !client.Address.IsValid() || client.Address.Is4In6() || client.Address.Zone() != "" || client.Address.IsLoopback() || client.Address.IsMulticast() || client.Address.IsUnspecified() {
		return "OUTSIDE_SCOPE", ""
	}
	bindings := map[string]DeviceBinding{}
	deviceID := ""
	for _, binding := range observation.Devices {
		if _, exists := bindings[binding.ID]; exists {
			return "SCOPE_UNAVAILABLE", ""
		}
		bindings[binding.ID] = binding
		if binding.Confirmed && binding.SegmentID == segment.ID && binding.Interface == client.Interface && sameMAC(binding.MAC, client.MAC) {
			if deviceID != "" {
				return "SCOPE_UNAVAILABLE", ""
			}
			deviceID = binding.ID
		}
	}
	// An unresolved negative identity cannot fall through a catch-all. If its
	// last confirmed segment is known, only that segment is unavailable.
	negative := slices.Clone(p.Clients.ExcludedDeviceIDs)
	for _, rule := range p.Rules {
		if rule.Action == "direct" {
			negative = append(negative, rule.DeviceIDs...)
		}
	}
	for _, id := range negative {
		binding, known := bindings[id]
		_, macOK := validMAC(binding.MAC)
		if !known || !binding.Confirmed || !macOK || binding.Interface == "" || binding.SegmentID == "" || binding.SegmentID == segment.ID && binding.Interface != segment.Interface {
			if !known || binding.SegmentID == "" || binding.SegmentID == segment.ID {
				return "SCOPE_UNAVAILABLE", deviceID
			}
		}
	}
	if slices.Contains(p.Clients.ExcludedDeviceIDs, deviceID) {
		return "DEVICE_EXCLUDED", deviceID
	}
	for _, value := range p.Clients.ExcludedCIDRs {
		prefix, _ := netip.ParsePrefix(value)
		if prefix.Contains(client.Address) {
			return "ADDRESS_EXCLUDED", deviceID
		}
	}
	if p.Clients.Mode == "selected_devices" && !slices.Contains(p.Clients.DeviceIDs, deviceID) || p.Clients.Mode == "lan_except" && p.Clients.NewDevices == "base" && deviceID == "" {
		return "OUTSIDE_SCOPE", deviceID
	}
	return "", deviceID
}

func ruleMatches(r config.NetworkRule, q TrafficQuestion, device string) bool {
	if len(r.DeviceIDs) > 0 && !slices.Contains(r.DeviceIDs, device) {
		return false
	}
	switch r.Kind {
	case "exact":
		return q.Domain == r.Value
	case "suffix":
		return q.Domain == r.Value || strings.HasSuffix(q.Domain, "."+r.Value)
	case "ip":
		ip, _ := netip.ParseAddr(r.Value)
		return q.Address == ip
	case "cidr":
		p, _ := netip.ParsePrefix(r.Value)
		return p.Contains(q.Address)
	}
	return false
}

// DecideNetworkPolicy is pure. Every executor must consume the same result;
// the function itself never grants a runtime capability or mutates networking.
func DecideNetworkPolicy(p *config.NetworkPolicy, observation ScopeObservation, q TrafficQuestion, now time.Time) NetworkDecision {
	d := NetworkDecision{Action: "unavailable", Reason: "POLICY_INVALID"}
	if p == nil || config.ValidateNetworkPolicy(p) != nil {
		return d
	}
	d.PolicyRevision = p.Revision
	if q.ProtectedDestination {
		d.Action, d.Reason = "base", "PROTECTED_DESTINATION"
		return d
	}
	if q.Domain != "" {
		name, err := config.PolicyDomain(q.Domain)
		if err != nil {
			d.Reason = "DOMAIN_IDENTITY_UNAVAILABLE"
			return d
		}
		q.Domain = name
	}
	reason, device := clientScope(p, observation, q.Client, now)
	d.DeviceID = device
	if reason != "" {
		d.Reason = reason
		if reason != "SCOPE_UNAVAILABLE" {
			d.Action = "base"
		}
		return d
	}
	d.ScopeDigest = networkScopeDigest(p, observation)
	if len(q.ServiceSources) > 128 {
		d.Reason = "SCOPE_UNAVAILABLE"
		return d
	}
	if len(q.ServiceSources) > 0 {
		inherited := false
		for _, value := range q.ServiceSources {
			prefix, err := netip.ParsePrefix(value)
			if err != nil || !prefix.IsValid() || prefix.Bits() == 0 || prefix != prefix.Masked() || prefix.Addr().Is4In6() {
				d.Reason = "SCOPE_UNAVAILABLE"
				return d
			}
			if prefix.Contains(q.Client.Address) {
				inherited = true
			}
		}
		if !inherited {
			d.Action, d.Reason = "base", "SERVICE_SCOPE_MISMATCH"
			return d
		}
	}
	var direct, bypass, mandatoryBypass *config.NetworkRule
	for i := range p.Rules {
		rule := &p.Rules[i]
		if !ruleMatches(*rule, q, device) {
			continue
		}
		if rule.Action == "direct" {
			if direct == nil || rule.ID < direct.ID {
				direct = rule
			}
		} else {
			if bypass == nil || rule.ID < bypass.ID {
				bypass = rule
			}
			if rule.Mandatory {
				mandatoryBypass = rule
			}
		}
	}
	if direct != nil && mandatoryBypass != nil {
		d.Reason = "MANUAL_RULE_CONFLICT"
		return d
	}
	if direct != nil {
		d.Action, d.Reason, d.RuleID, d.RuleRevision = "base", "MANUAL_DIRECT", direct.ID, direct.Revision
		return d
	}
	if bypass != nil {
		d.Action, d.Reason, d.RuleID, d.RuleRevision = "bypass", "MANUAL_BYPASS_OVERRIDE", bypass.ID, bypass.Revision
		return d
	}
	if q.ExplicitBypass {
		d.Action, d.Reason = "bypass", "MANUAL_BYPASS_OVERRIDE"
		return d
	}
	if p.Russian.Enabled {
		match := q.ServiceID != "" && slices.Contains(p.Russian.ServiceIDs, q.ServiceID)
		for _, tld := range p.Russian.BroadTLDs {
			match = match || q.Domain != "" && strings.HasSuffix(q.Domain, "."+tld)
		}
		if match {
			d.Action, d.Reason, d.RuleID, d.RuleRevision = "base", "RU_CATALOG_DIRECT", p.Russian.CatalogID, p.Russian.Revision
			return d
		}
	}
	d.Action, d.Reason = "base", "UNSELECTED_DESTINATION"
	if q.ServiceSelected || p.Traffic.Mode == "all_except" {
		d.Action, d.Reason = "bypass", "DEFAULT_POLICY"
	}
	return d
}

// Freshness is checked separately. Renewing an unchanged observation or its
// enumeration order must not invalidate every existing policy identity.
func networkScopeDigest(policy *config.NetworkPolicy, observation ScopeObservation) string {
	p := config.CloneNetworkPolicy(policy)
	for _, values := range [][]string{p.Clients.SegmentIDs, p.Clients.DeviceIDs, p.Clients.ExcludedDeviceIDs, p.Clients.ExcludedCIDRs, p.Russian.ServiceIDs, p.Russian.BroadTLDs} {
		slices.Sort(values)
	}
	for i := range p.Rules {
		slices.Sort(p.Rules[i].DeviceIDs)
	}
	slices.SortFunc(p.Rules, func(a, b config.NetworkRule) int { return strings.Compare(a.ID, b.ID) })
	o := observation
	o.ObservedAt = time.Time{}
	o.FreshUntil = time.Time{}
	o.Segments = slices.Clone(observation.Segments)
	for i := range o.Segments {
		o.Segments[i].Prefixes = slices.Clone(o.Segments[i].Prefixes)
		slices.SortFunc(o.Segments[i].Prefixes, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
	}
	slices.SortFunc(o.Segments, func(a, b HomeSegment) int { return strings.Compare(a.ID, b.ID) })
	o.Devices = slices.Clone(observation.Devices)
	for i := range o.Devices {
		if mac, ok := validMAC(o.Devices[i].MAC); ok {
			o.Devices[i].MAC = mac
		}
	}
	slices.SortFunc(o.Devices, func(a, b DeviceBinding) int { return strings.Compare(a.ID, b.ID) })
	encoded, _ := json.Marshal(struct {
		Policy      *config.NetworkPolicy
		Observation ScopeObservation
	}{p, o})
	hash := sha256.Sum256(encoded)
	return hex.EncodeToString(hash[:])
}

// IP-set executors cannot express opposing decisions for one client's shared
// address. The candidate must be rejected; dropping one side is not a repair.
type AddressDecision struct {
	Interface string
	Sources   []netip.Prefix // already intersected with the managed home scope
	MAC       string         // optional packet discriminator, not a device display name
	Address   netip.Addr
	Domain    string
	Action    string
}

func SharedAddressConflict(decisions []AddressDecision) bool {
	if len(decisions) > 8192 {
		return true
	}
	type key struct {
		ingress string
		address netip.Addr
	}
	type entry struct {
		source      netip.Prefix
		mac, action string
	}
	seen := map[key][]entry{}
	total := 0
	for _, d := range decisions {
		if d.Interface == "" || !d.Address.IsValid() || d.Address.Zone() != "" || !slices.Contains([]string{"base", "bypass"}, d.Action) || len(d.Sources) == 0 || len(d.Sources) > 32 {
			return true
		}
		mac := ""
		if d.MAC != "" {
			var ok bool
			mac, ok = validMAC(d.MAC)
			if !ok {
				return true
			}
		}
		k := key{d.Interface, d.Address.Unmap()}
		for _, source := range d.Sources {
			if !source.IsValid() || source.Bits() == 0 || source != source.Masked() || source.Addr().Is4In6() {
				return true
			}
			// Bound both memory and pairwise overlap comparisons on small routers.
			total++
			if total > 32768 || len(seen[k]) >= 256 {
				return true
			}
			for _, previous := range seen[k] {
				if previous.action != d.Action && (previous.mac == "" || mac == "" || previous.mac == mac) && source.Overlaps(previous.source) {
					return true
				}
			}
			seen[k] = append(seen[k], entry{source, mac, d.Action})
		}
	}
	return false
}
