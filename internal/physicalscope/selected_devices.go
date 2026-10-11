package physicalscope

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// SelectedDeviceProjection is bounded user intent, never a MAC/IP observation.
// Both sets must resolve through the actual dual-stack kernel binder. Excluded
// devices remain in the original physical cohort even when also selected.
type SelectedDeviceProjection struct {
	DeviceIDs         []string `json:"device_ids"`
	ExcludedDeviceIDs []string `json:"excluded_device_ids"`
}

func cloneSelectedDeviceProjection(p *SelectedDeviceProjection) *SelectedDeviceProjection {
	if p == nil {
		return nil
	}
	return &SelectedDeviceProjection{DeviceIDs: slices.Clone(p.DeviceIDs), ExcludedDeviceIDs: slices.Clone(p.ExcludedDeviceIDs)}
}

func physicalDeviceID(mac string) string {
	return "mac-" + strings.ReplaceAll(mac, ":", "-")
}

func projectionIntentMACs(p *SelectedDeviceProjection) (map[string]bool, error) {
	if p == nil {
		return nil, nil
	}
	if len(p.DeviceIDs) == 0 || len(p.DeviceIDs) > 128 || len(p.ExcludedDeviceIDs) > 128 {
		return nil, at("projection.intent.count", nil)
	}
	wanted := map[string]bool{}
	for _, ids := range [][]string{p.DeviceIDs, p.ExcludedDeviceIDs} {
		seen := map[string]bool{}
		for _, id := range ids {
			mac := strings.ReplaceAll(strings.TrimPrefix(id, "mac-"), "-", ":")
			if !validMAC(mac) || physicalDeviceID(mac) != id || strings.ToLower(mac) != mac || seen[id] {
				return nil, at("projection.intent.device", nil)
			}
			seen[id], wanted[mac] = true, true
		}
	}
	return wanted, nil
}

func canonicalSelectedDeviceProjection(p *SelectedDeviceProjection) (*SelectedDeviceProjection, error) {
	if _, err := projectionIntentMACs(p); err != nil {
		return nil, err
	}
	p = cloneSelectedDeviceProjection(p)
	if p != nil {
		slices.Sort(p.DeviceIDs)
		slices.Sort(p.ExcludedDeviceIDs)
	}
	return p, nil
}

// Intent only identifies what must be observed; a missing or substituted
// binding cannot be manufactured by decoding the MAC-shaped device ID.
func validateSelectedDevices(p *SelectedDeviceProjection, devices []Device) error {
	wanted, err := projectionIntentMACs(p)
	if err != nil || p == nil {
		return err
	}
	seen := map[string]bool{}
	for _, d := range devices {
		if !wanted[d.MAC] || physicalDeviceID(d.MAC) != d.ID || seen[d.MAC] {
			return at("projection.bindings.identity", nil)
		}
		seen[d.MAC] = true
	}
	if len(seen) != len(wanted) {
		return at("projection.bindings.missing", nil)
	}
	return nil
}

func projectionAddressKey(index int, address netip.Addr) string {
	if address.IsLinkLocalUnicast() {
		return strconv.Itoa(index) + "\x00" + address.String()
	}
	return address.String()
}

type selectedDeviceWatch struct {
	macs      map[string]bool
	addresses map[string]bool
}

// The immutable first snapshot owns the notification boundary. Infrastructure
// stays negative and strict; only proven unrelated ordinary client churn leaves
// this boundary. An unresolved row can still conflict by its original address.
func selectedSnapshotWatch(snapshot Snapshot) (*selectedDeviceWatch, error) {
	p := snapshot.Selection.SelectedDevices
	if p == nil {
		return nil, nil
	}
	if err := validateSelectedDevices(p, snapshot.Devices); err != nil {
		return nil, err
	}
	wanted, _ := projectionIntentMACs(p)
	w := &selectedDeviceWatch{macs: wanted, addresses: map[string]bool{}}
	addMAC := func(mac string) error {
		if mac == "" {
			return nil
		}
		if !validMAC(mac) {
			return at("projection.infrastructure.mac", nil)
		}
		w.macs[mac] = true
		return nil
	}
	addAddress := func(index int, raw string) error {
		address, err := netip.ParseAddr(raw)
		if err != nil {
			return at("projection.bindings.address", err)
		}
		w.addresses[projectionAddressKey(index, address)] = true
		return nil
	}
	for _, d := range snapshot.Devices {
		for _, addresses := range [][]string{d.Addresses, d.LinkLocalAddresses} {
			for _, address := range addresses {
				if err := addAddress(d.IfIndex, address); err != nil {
					return nil, err
				}
			}
		}
	}
	for _, s := range snapshot.Segments {
		if err := addMAC(s.MAC); err != nil {
			return nil, err
		}
		for _, member := range s.Members {
			if err := addMAC(member.MAC); err != nil {
				return nil, err
			}
			if member.Parent.Known {
				if err := addMAC(member.Parent.MAC); err != nil {
					return nil, err
				}
			}
		}
		for _, raw := range s.LinkAddresses {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, at("projection.infrastructure.address", err)
			}
			w.addresses[projectionAddressKey(s.IfIndex, prefix.Addr())] = true
		}
		for _, router := range s.RouterNeighbors {
			if err := addMAC(router.MAC); err != nil {
				return nil, err
			}
			if err := addAddress(s.IfIndex, router.Address); err != nil {
				return nil, err
			}
		}
	}
	return w, nil
}

func (w *selectedDeviceWatch) owns(n kernelNeighbor) bool {
	return w.macs[n.mac] || w.addresses[projectionAddressKey(n.index, n.address)]
}

func (w *selectedDeviceWatch) irrelevant(n kernelNeighbor) (bool, error) {
	if n.mac != "" && !validMAC(n.mac) {
		return false, at("projection.neighbor.mac", nil)
	}
	return n.flags&128 == 0 && !w.owns(n), nil
}

// Every selected-bridge row has already passed the exact kernel decoder. Read
// all rows before filtering so a foreign MAC cannot claim a cohort/router IP,
// and an IPv6 router flag cannot turn an IPv4-only chosen client into a router.
func validateProjectedNeighbors(p *SelectedDeviceProjection, segments []Segment, neighbors, foreign []kernelNeighbor, routerMACs map[string]bool) (map[string]bool, error) {
	wanted, err := projectionIntentMACs(p)
	if err != nil || p == nil {
		return wanted, err
	}
	owners := map[string]string{}
	for _, s := range segments {
		for _, raw := range s.LinkAddresses {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || !validMAC(s.MAC) {
				return nil, at("projection.infrastructure.address", err)
			}
			key := projectionAddressKey(s.IfIndex, prefix.Addr())
			if previous, exists := owners[key]; exists && previous != s.MAC {
				return nil, at("projection.bindings.address-conflict", nil)
			}
			owners[key] = s.MAC
		}
	}
	for _, n := range neighbors {
		if n.mac != "" && !validMAC(n.mac) {
			return nil, at("projection.neighbor.mac", nil)
		}
		if !wanted[n.mac] && !routerMACs[n.mac] {
			continue
		}
		if wanted[n.mac] && (routerMACs[n.mac] || n.state == 1 || n.state == 32) {
			return nil, at("projection.bindings.role-state", nil)
		}
		key := projectionAddressKey(n.index, n.address)
		if previous, exists := owners[key]; exists && previous != n.mac {
			return nil, at("projection.bindings.address-conflict", nil)
		}
		owners[key] = n.mac
	}
	for _, n := range neighbors {
		if mac, protected := owners[projectionAddressKey(n.index, n.address)]; protected && mac != n.mac {
			return nil, at("projection.bindings.address-conflict", nil)
		}
	}
	for _, n := range foreign {
		if routerMACs[n.mac] {
			return nil, at("projection.bindings.ingress", nil)
		}
		if mac, protected := owners[projectionAddressKey(n.index, n.address)]; protected && mac != n.mac {
			return nil, at("projection.bindings.address-conflict", nil)
		}
	}
	return wanted, nil
}
