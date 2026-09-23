package devices

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

const bindingOutputLimit = 1 << 20

var bindingInterface = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,14}$`)

var ErrBindingObservation = errors.New("device binding observation unavailable")
var ErrBindingAmbiguous = errors.New("device binding observation ambiguous")

// A current kernel mapping, not proof that a device or its Internet works.
// Callers still bind these observations to confirmed home segments/boot/network.
// They must not turn all requested interfaces into permission to manage them.
type BindingAddress struct {
	Address string `json:"address"`
	State   string `json:"state"`
}
type Binding struct {
	ID        string           `json:"id"`
	MAC       string           `json:"mac"`
	Interface string           `json:"interface"`
	Addresses []BindingAddress `json:"addresses"`
}
type BindingObservation struct {
	ObservedAt time.Time `json:"observed_at"`
	FreshUntil time.Time `json:"fresh_until"`
	Interfaces []string  `json:"interfaces"`
	Bindings   []Binding `json:"bindings"`
}

// ObserveBindings is read-only: no registry merge, DHCP/ARP-cache fallback,
// hostname inference, persisted LKG or last-seen write can invent a binding.
// Every selected interface/family must be observed in one bounded attempt.
func (m *Manager) ObserveBindings(parent context.Context, interfaces []string) (BindingObservation, error) {
	if len(interfaces) == 0 || len(interfaces) > 16 {
		return BindingObservation{}, ErrBindingObservation
	}
	interfaces = slices.Clone(interfaces)
	seen := map[string]bool{}
	for _, iface := range interfaces {
		if !bindingInterface.MatchString(iface) || iface == "lo" || seen[iface] {
			return BindingObservation{}, ErrBindingObservation
		}
		seen[iface] = true
	}
	sort.Strings(interfaces)
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	command := m.IPCommand
	if command == "" {
		command = findIPCommand()
	}
	if command == "" {
		return BindingObservation{}, ErrBindingObservation
	}
	runner := m.Runner
	if runner == nil {
		runner = execRunner{}
	}
	now := time.Now().UTC()
	out := BindingObservation{ObservedAt: now, FreshUntil: now.Add(2 * time.Minute), Interfaces: interfaces, Bindings: []Binding{}}
	bindings := map[string]Binding{}
	owners := map[string]string{}
	totalBytes, totalRecords := 0, 0
	for _, iface := range interfaces {
		for _, family := range []string{"-4", "-6"} {
			if err := ctx.Err(); err != nil {
				return BindingObservation{}, err
			}
			data, err := runner.Run(ctx, command, family, "neigh", "show", "dev", iface)
			if ctx.Err() != nil {
				return BindingObservation{}, ctx.Err()
			}
			totalBytes += len(data)
			if err != nil || totalBytes > bindingOutputLimit {
				return BindingObservation{}, ErrBindingObservation
			}
			rows, err := parseBindingNeighbors(data, iface, family == "-6")
			if err != nil {
				return BindingObservation{}, err
			}
			// Count failed/incomplete rows too: ignoring their binding must not
			// allow an unbounded kernel table to evade the attempt budget.
			totalRecords += bytes.Count(bytes.TrimSpace(data), []byte("\n"))
			if len(bytes.TrimSpace(data)) > 0 {
				totalRecords++
			}
			if totalRecords > 4096 {
				return BindingObservation{}, ErrBindingObservation
			}
			for _, row := range rows {
				ownerKey := iface + "\x00" + row.Addresses[0].Address
				if previous, ok := owners[ownerKey]; ok && previous != row.MAC {
					return BindingObservation{}, ErrBindingAmbiguous
				}
				owners[ownerKey] = row.MAC
				binding, exists := bindings[row.ID]
				if exists && binding.Interface != iface {
					return BindingObservation{}, ErrBindingAmbiguous
				}
				if !exists {
					binding = Binding{ID: row.ID, MAC: row.MAC, Interface: iface}
				}
				for _, address := range row.Addresses {
					if slices.ContainsFunc(binding.Addresses, func(previous BindingAddress) bool { return previous.Address == address.Address }) {
						return BindingObservation{}, ErrBindingAmbiguous
					}
					binding.Addresses = append(binding.Addresses, address)
				}
				if len(binding.Addresses) > 64 {
					return BindingObservation{}, ErrBindingObservation
				}
				bindings[row.ID] = binding
				if len(bindings) > maxDevices {
					return BindingObservation{}, ErrBindingObservation
				}
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return BindingObservation{}, err
	}
	for _, binding := range bindings {
		sort.Slice(binding.Addresses, func(i, j int) bool { return binding.Addresses[i].Address < binding.Addresses[j].Address })
		out.Bindings = append(out.Bindings, binding)
	}
	sort.Slice(out.Bindings, func(i, j int) bool { return out.Bindings[i].ID < out.Bindings[j].ID })
	return out, nil
}

func parseBindingNeighbors(data []byte, iface string, v6 bool) ([]Binding, error) {
	if len(data) > bindingOutputLimit || bytes.IndexByte(data, 0) >= 0 {
		return nil, ErrBindingObservation
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) > 4096 {
		return nil, ErrBindingObservation
	}
	out := []Binding{}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) > 16 {
			return nil, ErrBindingObservation
		}
		address, err := netip.ParseAddr(fields[0])
		if err != nil || address.Is4In6() || address.Zone() != "" || address.Is6() != v6 || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() {
			return nil, ErrBindingObservation
		}
		mac, state := "", ""
		deviceSeen, macSeen := false, false
		for i := 1; i < len(fields); i++ {
			switch fields[i] {
			case "dev":
				if deviceSeen || i+1 == len(fields) || fields[i+1] != iface {
					return nil, ErrBindingObservation
				}
				deviceSeen = true
				i++
			case "lladdr":
				if macSeen || i+1 == len(fields) {
					return nil, ErrBindingObservation
				}
				macSeen = true
				i++
				mac = fields[i]
			case "router", "managed", "extern_learn", "extern_valid", "use":
				// Known iproute2 flags do not supply address ownership or reachability.
			case "REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT", "NOARP", "FAILED", "INCOMPLETE":
				if state != "" {
					return nil, ErrBindingObservation
				}
				state = strings.ToLower(fields[i])
			default:
				return nil, ErrBindingObservation
			}
		}
		if state == "failed" || state == "incomplete" {
			continue
		}
		parsed, err := net.ParseMAC(mac)
		if state == "" || err != nil || len(parsed) != 6 || parsed[0]&1 != 0 || parsed.String() == "00:00:00:00:00:00" {
			return nil, ErrBindingObservation
		}
		mac = parsed.String()
		out = append(out, Binding{ID: deviceID(mac, ""), MAC: mac, Interface: iface, Addresses: []BindingAddress{{Address: address.String(), State: state}}})
	}
	return out, nil
}

// Bound stdout and stderr before buffering. A noisy/broken utility must not
// consume the router's RAM even when its context timeout has not fired yet.
type boundedCommandOutput struct {
	buffer   bytes.Buffer // Do not embed: Buffer.ReadFrom would bypass Write's limit.
	exceeded bool
}

func (b *boundedCommandOutput) Len() int { return b.buffer.Len() }

func (b *boundedCommandOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > bindingOutputLimit {
		b.exceeded = true
		return 0, ErrBindingObservation
	}
	return b.buffer.Write(p)
}
func runBoundedDeviceCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	var output boundedCommandOutput
	command := exec.CommandContext(ctx, name, args...)
	command.Stdout, command.Stderr = &output, &output
	command.WaitDelay = time.Second
	err := command.Run()
	if output.exceeded {
		return nil, ErrBindingObservation
	}
	return output.buffer.Bytes(), err
}
