package engineconfig

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// DiscordRepairProfile is RAZVILKA's "Discord repair" for NFQWS2: Discord
// voice/STUN UDP on its media ports. It uses the same desync family as the
// stock nfqws2-keenetic 1.3 UDP profile (circular over two fakes, first
// packets only), restricted to the Discord and STUN protocol detectors, and
// relies only on the stock Lua modules and quic_initial blob.
const DiscordRepairProfile = "--filter-udp=1400,3478-3481,5349,19294-19344,50000-50099 --filter-l7=discord,stun --out-range=<n2 --payload=stun,discord_ip_discovery --lua-desync=circular:fails=2:time=300:retrans=3:nld=2 --lua-desync=fake:repeats=6:strategy=1 --lua-desync=fake:blob=quic_initial:repeats=6:strategy=2"

// The firewall must queue these UDP ports, or no profile ever sees the flow.
var discordVoicePorts = [][2]int{{1400, 1400}, {3478, 3481}, {5349, 5349}, {19294, 19344}, {50000, 50099}}

// iptables multiport accepts at most 15 port slots; a range takes two.
const maxMultiportSlots = 15

var ErrDiscordRepairPorts = errors.New("NFQWS2 UDP port list has no room for Discord voice ports")

type portRange [2]int

func parsePortList(value string) ([]portRange, error) {
	out := []portRange{}
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		low, high, isRange := strings.Cut(item, ":")
		first, err := strconv.Atoi(low)
		if err != nil || first < 1 || first > 65535 {
			return nil, ErrNFQWSModeUnsupported
		}
		last := first
		if isRange {
			if last, err = strconv.Atoi(high); err != nil || last < first || last > 65535 {
				return nil, ErrNFQWSModeUnsupported
			}
		}
		out = append(out, portRange{first, last})
	}
	return out, nil
}

func portsCovered(list []portRange, want [2]int) bool {
	for port := want[0]; port <= want[1]; port++ {
		covered := false
		for _, r := range list {
			if port >= r[0] && port <= r[1] {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

func multiportSlots(list []portRange) int {
	slots := 0
	for _, r := range list {
		slots++
		if r[1] != r[0] {
			slots++
		}
	}
	return slots
}

// Arguments that name the discord protocol detector in a UDP profile.
func argumentsDetectDiscord(args string) bool {
	for _, token := range strings.Fields(args) {
		if value, ok := strings.CutPrefix(token, "--filter-l7="); ok {
			for _, protocol := range strings.Split(value, ",") {
				if protocol == "discord" {
					return true
				}
			}
		}
	}
	return false
}

// discordVoiceCovered reports whether a UDP profile detects Discord and the
// firewall queues every Discord voice port.
func discordVoiceCovered(fields map[string]string) bool {
	if !argumentsDetectDiscord(fields["NFQWS_ARGS_UDP"]) && !argumentsDetectDiscord(fields["NFQWS_ARGS_CUSTOM"]) {
		return false
	}
	ports, err := parsePortList(fields["UDP_PORTS"])
	if err != nil {
		return false
	}
	for _, want := range discordVoicePorts {
		if !portsCovered(ports, want) {
			return false
		}
	}
	return true
}

// discordRepairValues returns the assignments that add the repair profile to
// the additional strategies and queue the missing voice ports, keeping every
// existing strategy and port.
func discordRepairValues(fields map[string]string) (map[string]string, error) {
	ports, err := parsePortList(fields["UDP_PORTS"])
	if err != nil {
		return nil, err
	}
	merged := strings.TrimSpace(fields["UDP_PORTS"])
	for _, want := range discordVoicePorts {
		if portsCovered(ports, want) {
			continue
		}
		item := strconv.Itoa(want[0])
		if want[1] != want[0] {
			item += ":" + strconv.Itoa(want[1])
		}
		if merged != "" {
			merged += ","
		}
		merged += item
		ports = append(ports, portRange(want))
	}
	if multiportSlots(ports) > maxMultiportSlots {
		return nil, ErrDiscordRepairPorts
	}
	values := map[string]string{"UDP_PORTS": merged}
	if !argumentsDetectDiscord(fields["NFQWS_ARGS_UDP"]) && !argumentsDetectDiscord(fields["NFQWS_ARGS_CUSTOM"]) {
		custom := strings.TrimSpace(fields["NFQWS_ARGS_CUSTOM"])
		if custom != "" {
			custom += " --new "
		}
		values["NFQWS_ARGS_CUSTOM"] = custom + DiscordRepairProfile
	}
	return values, nil
}

// StageNFQWSDiscordRepair adds the Discord repair to the private NFQWS2 draft
// when the reviewed configuration does not cover Discord voice yet. It never
// replaces an existing strategy and never touches the live service; the
// ordinary reviewed Apply validates and activates it.
func (m *Manager) StageNFQWSDiscordRepair(ctx context.Context, review string) (NFQWSModeView, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	target, err := OpenRestoreTarget(m.StageRoot, "nfqws2", "main")
	if err != nil {
		return NFQWSModeView{}, err
	}
	defer target.Close()
	before, err := target.Read(ctx)
	if err != nil {
		return NFQWSModeView{}, err
	}
	raw, source, err := m.rawLocked("nfqws2", "main")
	if err != nil {
		return NFQWSModeView{}, ErrNFQWSModeUnsupported
	}
	current, err := nfqwsModeView(raw, source)
	if err != nil {
		return NFQWSModeView{}, err
	}
	if review == "" || review != current.Review {
		return NFQWSModeView{}, ErrNFQWSModeChanged
	}
	if current.DiscordVoice {
		return current, nil
	}
	fields, err := parseShellAssignments(string(raw))
	if err != nil {
		return NFQWSModeView{}, ErrNFQWSModeUnsupported
	}
	values, err := discordRepairValues(fields)
	if err != nil {
		return NFQWSModeView{}, err
	}
	updated, err := encodeGuided("shell", raw, guidedFields("nfqws2", "main"), values)
	if err != nil || len(updated) > maxConfigBytes {
		return NFQWSModeView{}, ErrNFQWSModeUnsupported
	}
	if validation := ValidateContent("nfqws2", "main", string(updated)); !validation.OK {
		return NFQWSModeView{}, ErrNFQWSModeUnsupported
	}
	if err := target.CompareAndSwap(ctx, before, restorejournal.Image{Exists: true, Data: updated}); err != nil {
		return NFQWSModeView{}, err
	}
	return nfqwsModeView(updated, "staged")
}
