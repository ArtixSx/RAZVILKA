package engineconfig

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

var ErrNFQWSModeChanged = errors.New("NFQWS2 mode review changed")
var ErrNFQWSModeUnsupported = errors.New("NFQWS2 mode is unavailable in this configuration")

type NFQWSModeView struct {
	Source         string `json:"source"`
	Mode           string `json:"mode"`
	Review         string `json:"review"`
	Available      bool   `json:"available"`
	CanList        bool   `json:"can_list"`
	CanAuto        bool   `json:"can_auto"`
	NativeAdaptive bool   `json:"native_adaptive"`
	DraftOnly      bool   `json:"draft_only"`
	// DiscordVoice: a UDP profile detects Discord and its voice ports are queued.
	DiscordVoice bool `json:"discord_voice"`
	// PolicyName/PolicyExclude: the Keenetic access policy of the (draft)
	// configuration. With PolicyExclude, devices in that policy bypass NFQWS2;
	// otherwise only they are processed, if the policy exists.
	PolicyName    string `json:"policy_name"`
	PolicyExclude bool   `json:"policy_exclude"`
	// PolicyRuntime: what the running service resolved at its last start.
	PolicyRuntime *NFQWSPolicyRuntime `json:"policy_runtime,omitempty"`
}

// NFQWSPolicyRuntime is read from nfqws2.conf.run, which the package's init
// writes at start: an empty mark means no Keenetic policy by that name was
// found, so every device is processed.
type NFQWSPolicyRuntime struct {
	Name    string `json:"name"`
	Exclude bool   `json:"exclude"`
	Found   bool   `json:"found"`
}

func nfqwsPolicyRuntime(path string) *NFQWSPolicyRuntime {
	data, err := os.ReadFile(path + ".run")
	if err != nil || len(data) > maxConfigBytes {
		return nil
	}
	fields, err := parseShellAssignments(string(data))
	if err != nil {
		return nil
	}
	if _, ok := fields["POLICY_NAME"]; !ok {
		return nil
	}
	return &NFQWSPolicyRuntime{Name: fields["POLICY_NAME"], Exclude: strings.TrimSpace(fields["POLICY_EXCLUDE"]) != "" && strings.TrimSpace(fields["POLICY_EXCLUDE"]) != "0", Found: strings.TrimSpace(fields["POLICY_MARK"]) != ""}
}

func nfqwsModeView(raw []byte, source string) (NFQWSModeView, error) {
	v := NFQWSModeView{Source: source, Mode: "custom", DraftOnly: true}
	if source == "missing" {
		v.Mode = "unavailable"
		return v, nil
	}
	fields, err := parseShellAssignments(string(raw))
	if err != nil {
		return v, ErrNFQWSModeUnsupported
	}
	v.Available = true
	v.CanList = strings.TrimSpace(fields["MODE_LIST"]) != ""
	v.CanAuto = v.CanList && strings.TrimSpace(fields["MODE_AUTO"]) != ""
	switch fields["NFQWS_EXTRA_ARGS"] {
	case "$MODE_LIST", "${MODE_LIST}":
		v.Mode = "user-list"
	case "$MODE_AUTO", "${MODE_AUTO}":
		v.Mode = "auto"
	case "$MODE_ALL", "${MODE_ALL}":
		v.Mode = "all"
	}
	v.Review = sum(append([]byte(source+"\x00"), raw...))
	args := fields["NFQWS_ARGS"] + "\n" + fields["NFQWS_ARGS_UDP"]
	v.NativeAdaptive = strings.Contains(args, "--lua-desync=circular:") || strings.Contains(args, "--lua-desync=autocircular:")
	v.DiscordVoice = discordVoiceCovered(fields)
	v.PolicyName = fields["POLICY_NAME"]
	v.PolicyExclude = strings.TrimSpace(fields["POLICY_EXCLUDE"]) != "" && strings.TrimSpace(fields["POLICY_EXCLUDE"]) != "0"
	return v, nil
}
func (m *Manager) NFQWSMode() (NFQWSModeView, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	raw, source, err := m.rawLocked("nfqws2", "main")
	if errors.Is(err, os.ErrNotExist) {
		return nfqwsModeView(nil, "missing")
	}
	if err != nil {
		return NFQWSModeView{}, err
	}
	v, err := nfqwsModeView(raw, source)
	if err == nil {
		if _, file, lookupErr := lookup("nfqws2", "main"); lookupErr == nil {
			v.PolicyRuntime = nfqwsPolicyRuntime(choosePath(file.Paths))
		}
	}
	return v, err
}

// StageNFQWSMode changes one reviewed assignment in the private draft. All
// strategies, interface, ports, lists and exclusions remain byte-preserved.
// It neither runs shell nor changes the live service. Global Apply owns that.
func (m *Manager) StageNFQWSMode(ctx context.Context, mode, review string, allowDiscovery bool) (NFQWSModeView, error) {
	if (mode != "user-list" && mode != "auto") || (mode == "auto" && !allowDiscovery) {
		return NFQWSModeView{}, ErrNFQWSModeUnsupported
	}
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
	if mode == "auto" && !current.CanAuto || mode == "user-list" && !current.CanList {
		return NFQWSModeView{}, ErrNFQWSModeUnsupported
	}
	value := "$MODE_LIST"
	if mode == "auto" {
		value = "$MODE_AUTO"
	}
	updated, err := encodeGuided("shell", raw, guidedFields("nfqws2", "main"), map[string]string{"NFQWS_EXTRA_ARGS": value})
	if err != nil {
		return NFQWSModeView{}, err
	}
	if len(updated) > maxConfigBytes {
		return NFQWSModeView{}, ErrNFQWSModeUnsupported
	}
	if err := target.CompareAndSwap(ctx, before, restorejournal.Image{Exists: true, Data: updated}); err != nil {
		return NFQWSModeView{}, err
	}
	return nfqwsModeView(updated, "staged")
}
