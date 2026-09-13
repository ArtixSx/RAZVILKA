package dataplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

var errWARPCleanupOwnership = errors.New("WARP cleanup ownership is incomplete or invalid; retained local state and interface require review")

func warpRuntimeDigest(data []byte) string {
	value := sha256.Sum256(data)
	return hex.EncodeToString(value[:])
}

// A runtime file alone is only intent: Activate writes it before link creation.
// A failed creation can therefore leave that file alongside a foreign link.
// Only a complete committed policy/runtime binding grants destructive cleanup.
func (a *WARPWireGuardAdapter) deactivationOwnership(ctx context.Context) (PolicyState, bool, error) {
	if err := ctx.Err(); err != nil {
		return PolicyState{}, false, err
	}
	policy, policyExists, err := readWARPCleanupFile(a.statePath(), 1<<20)
	if err != nil {
		return PolicyState{}, false, errWARPCleanupOwnership
	}
	runtime, runtimeExists, err := readWARPCleanupFile(a.RuntimeConfigPath, 256<<10)
	if err != nil {
		return PolicyState{}, false, errWARPCleanupOwnership
	}
	if !policyExists && !runtimeExists {
		return PolicyState{}, false, nil
	}
	if !policyExists || !runtimeExists {
		return PolicyState{}, false, errWARPCleanupOwnership
	}
	var state PolicyState
	decoder := json.NewDecoder(bytes.NewReader(policy))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || decoder.Decode(&struct{}{}) != io.EOF || state.Interface != a.interfaceName() || state.Table != a.table() || state.PriorityBase != a.priorityBase() || len(state.Prefixes) == 0 || len(state.Prefixes) > maxPolicyPrefixes || len(effectivePolicyRules(state)) > maxPolicyPrefixes || len(state.Exclusions) != 0 || state.Forwarding != nil || state.RuntimeConfigSHA256 != warpRuntimeDigest(runtime) {
		return state, false, errWARPCleanupOwnership
	}
	// wg-quick derives the interface from the filename. Keep it consistent with
	// the exact policy identity and reject hooks, automatic routes or DNS changes.
	if err := validPolicyLayout(state); err != nil {
		return state, false, errWARPCleanupOwnership
	}
	sanitized, err := sanitizeWGQuickProfile(string(runtime))
	if err != nil || sanitized != string(runtime) || filepath.Base(a.RuntimeConfigPath) != a.interfaceName()+".conf" {
		return state, false, errWARPCleanupOwnership
	}
	prefixes := map[string]bool{}
	for _, value := range state.Prefixes {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return state, false, errWARPCleanupOwnership
		}
		prefixes[prefix.Masked().String()] = true
	}
	for _, rule := range effectivePolicyRules(state) {
		destination, err := netip.ParsePrefix(rule.Destination)
		if err != nil || !prefixes[destination.Masked().String()] {
			return state, false, errWARPCleanupOwnership
		}
		if rule.Source != "" {
			source, err := netip.ParsePrefix(rule.Source)
			if err != nil || source.Addr().Is4() != destination.Addr().Is4() {
				return state, false, errWARPCleanupOwnership
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return state, false, err
	}
	return state, true, nil
}

func readWARPCleanupFile(path string, limit int64) ([]byte, bool, error) {
	if path == "" {
		return nil, false, errWARPCleanupOwnership
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > limit {
		return nil, false, errWARPCleanupOwnership
	}
	root, err := ownedfs.Open(filepath.Dir(path))
	if err != nil {
		return nil, false, err
	}
	defer root.Close()
	data, err := root.ReadLimited(filepath.Base(path), limit)
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func (a *WARPWireGuardAdapter) deactivationInterfaceActive(ctx context.Context) (bool, error) {
	if a.ip() == "" {
		return false, errWARPCleanupOwnership
	}
	output, err := a.run(ctx, a.ip(), "link", "show", "dev", a.interfaceName())
	if err == nil {
		return true, nil
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	message := strings.ToLower(string(output) + " " + err.Error())
	if strings.Contains(message, "device") && (strings.Contains(message, "not found") || strings.Contains(message, "does not exist") || strings.Contains(message, "cannot find")) {
		return false, nil
	}
	return false, errors.New("WARP interface state could not be confirmed; ownership files were retained")
}
