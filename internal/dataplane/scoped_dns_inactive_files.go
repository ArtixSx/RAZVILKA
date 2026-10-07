package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

type scopedDNSInactiveImage struct {
	info os.FileInfo
	raw  []byte
}

// Current dnscontrol document only. Decoding never creates a Manager, repairs a
// selection, migrates a schema, or treats a saved probe as runtime evidence.
type scopedDNSInactiveSettings struct {
	Schema            int                      `json:"schema"`
	Draft             dnscontrol.Selection     `json:"draft"`
	Applied           dnscontrol.Selection     `json:"applied"`
	LastProbe         []dnscontrol.ProbeResult `json:"last_probe,omitempty"`
	ProbedAt          string                   `json:"probed_at,omitempty"`
	ProbeProfileID    string                   `json:"probe_profile_id,omitempty"`
	NextDNSProfileID  string                   `json:"nextdns_profile_id,omitempty"`
	CustomProvider    *dnscontrol.Provider     `json:"custom_provider,omitempty"`
	ServiceDrafts     map[string]string        `json:"service_drafts,omitempty"`
	ServiceApplied    map[string]string        `json:"service_applied,omitempty"`
	ServiceRevisions  map[string]uint64        `json:"service_revisions,omitempty"`
	MigrationWarnings []string                 `json:"migration_warnings,omitempty"`
}

func scopedDNSInactiveFiles(ctx context.Context, root, settings string) (map[string]scopedDNSInactiveImage, map[uint16]bool, error) {
	images := make(map[string]scopedDNSInactiveImage)
	ports := make(map[uint16]bool)
	read := func(path string, value any, required bool) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		image, err := scopedDNSInactiveRead(path)
		if err != nil {
			return false, err
		}
		images[path] = image
		parent, e := os.Lstat(filepath.Dir(path))
		if e != nil || !scopedDNSInactiveProtected(parent, true) {
			return false, ErrScopedDNSRuntimeInactive
		}
		images[filepath.Dir(path)] = scopedDNSInactiveImage{info: parent}
		if image.info == nil {
			if required {
				return false, ErrScopedDNSRuntimeInactive
			}
			return false, nil
		}
		if err := scopedDNSInactiveDecode(image.raw, value); err != nil {
			return false, err
		}
		return true, nil
	}
	var doc scopedDNSInactiveSettings
	if _, err := read(settings, &doc, true); err != nil || !doc.valid() {
		return nil, nil, errors.Join(ErrScopedDNSRuntimeInactive, err)
	}
	if err := scopedDNSInactivePendingDirectory(filepath.Dir(settings), ".dns-", false, images); err != nil {
		return nil, nil, err
	}
	// Only an empty, protected runtime directory is a settled absence. Owner,
	// temporary files, foreign entries and symlinks all hold, without deletion.
	info, err := os.Lstat(root)
	if err == nil {
		if !scopedDNSInactiveProtected(info, true) {
			return nil, nil, ErrScopedDNSRuntimeInactive
		}
		images[root] = scopedDNSInactiveImage{info: info}
		f, err := os.OpenRoot(root)
		if err != nil {
			return nil, nil, err
		}
		dir, err := f.Open(".")
		if err != nil {
			_ = f.Close()
			return nil, nil, err
		}
		entries, e := dir.ReadDir(1)
		_ = dir.Close()
		anchored, statErr := f.Stat(".")
		_ = f.Close()
		if e != nil && !errors.Is(e, io.EOF) || len(entries) != 0 || statErr != nil || !os.SameFile(info, anchored) {
			return nil, nil, ErrScopedDNSRuntimeInactive
		}
	} else if errors.Is(err, os.ErrNotExist) {
		// Check the parent even for first use; a missing child under a substituted
		// or writable parent is not a protected absence.
		parent, e := os.Lstat(filepath.Dir(root))
		if e != nil || !scopedDNSInactiveProtected(parent, true) {
			return nil, nil, ErrScopedDNSRuntimeInactive
		}
		images[root] = scopedDNSInactiveImage{}
	} else {
		return nil, nil, err
	}
	stateRoot := filepath.Dir(root)
	var latest, committed Plan
	lp, err := read(filepath.Join(stateRoot, "latest-plan.json"), &latest, false)
	if err != nil {
		return nil, nil, err
	}
	cp, err := read(filepath.Join(stateRoot, "latest-committed-plan.json"), &committed, false)
	if err != nil {
		return nil, nil, err
	}
	for _, p := range []struct {
		found bool
		plan  Plan
	}{{lp, latest}, {cp, committed}} {
		if p.found && (p.plan.SchemaVersion != SchemaVersion || !validPlanID(p.plan.PlanID) || !validPlanDigest(p.plan.Digest) ||
			p.plan.State != "committed" && p.plan.State != "rolled-back" && p.plan.State != "blocked" && p.plan.State != "canary-failed" && p.plan.State != "network-stale") {
			return nil, nil, ErrScopedDNSRuntimeInactive
		}
	}
	if cp && committed.State != "committed" || !cp && lp && latest.State == "committed" {
		return nil, nil, ErrScopedDNSRuntimeInactive
	} // No legacy promotion.
	var execution Execution
	ep, err := read(filepath.Join(stateRoot, "latest-execution.json"), &execution, false)
	if err != nil {
		return nil, nil, err
	}
	if err := scopedDNSInactivePendingDirectory(stateRoot, ".transaction-", false, images); err != nil {
		return nil, nil, err
	}
	if err := scopedDNSInactivePendingDirectory(filepath.Join(stateRoot, "transactions"), "", !ep, images); err != nil {
		return nil, nil, err
	}
	if lp || cp || ep {
		// Use the execution owner's terminal resource validator on strict paired
		// bounded images, without reopening its permissive legacy file reader.
		if !ep || !validExecutionPlanID(execution.PlanID) {
			return nil, nil, ErrScopedDNSRuntimeInactive
		}
		var paired Execution
		if _, err := read(filepath.Join(stateRoot, "transactions", execution.PlanID, "execution.json"), &paired, true); err != nil || !reflect.DeepEqual(execution, paired) {
			return nil, nil, errors.Join(ErrScopedDNSRuntimeInactive, err)
		}
		if err := scopedDNSInactiveExecution(execution); err != nil {
			return nil, nil, err
		}
		if lp && (latest.PlanID != execution.PlanID || latest.Digest != execution.Digest || latest.State != execution.State) {
			return nil, nil, ErrScopedDNSRuntimeInactive
		}
	}
	var scope *ScopedDNSPlan
	if cp {
		scope = committed.DNS
		retiring := slices.Contains(committed.RetiringAdapters, scopedDNSAdapterID)
		if (scope != nil) != slices.Contains(committed.Adapters, scopedDNSAdapterID) ||
			scope != nil && (committed.SuspendDNS || validateScopedDNSPlan(scope, committed.Routes) != nil) {
			return nil, nil, ErrScopedDNSRuntimeInactive
		}
		if scope != nil || retiring {
			var saved scopedDNSSnapshot
			path := filepath.Join(stateRoot, "transactions", committed.PlanID, scopedDNSAdapterID, "snapshot.json")
			if _, err := read(path, &saved, true); err != nil || !validScopedDNSSnapshotState(saved) || validateScopedSettingsSnapshot(saved, committed.DNS, committed.SuspendDNS) != nil {
				return nil, nil, errors.Join(ErrScopedDNSRuntimeInactive, err)
			}
			if previous := saved.settingsScope(); previous != nil {
				endpoint, _ := netip.ParseAddrPort(previous.DNS.Listener)
				ports[endpoint.Port()] = true
			}
			if committed.SuspendDNS {
				if !retiring || saved.settingsScope() == nil || committed.DNS != nil || len(committed.Routes) != 0 {
					return nil, nil, ErrScopedDNSRuntimeInactive
				}
				scope = saved.settingsScope().DNS
			}
		}
		if committed.SuspendDNS && !retiring || committed.DiscardDNS && (!retiring || committed.SuspendDNS || committed.DNS != nil || len(committed.Routes) != 0) {
			return nil, nil, ErrScopedDNSRuntimeInactive
		}
	}
	if scope != nil {
		endpoint, err := netip.ParseAddrPort(scope.Listener)
		if err != nil {
			return nil, nil, err
		}
		ports[endpoint.Port()] = true
		first := scope.Bindings[0]
		if len(doc.ServiceApplied) != 1 || doc.ServiceApplied[first.ServiceID] != first.ProfileID {
			return nil, nil, ErrScopedDNSRuntimeInactive
		}
	} else if len(doc.ServiceApplied) != 0 {
		return nil, nil, ErrScopedDNSRuntimeInactive
	}
	// A failed candidate may have bound its own port before rollback. Its saved
	// coordinates join the negative socket inventory even when not committed.
	if lp && latest.DNS != nil {
		if validateScopedDNSPlan(latest.DNS, latest.Routes) != nil {
			return nil, nil, ErrScopedDNSRuntimeInactive
		}
		endpoint, _ := netip.ParseAddrPort(latest.DNS.Listener)
		ports[endpoint.Port()] = true
	}
	return images, ports, ctx.Err()
}

func scopedDNSInactivePendingDirectory(path, prefix string, empty bool, images map[string]scopedDNSInactiveImage) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		images[path] = scopedDNSInactiveImage{}
		return nil
	}
	if err != nil || !scopedDNSInactiveProtected(info, true) {
		return ErrScopedDNSRuntimeInactive
	}
	r, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	defer r.Close()
	f, err := r.Open(".")
	if err != nil {
		return err
	}
	entries, err := f.ReadDir(1025)
	_ = f.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 1024 || empty && len(entries) > 0 {
		return ErrScopedDNSRuntimeInactive
	}
	for _, entry := range entries {
		if prefix != "" && strings.HasPrefix(entry.Name(), prefix) {
			return ErrScopedDNSRuntimeInactive
		}
	}
	after, err := r.Stat(".")
	if err != nil || !os.SameFile(info, after) || !info.ModTime().Equal(after.ModTime()) {
		return ErrScopedDNSRuntimeInactive
	}
	images[path] = scopedDNSInactiveImage{info: info}
	return nil
}

func scopedDNSInactiveRead(path string) (scopedDNSInactiveImage, error) {
	// The explicit startup path must not cross an ancestor symlink. Root keeps
	// descendant resolution anchored after these checks.
	for current := filepath.Dir(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return scopedDNSInactiveImage{}, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return scopedDNSInactiveImage{}, ErrScopedDNSRuntimeInactive
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !scopedDNSInactiveProtected(parent, true) {
		return scopedDNSInactiveImage{}, ErrScopedDNSRuntimeInactive
	}
	r, err := ownedfs.Open(filepath.Dir(path))
	if err != nil {
		return scopedDNSInactiveImage{}, err
	}
	defer r.Close()
	info, err := r.Stat(filepath.Base(path))
	if errors.Is(err, os.ErrNotExist) {
		return scopedDNSInactiveImage{}, nil
	}
	if err != nil || !scopedDNSInactiveProtected(info, false) || info.Size() > 128<<10 {
		return scopedDNSInactiveImage{}, ErrScopedDNSRuntimeInactive
	}
	raw, err := r.ReadLimited(filepath.Base(path), 128<<10)
	if err != nil {
		return scopedDNSInactiveImage{}, err
	}
	after, err := r.Stat(filepath.Base(path))
	if err != nil || !os.SameFile(info, after) || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
		return scopedDNSInactiveImage{}, ErrScopedDNSRuntimeInactive
	}
	return scopedDNSInactiveImage{info, raw}, nil
}

func scopedDNSInactiveSameFiles(a, b map[string]scopedDNSInactiveImage) bool {
	if len(a) != len(b) {
		return false
	}
	for path, x := range a {
		y, ok := b[path]
		if !ok || (x.info == nil) != (y.info == nil) || !bytes.Equal(x.raw, y.raw) {
			return false
		}
		if x.info != nil && (!os.SameFile(x.info, y.info) || x.info.Mode() != y.info.Mode() || x.info.Size() != y.info.Size() || !x.info.ModTime().Equal(y.info.ModTime())) {
			return false
		}
	}
	return true
}

func (d scopedDNSInactiveSettings) valid() bool {
	profiles := make(map[string]bool)
	for _, p := range dnscontrol.Profiles() {
		profiles[p.ID] = true
	}
	if d.Schema != 5 || !profiles[d.Draft.ProfileID] || d.Applied.ProfileID != "automatic" ||
		len(d.ServiceDrafts) > 64 || len(d.ServiceApplied) > 64 || len(d.ServiceRevisions) > 64 || len(d.LastProbe) > 64 ||
		d.ProbeProfileID != "" && !profiles[d.ProbeProfileID] {
		return false
	}
	if d.ProbedAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, d.ProbedAt); err != nil {
			return false
		}
	}
	for _, bindings := range []map[string]string{d.ServiceDrafts, d.ServiceApplied} {
		for id, profile := range bindings {
			if !scopedDNSInactiveServiceID(id) || !profiles[profile] {
				return false
			}
		}
	}
	for id := range d.ServiceRevisions {
		if !scopedDNSInactiveServiceID(id) {
			return false
		}
	}
	if d.NextDNSProfileID != "" && (len(d.NextDNSProfileID) != 6 || strings.Trim(d.NextDNSProfileID, "0123456789abcdef") != "") {
		return false
	}
	if d.CustomProvider != nil && (d.CustomProvider.ID != "custom" || !d.CustomProvider.Configured || d.CustomProvider.Name == "" ||
		len(d.CustomProvider.Servers) == 0 && d.CustomProvider.DoH == "" && d.CustomProvider.DoT == "") {
		return false
	}
	return true
}

// Validate the already bounded, strict paired images. Re-reading through the
// legacy unbounded journal decoder would reopen a path substitution window.
func scopedDNSInactiveExecution(e Execution) error {
	if !validPlanID(e.PlanID) || !validPlanDigest(e.Digest) || e.StartedAt == "" || e.FinishedAt == "" || len(e.Steps) > 1024 {
		return ErrScopedDNSRuntimeInactive
	}
	switch e.State {
	case "committed", "rolled-back", "canary-failed", "network-stale", "temporary-complete":
	default:
		return ErrScopedDNSRuntimeInactive
	}
	if _, err := time.Parse(time.RFC3339Nano, e.StartedAt); err != nil {
		return err
	}
	if _, err := time.Parse(time.RFC3339Nano, e.FinishedAt); err != nil {
		return err
	}
	for _, step := range e.Steps {
		if step.State != "passed" && step.State != "failed" || step.FinishedAt == "" || e.State == "committed" && step.State != "passed" {
			return ErrScopedDNSRuntimeInactive
		}
		if _, err := time.Parse(time.RFC3339Nano, step.FinishedAt); err != nil {
			return err
		}
	}
	return validateExecutionResources(e, true)
}

func scopedDNSInactiveServiceID(id string) bool {
	return len(id) > 0 && len(id) <= 64 && id[0] != '-' && strings.Trim(id, "abcdefghijklmnopqrstuvwxyz0123456789-") == ""
}

// Round-trip wire equality rejects missing fields, case aliases and explicit
// null/empty optional fields not emitted by the current writer. The token pass
// rejects duplicates at every depth before encoding/json can discard them.
func scopedDNSInactiveDecode(raw []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	count := 0
	walk = func(depth int) error {
		count++
		if depth > 64 || count > 65536 {
			return ErrScopedDNSRuntimeInactive
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		if delim != '{' && delim != '[' {
			return ErrScopedDNSRuntimeInactive
		}
		keys := map[string]bool{}
		for d.More() {
			if delim == '{' {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok || keys[name] {
					return ErrScopedDNSRuntimeInactive
				}
				keys[name] = true
			}
			if err := walk(depth + 1); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrScopedDNSRuntimeInactive
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	canonical := func(b []byte) []byte {
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.UseNumber()
		var v any
		if decoder.Decode(&v) != nil {
			return nil
		}
		out, _ := json.Marshal(v)
		return out
	}
	if !bytes.Equal(canonical(raw), canonical(encoded)) {
		return ErrScopedDNSRuntimeInactive
	}
	return nil
}
