//go:build linux && arm64

package physicalscope

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"golang.org/x/sys/unix"
)

// ROOT-only network readback. Local writes are limited to a new test-owned
// temporary control root. No installed control, Store, Stop or effect is used.
// RAZVILKA_PHYSICAL_SCOPE_IPV4_LAN_PACKET_NATIVE=1
// RAZVILKA_PHYSICAL_SCOPE_NATIVE=stock-nc1812
// RAZVILKA_PHYSICAL_SCOPE_IPV4_LAN_PACKET_INTENT_FILE=<absolute private JSON>
// JSON has exactly revision, policy_revision, mode, new_devices, segment_ids,
// excluded_device_ids, excluded_cidrs. ROOT supplies actual intent, including
// one explicit native Home ID; no observed identity/address/fact is accepted.
// Each operation retains 12s; overall supervision is 90s or t.Deadline sooner.
// An external ROOT runner timeout remains necessary for a stuck native syscall.
func TestPhysicalScopeNativeIPv4LANPacketLifecycle(t *testing.T) {
	if os.Getenv("RAZVILKA_PHYSICAL_SCOPE_IPV4_LAN_PACKET_NATIVE") != "1" {
		t.Skip("ROOT-only IPv4 LAN packet lifecycle opt-in")
	}
	if os.Getenv("RAZVILKA_PHYSICAL_SCOPE_NATIVE") != "stock-nc1812" || os.Geteuid() != 0 {
		t.Fatal("IPv4 LAN packet lifecycle requires actual stock NC1812 Linux ARM64/root")
	}
	base, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if deadline, ok := t.Deadline(); ok {
		limited, finish := context.WithDeadline(base, deadline)
		defer finish()
		base = limited
	}
	var scope *IPv4LANPacketScope
	var membership *IPv4LANMembershipReview
	var control *operationgate.ControlEpochReview
	var release func()
	var held context.Context
	tracker := &packetNativeOriginalHandle{}
	// Registered before any admission. Goexit from t.Fatal also executes this
	// finalizer, then t.TempDir removes ONLY this test's temporary local files.
	defer func() {
		joined := false
		if membership != nil {
			membership.Close()
		}
		if scope != nil {
			_, err := packetNativePhase(t, base, "close", func(ctx context.Context) error {
				return packetNativeSuperviseClose(ctx, scope.Close)
			})
			if err != nil {
				t.Error("IPv4 LAN packet original Close refused or unjoined")
			}
		}
		if tracker.handle != nil {
			_, err := packetNativePhase(t, base, "collector_join", func(ctx context.Context) error {
				return packetNativeWaitJoin(ctx, tracker.handle.original.reader.done)
			})
			if err != nil {
				t.Error("IPv4 LAN packet original collector was not joined")
			} else if tracker.handle.original.reader.failure != nil {
				packetNativeLog(t, packetNativeMetricFor("collector_terminal", 0, tracker.handle.original.reader.failure))
				t.Error("IPv4 LAN packet original collector had a terminal refusal")
			}
			select {
			case <-tracker.handle.original.reader.done:
				joined = true
			default:
			}
		} else {
			packetNativeLog(t, packetNativeMetric{Phase: "collector_join", Status: "not_opened"})
		}
		// These are unconditional, including constructor refusal/Close timeout.
		// Neither cleanup manufactures a forward operation or touches the router.
		if control != nil {
			start := time.Now()
			err := control.Close()
			elapsed := time.Since(start)
			if elapsed >= 12*time.Second {
				err = errors.Join(err, context.DeadlineExceeded)
			}
			packetNativeLog(t, packetNativeMetricFor("control_close", elapsed, err))
			if err != nil {
				t.Error("IPv4 LAN packet original control Close refused")
			}
		}
		if release != nil {
			release()
		}
		if tracker.opens > 1 {
			t.Error("IPv4 LAN packet original collector was reopened")
		}
		packetNativeLog(t, packetNativeMetric{Phase: "original_handles", Status: "observed", Opens: tracker.opens, CollectorPresent: tracker.handle != nil, CollectorJoined: &joined})
	}()

	path := os.Getenv("RAZVILKA_PHYSICAL_SCOPE_IPV4_LAN_PACKET_INTENT_FILE")
	var initial IPv4LANPacketIntent
	if _, err := packetNativePhase(t, base, "intent", func(ctx context.Context) error {
		var err error
		initial, err = packetNativeReadIntent(ctx, path)
		return err
	}); err != nil {
		t.Fatal("IPv4 LAN packet private intent refused")
	}

	var provider *netidentity.Provider
	if _, err := packetNativePhase(t, base, "provider", func(ctx context.Context) error {
		var err error
		provider, err = netidentity.NewReviewedStockNC1812Provider(ctx)
		return err
	}); err != nil {
		t.Fatal("IPv4 LAN packet actual stock provider refused")
	}
	root := filepath.Join(t.TempDir(), "control")
	gate := &operationgate.Gate{}
	if _, err := packetNativePhase(t, base, "control_setup", func(ctx context.Context) error {
		if _, err := operationgate.InitializeSelfUpdateControl(ctx, root); err != nil {
			return err
		}
		var err error
		// Keep the actual admitted lifetime on the overall context. The short
		// setup deadline must not become the later scope's expired Gate context.
		held, release, err = gate.ExclusiveContext(base)
		if err != nil {
			return err
		}
		deadline, _ := ctx.Deadline()
		reviewCtx, finish := context.WithDeadline(held, deadline)
		defer finish()
		control, err = gate.ReviewControlEpoch(reviewCtx, root)
		return err
	}); err != nil {
		t.Fatal("IPv4 LAN packet test-owned control setup refused")
	}
	if provider == nil || control == nil || !control.MatchesControlRoot(root) {
		t.Fatal("IPv4 LAN packet concrete original dependencies refused")
	}
	intentReads := 0
	read := func(ctx context.Context) (IPv4LANPacketIntent, error) {
		intentReads++
		return packetNativeReadIntent(ctx, path)
	}
	// Same reviewed factory and issuer as the public constructor, after its
	// concrete dependency/root checks above. ONLY open is wrapped: count and
	// retain the actually returned object, return object/error unmodified. This
	// exposes its join even when the constructor closes it and returns nil.
	source := tracker.retain(reviewedIPv4LANPacketSource(provider, control, root))
	if _, err := packetNativePhase(t, held, "constructor", func(ctx context.Context) error {
		var err error
		scope, err = newIPv4LANPacketScope(ctx, read, source)
		return err
	}); err != nil {
		for _, phase := range []string{"current", "membership", "retained", "close"} {
			packetNativeLog(t, packetNativeMetric{Phase: phase, Status: "skipped_dependency"})
		}
		t.Fatal("IPv4 LAN packet constructor refused; original collector join follows")
	}
	if scope == nil {
		t.Fatal("IPv4 LAN packet constructor returned no scope")
	}
	actual, ok := scope.fence.(*ipv4LANPacketKernelFence)
	if !ok || tracker.opens != 1 || actual != tracker.handle || actual.original == nil || actual.original.reader == nil {
		t.Fatal("IPv4 LAN packet original kernel handle binding refused")
	}
	original := scope.PacketFacts()
	if original.Identity.Kind != netidentity.ReviewedSingleInitNet || original.ScopeID == "" || original.Home.ID != initial.SegmentIDs[0] || !original.Home.Home || original.Home.Guest || len(original.IPv4Prefixes) == 0 || !reflect.DeepEqual(original.Intent, initial) || original.Control != control.Reference() {
		t.Fatal("IPv4 LAN packet original facts refused")
	}
	unchanged := func() bool { return reflect.DeepEqual(original, scope.PacketFacts()) }
	_, currentErr := packetNativePhase(t, held, "current", scope.Current)
	if currentErr != nil {
		t.Error("IPv4 LAN packet Current refused")
	}
	if currentErr == nil {
		if _, err := packetNativePhase(t, held, "membership", func(ctx context.Context) error {
			var err error
			membership, err = scope.ObserveMembership(ctx)
			return err
		}); err != nil {
			t.Error("IPv4 LAN packet membership refused; no replacement epoch attempted")
		} else if membership == nil || membership.Facts().ScopeID != original.ScopeID {
			t.Error("IPv4 LAN packet membership original-owner binding refused")
		}
	} else {
		packetNativeLog(t, packetNativeMetric{Phase: "membership", Status: "skipped_dependency"})
	}
	reads := intentReads
	if _, err := packetNativePhase(t, held, "retained", scope.RetainedCurrent); err != nil {
		t.Error("IPv4 LAN packet RetainedCurrent refused")
	}
	if intentReads != reads || !unchanged() || tracker.opens != 1 {
		t.Error("IPv4 LAN packet retained comparison reread intent or adopted another A")
	}
	packetNativeLog(t, packetNativeMetric{Phase: "original_comparison", Status: "observed", IntentReads: intentReads, OriginalUnchanged: unchanged(), RetainedIntentUnchanged: intentReads == reads})
}

type packetNativeOriginalHandle struct {
	opens  int
	handle *ipv4LANPacketKernelFence
}

func (h *packetNativeOriginalHandle) retain(source ipv4LANPacketSource) ipv4LANPacketSource {
	open := source.open
	source.open = func(ctx context.Context) (ipv4LANPacketFence, error) {
		h.opens++
		f, err := open(ctx)
		if actual, ok := f.(*ipv4LANPacketKernelFence); ok && h.handle == nil {
			h.handle = actual
		}
		return f, err
	}
	return source
}

type packetNativeMetric struct {
	Phase                   string   `json:"phase"`
	Status                  string   `json:"status"`
	ElapsedMS               int64    `json:"elapsed_ms"`
	DeadlineExceeded        bool     `json:"deadline_exceeded"`
	ErrorClass              string   `json:"error_class,omitempty"`
	Stages                  []string `json:"stages,omitempty"`
	UnclassifiedStage       bool     `json:"unclassified_stage,omitempty"`
	Opens                   int      `json:"opens,omitempty"`
	IntentReads             int      `json:"intent_reads,omitempty"`
	CollectorPresent        bool     `json:"collector_present,omitempty"`
	CollectorJoined         *bool    `json:"collector_joined,omitempty"`
	OriginalUnchanged       bool     `json:"original_unchanged,omitempty"`
	RetainedIntentUnchanged bool     `json:"retained_intent_unchanged,omitempty"`
}

func packetNativeMetricFor(phase string, elapsed time.Duration, err error) packetNativeMetric {
	m := packetNativeMetric{Phase: phase, Status: "ok", ElapsedMS: elapsed.Milliseconds(), DeadlineExceeded: errors.Is(err, context.DeadlineExceeded)}
	if err == nil {
		return m
	}
	m.Status = "refused"
	switch {
	case m.DeadlineExceeded:
		m.ErrorClass = "context_deadline"
	case errors.Is(err, context.Canceled):
		m.ErrorClass = "context_cancelled"
	case errors.Is(err, operationgate.ErrSelfUpdateStopped):
		m.ErrorClass = "control_stopped"
	case errors.Is(err, operationgate.ErrSelfUpdateStopChanged):
		m.ErrorClass = "control_changed"
	case errors.Is(err, operationgate.ErrSelfUpdateStopJournal):
		m.ErrorClass = "control_journal"
	case errors.Is(err, operationgate.ErrBusy):
		m.ErrorClass = "gate_busy"
	case errors.Is(err, ErrUnknown):
		m.ErrorClass = "physical_scope_refused"
	case errors.Is(err, netidentity.ErrUnknown):
		m.ErrorClass = "netidentity_refused"
	default:
		m.ErrorClass = "other_refused"
	}
	// Fixed semantic allowlist; neither Error() nor arbitrary stage text is
	// serialized. Unknown diagnostics remain explicitly unclassified.
	for _, stage := range DiagnosticStages(err) {
		switch stage {
		case "packet.capture", "packet.home", "packet.home.ipv4-missing", "packet.identity.changed", "packet.identity.kind", "packet.fence.open", "packet.structure.changed", "packet.structure.limit", "packet.control.changed", "packet.control.initial", "packet.control.closing", "packet.intent.initial", "packet.intent.changed", "packet.intent.purpose", "packet.intent.segment", "packet.intent.exclusion-unmappable", "packet.intent.excluded-prefix", "packet.owned.address", "packet.owned.address.duplicate", "packet.owned.neighbor.conflict", "packet.foreign.prefix.overlap", "packet.neighbor.mac", "packet.unavailable", "packet.membership.capture.changed", "packet.membership.epoch.changed", "packet.membership.foreign", "packet.membership.address-conflict", "packet.membership.limit", "fence.notifications", "fence.check.descriptor", "fence.check.closed", "fence.drain.context", "fence.drain.closing-descriptor", "fence.datagram.decode", "kernel.bindings.neighbor.router-state", "kernel.bindings.neighbor.family-missing", "kernel.bindings.neighbor.dump-family", "kernel.bindings.neighbor.duplicate", "kernel.bindings.neighbor.limit", "native.packet.intent.path", "native.packet.intent.file", "native.packet.intent.limit", "native.packet.intent.schema", "native.packet.join.timeout":
			m.Stages = append(m.Stages, stage)
		// Finite first-capture labels absent from the old metric allowlist.
		// 470's filtered log cannot identify its actual refusal label.
		case "kernel.bindings.neighbor.header", "kernel.bindings.neighbor.family", "kernel.bindings.neighbor.attributes", "kernel.bindings.neighbor.index", "kernel.bindings.neighbor.address", "kernel.bindings.neighbor.state", "kernel.bindings.neighbor.flags", "kernel.bindings.neighbor.router-flag", "kernel.bindings.neighbor.bookkeeping-attributes", "kernel.bindings.neighbor.mac", "kernel.bindings.neighbor.type", "kernel.bindings.neighbor.bookkeeping-state", "kernel.bindings.neighbor.bookkeeping-mac", "kernel.bindings.neighbor.multicast-tuple", "kernel.bindings.neighbor.broadcast-tuple", "kernel.bindings.neighbor.broadcast-prefix", "kernel.bindings.neighbor.broadcast-type":
			m.Stages = append(m.Stages, stage)
		case "ndm.envelope", "ndm.text-shape", "ndm.control-byte", "ndm.native-id-shape", "ndm.index-shape", "ndm.header-shape", "ndm.line-bound", "ndm.field-shape", "ndm.member-shape", "ndm.duplicate-native-object", "ndm.required-id", "ndm.required-index", "ndm.required-interface-name", "ndm.required-type", "ndm.duplicate-id", "ndm.duplicate-index", "ndm.duplicate-interface-name", "ndm.duplicate-type", "ndm.duplicate-global", "ndm.duplicate-public", "ndm.duplicate-security-level", "ndm.duplicate-link", "ndm.duplicate-state", "ndm.duplicate-connected", "ndm.duplicate-mac", "ndm.duplicate-address", "ndm.duplicate-mask", "ndm.duplicate-ipv6", "ndm.duplicate-bridge":
			m.Stages = append(m.Stages, stage)
		case "netlink.socket.open", "netlink.socket.receive-buffer", "netlink.socket.bind", "netlink.socket.name", "netlink.socket.binding", "netlink.receive.sender-type", "netlink.receive.sender-port", "netlink.receive.truncated", "netlink.receive.empty", "context.canceled", "context.deadline":
			m.Stages = append(m.Stages, stage)
		case "packet.notifications.neighbor.flags", "packet.notifications.link.flags", "packet.notifications.owned-link", "packet.notifications.address.flags", "packet.notifications.owned-address", "packet.membership.epoch.overflow":
			m.Stages = append(m.Stages, stage)
		case "notifications.link.flags", "notifications.address.flags", "notifications.neighbor.flags", "notifications.route.flags", "notifications.unknown.flags", "notifications.link.tracked-index", "notifications.link.selected-master", "notifications.link.tracked-name", "notifications.link.tracked-parent", "notifications.address.header", "notifications.address.tracked", "notifications.neighbor.header", "notifications.neighbor.delete", "notifications.neighbor.incomplete", "notifications.neighbor.failed", "notifications.neighbor.mac", "notifications.neighbor.binding.ambiguous", "notifications.route.tracked", "notifications.kind":
			m.Stages = append(m.Stages, stage)
		case "notifications.wireless.name", "notifications.wireless.binding", "notifications.wireless.role", "notifications.wireless.header", "notifications.wireless.attributes", "notifications.wireless.payload.length", "notifications.wireless.payload.command", "notifications.wireless.payload.padding", "notifications.wireless.payload.tokens":
			m.Stages = append(m.Stages, stage)
		default:
			m.UnclassifiedStage = true
		}
	}
	return m
}
func packetNativeLog(t *testing.T, m packetNativeMetric) {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Error("native packet closed metric encoding refused")
		return
	}
	t.Log(string(raw))
}
func packetNativePhase(t *testing.T, base context.Context, phase string, run func(context.Context) error) (time.Duration, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(base, 12*time.Second)
	defer cancel()
	start := time.Now()
	err := run(ctx)
	elapsed := time.Since(start)
	err = errors.Join(err, ctx.Err())
	if elapsed >= 12*time.Second {
		err = errors.Join(err, context.DeadlineExceeded)
	}
	packetNativeLog(t, packetNativeMetricFor(phase, elapsed, err))
	return elapsed, err
}
func packetNativeSuperviseClose(ctx context.Context, closeOriginal func() error) error {
	result := make(chan error, 1)
	go func() { result <- closeOriginal() }()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
func packetNativeWaitJoin(ctx context.Context, done <-chan struct{}) error {
	select {
	case <-done:
		return nil
	default:
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return boundary("native.packet.join.timeout", ctx.Err())
	}
}

func packetNativeReadIntent(ctx context.Context, path string) (IPv4LANPacketIntent, error) {
	if ctx.Err() != nil {
		return IPv4LANPacketIntent{}, ctx.Err()
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return IPv4LANPacketIntent{}, at("native.packet.intent.path", nil)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return IPv4LANPacketIntent{}, at("native.packet.intent.path", nil)
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 {
		return IPv4LANPacketIntent{}, at("native.packet.intent.file", nil)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return IPv4LANPacketIntent{}, at("native.packet.intent.file", nil)
	}
	f := os.NewFile(uintptr(fd), "private-native-packet-intent")
	defer f.Close()
	var st unix.Stat_t
	actual, err := f.Stat()
	if err != nil || unix.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) || actual.Mode().Perm()&0077 != 0 || !actual.Mode().IsRegular() || !os.SameFile(before, actual) {
		return IPv4LANPacketIntent{}, at("native.packet.intent.file", nil)
	}
	const limit = 16 << 10
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(raw) > limit {
		return IPv4LANPacketIntent{}, at("native.packet.intent.limit", nil)
	}
	after, err := os.Lstat(path)
	closing, closeErr := f.Stat()
	resolved, resolveErr := filepath.EvalSymlinks(path)
	var closingOwner unix.Stat_t
	if err != nil || closeErr != nil || resolveErr != nil || unix.Fstat(fd, &closingOwner) != nil || closingOwner.Uid != st.Uid || resolved != path || !os.SameFile(actual, after) || !os.SameFile(actual, closing) || closing.Size() != actual.Size() || !closing.ModTime().Equal(actual.ModTime()) || closing.Mode() != actual.Mode() {
		return IPv4LANPacketIntent{}, at("native.packet.intent.file", nil)
	}
	if ctx.Err() != nil {
		return IPv4LANPacketIntent{}, ctx.Err()
	}
	return packetNativeDecodeIntent(raw)
}
func packetNativeDecodeIntent(raw []byte) (IPv4LANPacketIntent, error) {
	fail := func() (IPv4LANPacketIntent, error) {
		return IPv4LANPacketIntent{}, at("native.packet.intent.schema", nil)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return fail()
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return fail()
		}
		key, ok := token.(string)
		if !ok {
			return fail()
		}
		switch key {
		case "revision", "policy_revision", "mode", "new_devices", "segment_ids", "excluded_device_ids", "excluded_cidrs":
		default:
			return fail()
		}
		if _, duplicate := fields[key]; duplicate {
			return fail()
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return fail()
		}
		fields[key] = value
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') || len(fields) != 7 {
		return fail()
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return fail()
	}
	var i IPv4LANPacketIntent
	var revision, policyRevision *uint64
	if json.Unmarshal(fields["revision"], &revision) != nil || revision == nil || json.Unmarshal(fields["policy_revision"], &policyRevision) != nil || policyRevision == nil {
		return fail()
	}
	i.Revision, i.PolicyRevision = *revision, *policyRevision
	for key, target := range map[string]any{"mode": &i.Mode, "new_devices": &i.NewDevices, "segment_ids": &i.SegmentIDs, "excluded_device_ids": &i.ExcludedDeviceIDs, "excluded_cidrs": &i.ExcludedCIDRs} {
		if json.Unmarshal(fields[key], target) != nil {
			return fail()
		}
	}
	if _, err := validateIPv4LANPacketIntent(i); err != nil {
		return IPv4LANPacketIntent{}, err
	}
	return i, nil
}

// Pure Linux/ARM64 harness checks do not opt into stock observations. They
// validate only modeled intent bytes, closed metric redaction and join signals.
func TestIPv4LANPacketNativeHarnessIntentSchema(t *testing.T) {
	valid := []byte(`{"revision":7,"policy_revision":3,"mode":"lan_except","new_devices":"inherit","segment_ids":["Bridge0"],"excluded_device_ids":["mac-02-00-00-00-00-40"],"excluded_cidrs":["198.51.100.0/24"]}`)
	i, err := packetNativeDecodeIntent(valid)
	if err != nil || !slices.Equal(i.ExcludedDeviceIDs, []string{"mac-02-00-00-00-00-40"}) {
		t.Fatal("modeled literal intent refused")
	}
	for _, bad := range [][]byte{append(slices.Clone(valid), []byte(` {}`)...), bytes.Replace(valid, []byte(`"revision":7`), []byte(`"revision":7,"revision":7`), 1), bytes.Replace(valid, []byte(`"revision":7`), []byte(`"Revision":7`), 1), bytes.Replace(valid, []byte(`"revision":7`), []byte(`"revision":null`), 1), bytes.Replace(valid, []byte(`"Bridge0"`), []byte(`"Bridge0","Bridge1"`), 1), bytes.Replace(valid, []byte(`"mac-02-00-00-00-00-40"`), []byte(`"legacy-id"`), 1), bytes.Replace(valid, []byte(`"mode"`), []byte(`"identity"`), 1)} {
		if _, err := packetNativeDecodeIntent(bad); err == nil {
			t.Fatal("unclosed modeled intent accepted")
		}
	}
	path := filepath.Join(t.TempDir(), "intent.json")
	if err := os.WriteFile(path, valid, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if got, err := packetNativeReadIntent(ctx, path); err != nil || !reflect.DeepEqual(got, i) {
		t.Fatal("original modeled private file refused")
	}
	alias := filepath.Join(filepath.Dir(path), "alias.json")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := packetNativeReadIntent(ctx, alias); err == nil {
		t.Fatal("symlink intent adopted")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := packetNativeReadIntent(ctx, path); err == nil {
		t.Fatal("public intent adopted")
	}
}
func TestIPv4LANPacketNativeHarnessClosedMetricsAndJoin(t *testing.T) {
	secret := "modeled-private-value"
	err := at(secret, errors.New(secret))
	raw, _ := json.Marshal(packetNativeMetricFor("constructor", time.Millisecond, err))
	if bytes.Contains(raw, []byte(secret)) || !bytes.Contains(raw, []byte(`"unclassified_stage":true`)) {
		t.Fatal("unallowlisted error leaked into metric")
	}
	// Model an actual nested decoder boundary, preserving both closed labels
	// and refusal while withholding arbitrary foreign error text.
	for _, stage := range []string{"kernel.bindings.neighbor.type", "ndm.duplicate-id", "netlink.receive.sender-port"} {
		nested := boundary("packet.capture", at(stage, errors.New(secret)))
		metric := packetNativeMetricFor("constructor", time.Millisecond, nested)
		if metric.Status != "refused" || metric.UnclassifiedStage || !slices.Equal(metric.Stages, []string{"packet.capture", stage}) {
			t.Fatal("closed nested decoder refusal lost")
		}
		encoded, encodeErr := json.Marshal(metric)
		if encodeErr != nil || bytes.Contains(encoded, []byte(secret)) {
			t.Fatal("foreign decoder cause leaked into metric")
		}
	}
	for _, stage := range []string{"packet.notifications.neighbor.flags", "packet.notifications.link.flags", "packet.notifications.owned-link", "packet.notifications.address.flags", "packet.notifications.owned-address", "packet.membership.epoch.overflow", "notifications.link.flags", "notifications.address.flags", "notifications.neighbor.flags", "notifications.route.flags", "notifications.unknown.flags", "notifications.link.tracked-index", "notifications.link.selected-master", "notifications.link.tracked-name", "notifications.link.tracked-parent", "notifications.address.header", "notifications.address.tracked", "notifications.neighbor.header", "notifications.neighbor.delete", "notifications.neighbor.incomplete", "notifications.neighbor.failed", "notifications.neighbor.mac", "notifications.neighbor.binding.ambiguous", "notifications.route.tracked", "notifications.kind", "notifications.wireless.name", "notifications.wireless.binding", "notifications.wireless.role", "notifications.wireless.header", "notifications.wireless.attributes", "notifications.wireless.payload.length", "notifications.wireless.payload.command", "notifications.wireless.payload.padding", "notifications.wireless.payload.tokens"} {
		metric := packetNativeMetricFor("constructor", time.Millisecond, boundary("packet.capture", boundary("fence.notifications", at(stage, errors.New(secret)))))
		if metric.Status != "refused" || metric.UnclassifiedStage || !slices.Equal(metric.Stages, []string{"packet.capture", "fence.notifications", stage}) {
			t.Fatal("exact nested notification stage lost")
		}
		encoded, encodeErr := json.Marshal(metric)
		if encodeErr != nil || bytes.Contains(encoded, []byte(secret)) {
			t.Fatal("foreign notification cause escaped closed metric")
		}
	}
	for _, sentinel := range []error{context.Canceled, context.DeadlineExceeded} {
		metric := packetNativeMetricFor("constructor", time.Millisecond, boundary("packet.capture", errors.Join(errors.New(secret), sentinel)))
		label := "context.canceled"
		if sentinel == context.DeadlineExceeded {
			label = "context.deadline"
		}
		if metric.Status != "refused" || metric.UnclassifiedStage || !slices.Equal(metric.Stages, []string{"packet.capture", label}) || metric.DeadlineExceeded != (sentinel == context.DeadlineExceeded) {
			t.Fatal("exact nested context sentinel lost")
		}
	}
	for _, prefix := range []string{"kernel.bindings.neighbor.", "ndm.duplicate-", "netlink.socket.", "packet.notifications.", "notifications."} {
		metric := packetNativeMetricFor("constructor", time.Millisecond, boundary("packet.capture", at(prefix+secret, errors.New(secret))))
		encoded, encodeErr := json.Marshal(metric)
		if encodeErr != nil || bytes.Contains(encoded, []byte(secret)) || !metric.UnclassifiedStage || !slices.Equal(metric.Stages, []string{"packet.capture"}) {
			t.Fatal("lookalike stage admitted through a prefix wildcard")
		}
	}
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if packetNativeWaitJoin(ctx, done) == nil {
		t.Fatal("unjoined reader declared joined")
	}
	close(done)
	if err := packetNativeWaitJoin(ctx, done); err != nil {
		t.Fatal("actual completed join refused")
	}
	called := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	err = packetNativeSuperviseClose(ctx, func() error { close(called); <-release; close(finished); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatal("Close timeout declared success")
	}
	<-called
	close(release)
	<-finished
}

// Separate ROOT-only fresh diagnostic read, never a constructor retry or a
// successful A/B Review. The unchanged production decoder still refuses rows.
// RAZVILKA_PHYSICAL_SCOPE_IPV4_LAN_PACKET_NEIGHBOR_NATIVE=1
// plus the same stock-nc1812 marker and private explicit intent file as above.
// Its classes describe THIS observation, not a reconstruction of native 473.
func TestPhysicalScopeNativeIPv4LANPacketNeighborClass(t *testing.T) {
	if os.Getenv("RAZVILKA_PHYSICAL_SCOPE_IPV4_LAN_PACKET_NEIGHBOR_NATIVE") != "1" {
		t.Skip("ROOT-only IPv4 LAN packet neighbor-class opt-in")
	}
	if os.Getenv("RAZVILKA_PHYSICAL_SCOPE_NATIVE") != "stock-nc1812" || os.Geteuid() != 0 {
		t.Fatal("neighbor-class read requires actual stock NC1812 Linux ARM64/root")
	}
	base, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if deadline, ok := t.Deadline(); ok {
		limited, finish := context.WithDeadline(base, deadline)
		defer finish()
		base = limited
	}
	path := os.Getenv("RAZVILKA_PHYSICAL_SCOPE_IPV4_LAN_PACKET_INTENT_FILE")
	var intent IPv4LANPacketIntent
	if _, err := packetNativePhase(t, base, "neighbor_intent", func(ctx context.Context) error {
		var err error
		intent, err = packetNativeReadIntent(ctx, path)
		return err
	}); err != nil {
		t.Fatal("neighbor-class private intent refused")
	}
	var provider *netidentity.Provider
	if _, err := packetNativePhase(t, base, "neighbor_provider", func(ctx context.Context) error {
		var err error
		provider, err = netidentity.NewReviewedStockNC1812Provider(ctx)
		return err
	}); err != nil {
		t.Fatal("neighbor-class actual provider refused")
	}
	var report packetNativeNeighborReport
	var decodeRefusal error
	if _, err := packetNativePhase(t, base, "neighbor_observation", func(ctx context.Context) error {
		return provider.WithCurrent(ctx, func(c context.Context, id netidentity.Identity) error {
			if id.Validate() != nil || id.Kind != netidentity.ReviewedSingleInitNet {
				return at("packet.identity.kind", nil)
			}
			fresh, err := packetNativeReadIntent(c, path)
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(intent, fresh) {
				return at("packet.intent.changed", nil)
			}
			var in scopeOptionsInput
			in.native, err = provider.ReadReviewedStockInterfaces(c)
			if err != nil {
				return err
			}
			in.links, err = dump(c, 18, 0)
			if err != nil {
				return err
			}
			in.addresses, err = dump(c, 22, 0)
			if err != nil {
				return err
			}
			for _, family := range []byte{2, 10} {
				rows, err := dump(c, 26, family)
				if err != nil {
					return err
				}
				in.routes = append(in.routes, rows...)
			}
			topology, err := packetTopologyFromFacts(in, intent)
			if err != nil {
				return err
			}
			links := map[int]Link{}
			for _, m := range in.links {
				link, err := decodeLink(m)
				if err != nil {
					return err
				}
				links[link.IfIndex] = link.Link
			}
			frames := map[byte][]message{}
			for _, family := range []byte{2, 10} {
				frames[family], err = dump(c, 30, family)
				if err != nil {
					return err
				}
			}
			report, decodeRefusal, err = packetNativeNeighborClasses(c, topology, links, intent, frames)
			if err != nil {
				return err
			}
			closing, err := packetNativeReadIntent(c, path)
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(intent, closing) {
				return at("packet.intent.changed", nil)
			}
			// A decoder refusal is the diagnostic result, not permission. Return
			// nil only for completed reads so the provider closes its actual NI
			// bookend before any shape is logged. No scope/identity is issued.
			return nil
		})
	}); err != nil {
		t.Fatal("neighbor-class original read did not close")
	}
	packetNativeLog(t, packetNativeMetricFor("neighbor_decoder", 0, decodeRefusal))
	for _, group := range report.Groups {
		raw, err := json.Marshal(struct {
			Phase string                    `json:"phase"`
			Group packetNativeNeighborGroup `json:"group"`
		}{"neighbor_class", group})
		if err != nil {
			t.Fatal("neighbor-class closed group encoding refused")
		}
		t.Log(string(raw))
	}
	report.Groups = nil
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal("neighbor-class closed summary encoding refused")
	}
	t.Log(string(raw))
	// PASS means a bounded diagnostic GET closed, even if every row refused.
	// It does not assert a working lifecycle, MAC matcher, or LIST admission.
}

// Comparable grouping key: enums, lengths and relations only. Values used to
// compare ownership/intent remain private; even opaque hashes are forbidden.
type packetNativeNeighborShape struct {
	DumpFamily           byte   `json:"dump_family"`
	HeaderFamily         byte   `json:"header_family"`
	Parsed               bool   `json:"parsed"`
	State                uint16 `json:"state"`
	Kind                 byte   `json:"kind"`
	Flags                byte   `json:"flags"`
	RouterFlag           bool   `json:"router_flag"`
	Ingress              string `json:"ingress"`
	HomeRelation         string `json:"home_relation"`
	LinkPresent          bool   `json:"link_present"`
	LinkType             uint16 `json:"link_type"`
	LinkClass            string `json:"link_class"`
	LLAddressBytes       int    `json:"lladdr_bytes"`
	LLAddressClass       string `json:"lladdr_class"`
	OwnedAddressRelation string `json:"owned_address_relation"`
	OwnedMACRelation     string `json:"owned_mac_relation"`
	ExplicitMACRelation  string `json:"explicit_mac_relation"`
	LiteralCIDRRelation  string `json:"literal_cidr_relation"`
	AddressClass         string `json:"address_class,omitempty"`
	LinkFlags            uint32 `json:"link_flags,omitempty"`
	LinkLoopbackFlag     bool   `json:"link_loopback_flag,omitempty"`
	LinkAttachments      string `json:"link_attachments,omitempty"`
}
type packetNativeNeighborGroup struct {
	Shape packetNativeNeighborShape `json:"shape"`
	Stage string                    `json:"stage,omitempty"`
	Count int                       `json:"count"`
}
type packetNativeNeighborClassKey struct {
	Shape packetNativeNeighborShape
	Stage string
}
type packetNativeNeighborStageCount struct {
	Stage string `json:"stage"`
	Count int    `json:"count"`
}
type packetNativeNeighborReport struct {
	Phase                     string                           `json:"phase"`
	Records                   int                              `json:"records"`
	MACRefusals               int                              `json:"mac_refusals"`
	OtherRefusals             int                              `json:"other_refusals"`
	GroupCount                int                              `json:"group_count"`
	GroupsOmitted             int                              `json:"groups_omitted"`
	RecordsOmitted            int                              `json:"records_omitted"`
	Groups                    []packetNativeNeighborGroup      `json:"groups,omitempty"`
	OtherStages               []packetNativeNeighborStageCount `json:"other_stages,omitempty"`
	OtherStagesOmitted        int                              `json:"other_stages_omitted"`
	OtherStageCountsOmitted   int                              `json:"other_stage_counts_omitted"`
	OtherUnclassifiedRefusals int                              `json:"other_unclassified_refusals"`
}

func packetNativeNeighborClasses(ctx context.Context, topology ipv4LANPacketTopology, links map[int]Link, intent IPv4LANPacketIntent, frames map[byte][]message) (packetNativeNeighborReport, error, error) {
	report := packetNativeNeighborReport{Phase: "neighbor_summary"}
	groups := map[packetNativeNeighborClassKey]int{}
	otherStages := map[string]int{}
	var order []packetNativeNeighborClassKey
	bytesSeen := 0
	for _, family := range []byte{2, 10} {
		rows, ok := frames[family]
		if !ok {
			return report, nil, at("kernel.bindings.neighbor.family-missing", nil)
		}
		for _, m := range rows {
			if ctx.Err() != nil {
				return report, nil, ctx.Err()
			}
			report.Records++
			bytesSeen += len(m.data)
			if report.Records > 4096 || bytesSeen > 1<<20 {
				return report, nil, at("kernel.bindings.neighbor.limit", nil)
			}
			if len(m.data) < 12 || m.data[0] != family {
				return report, nil, at("kernel.bindings.neighbor.dump-family", nil)
			}
			_, _, err := packetDecodeNeighbor(m, topology)
			if err == nil {
				continue
			}
			stages := DiagnosticStages(err)
			stage := ""
			if !slices.Contains(stages, "kernel.bindings.neighbor.mac") {
				report.OtherRefusals++
				if packetNativeCountNeighborOtherRefusal(err, otherStages) {
					report.OtherUnclassifiedRefusals++
				}
				if !slices.Contains(stages, "kernel.bindings.neighbor.type") {
					continue
				}
				stage = "kernel.bindings.neighbor.type"
			} else {
				report.MACRefusals++
			}
			shape := packetNativeNeighborClassKey{Shape: packetNativeNeighborClass(family, m, topology, links, intent), Stage: stage}
			if stage == "kernel.bindings.neighbor.type" {
				shape.Shape = packetNativeNeighborTypeFacts(shape.Shape, m, links)
			}
			if _, ok := groups[shape]; !ok {
				order = append(order, shape)
			}
			groups[shape]++
		}
	}
	report.GroupCount = len(order)
	for i, shape := range order {
		if i < 16 {
			report.Groups = append(report.Groups, packetNativeNeighborGroup{Shape: shape.Shape, Stage: shape.Stage, Count: groups[shape]})
		} else {
			report.GroupsOmitted++
			report.RecordsOmitted += groups[shape]
		}
	}
	packetNativeNeighborOtherSummary(&report, otherStages)
	// Unchanged complete boundary check supplies the same first refusal, including
	// duplicate/ownership checks. Shape counts never replace this classification.
	_, _, refusal := packetNeighborBoundary(ctx, topology, frames)
	return report, refusal, nil
}

// Extra closed facts are emitted only for the exact type-refusal group.
func packetNativeNeighborTypeFacts(s packetNativeNeighborShape, m message, links map[int]Link) packetNativeNeighborShape {
	s.AddressClass, s.LinkAttachments = "other", "unknown"
	if len(m.data) < 12 {
		return s
	}
	if link, ok := links[int(int32(binary.NativeEndian.Uint32(m.data[4:8])))]; ok {
		s.LinkFlags, s.LinkLoopbackFlag = link.Flags, link.Flags&8 != 0
		s.LinkAttachments = "present"
		if link.MasterIfIndex == 0 && link.ParentIfIndex == 0 && !link.ForeignParent {
			s.LinkAttachments = "absent"
		}
	}
	a, err := attrs(m.data[12:])
	ip, ok := netip.AddrFromSlice(a[1])
	if err != nil || !ok || !ip.Is6() || ip.Is4In6() {
		return s
	}
	switch {
	case ip.IsMulticast():
		s.AddressClass = "ipv6_multicast"
	case ip.IsLinkLocalUnicast():
		s.AddressClass = "ipv6_link_local"
	case ip.IsLoopback():
		s.AddressClass = "ipv6_loopback"
	case ip.IsUnspecified():
		s.AddressClass = "ipv6_unspecified"
	case ip.IsGlobalUnicast():
		s.AddressClass = "ipv6_global"
	}
	return s
}

// Count each exact allowlisted stage at most once per refused record. Foreign
// cause text is ignored; absent and lookalike labels stay unclassified.
func packetNativeCountNeighborOtherRefusal(err error, counts map[string]int) bool {
	seen := map[string]bool{}
	unclassified := false
	for _, stage := range DiagnosticStages(err) {
		switch stage {
		case "kernel.bindings.neighbor.header", "kernel.bindings.neighbor.family", "kernel.bindings.neighbor.attributes", "kernel.bindings.neighbor.index", "kernel.bindings.neighbor.address", "kernel.bindings.neighbor.state", "kernel.bindings.neighbor.flags", "kernel.bindings.neighbor.router-flag", "kernel.bindings.neighbor.bookkeeping-attributes", "kernel.bindings.neighbor.type", "kernel.bindings.neighbor.router-state", "kernel.bindings.neighbor.segment", "kernel.bindings.neighbor.bookkeeping-state", "kernel.bindings.neighbor.bookkeeping-mac", "kernel.bindings.neighbor.multicast-tuple", "kernel.bindings.neighbor.broadcast-tuple", "kernel.bindings.neighbor.broadcast-prefix", "kernel.bindings.neighbor.broadcast-type", "packet.neighbor.mac", "packet.owned.neighbor.conflict":
			if !seen[stage] {
				counts[stage]++
				seen[stage] = true
			}
		default:
			unclassified = true
		}
	}
	return unclassified || len(seen) == 0
}

func packetNativeNeighborOtherSummary(report *packetNativeNeighborReport, counts map[string]int) {
	stages := make([]string, 0, len(counts))
	for stage := range counts {
		stages = append(stages, stage)
	}
	slices.Sort(stages)
	for i, stage := range stages {
		if i < 16 {
			report.OtherStages = append(report.OtherStages, packetNativeNeighborStageCount{Stage: stage, Count: counts[stage]})
		} else {
			report.OtherStagesOmitted++
			report.OtherStageCountsOmitted += counts[stage]
		}
	}
}

func packetNativeNeighborClass(family byte, m message, topology ipv4LANPacketTopology, links map[int]Link, intent IPv4LANPacketIntent) packetNativeNeighborShape {
	s := packetNativeNeighborShape{DumpFamily: family, Ingress: "unknown", HomeRelation: "unknown", LinkClass: "unknown", LLAddressClass: "unknown", OwnedAddressRelation: "unknown", OwnedMACRelation: "unobservable", ExplicitMACRelation: "unobservable", LiteralCIDRRelation: "unknown"}
	if len(m.data) < 12 {
		return s
	}
	s.HeaderFamily = m.data[0]
	s.State = binary.NativeEndian.Uint16(m.data[8:10])
	s.Kind = m.data[11]
	s.Flags = m.data[10]
	s.RouterFlag = s.Flags&128 != 0
	index := int(int32(binary.NativeEndian.Uint32(m.data[4:8])))
	if index > 0 {
		s.Ingress = "foreign"
		if index == topology.home.IfIndex {
			s.Ingress = "home"
		}
	}
	if link, ok := links[index]; ok {
		s.LinkPresent = true
		s.HomeRelation = "unrelated"
		if index == topology.home.IfIndex {
			s.HomeRelation = "home"
		}
		for _, member := range topology.home.Members {
			if index == member.IfIndex {
				s.HomeRelation = "member"
			}
			if member.Parent.Known && index == member.Parent.IfIndex || member.ParentIfIndex != 0 && index == member.ParentIfIndex {
				s.HomeRelation = "parent"
			}
		}
		if s.HomeRelation == "unrelated" && (link.MasterIfIndex == topology.home.IfIndex || link.ParentIfIndex == topology.home.IfIndex) {
			s.HomeRelation = "home_linked"
		}
		s.LinkType = link.LinkType
		switch link.LinkType {
		case 1:
			s.LinkClass = "ethernet"
		case 772:
			s.LinkClass = "loopback"
		case 0:
			s.LinkClass = "unknown"
		default:
			s.LinkClass = "non_ethernet"
		}
	}
	a, err := attrs(m.data[12:])
	if err != nil {
		return s
	}
	ll, present := a[2]
	s.LLAddressBytes = len(ll)
	mac := ""
	if len(ll) == 6 {
		mac = net.HardwareAddr(ll).String()
	}
	switch {
	case !present:
		s.LLAddressClass = "absent"
	case len(ll) == 0:
		s.LLAddressClass = "empty"
	case bytes.Equal(ll, []byte{0, 0, 0, 0, 0, 0}):
		s.LLAddressClass = "zero"
	case validMAC(mac):
		s.LLAddressClass = "valid_unicast"
	case bytes.Equal(ll, []byte{255, 255, 255, 255, 255, 255}):
		s.LLAddressClass = "broadcast"
	case len(ll) == 6 && ll[0]&1 != 0:
		s.LLAddressClass = "multicast"
	default:
		s.LLAddressClass = "invalid_length_or_form"
	}
	if validMAC(mac) {
		s.OwnedMACRelation = "no_match"
		s.ExplicitMACRelation = "no_match"
		for _, link := range topology.links {
			if link.MAC == mac {
				s.OwnedMACRelation = "match"
			}
		}
		for _, id := range intent.ExcludedDeviceIDs {
			if physicalDeviceID(mac) == id {
				s.ExplicitMACRelation = "match"
			}
		}
	}
	n, err := parseKernelNeighbor(m)
	if err != nil {
		return s
	}
	s.Parsed = true
	same, other := 0, 0
	for _, address := range topology.addresses {
		prefix, _ := netip.ParsePrefix(address.prefix)
		if projectionAddressKey(address.index, prefix.Addr()) == projectionAddressKey(n.index, n.address) {
			if address.index == n.index {
				same++
			} else {
				other++
			}
		}
	}
	switch {
	case same+other == 0:
		s.OwnedAddressRelation = "none"
	case same+other > 1:
		s.OwnedAddressRelation = "ambiguous"
	case same == 1:
		s.OwnedAddressRelation = "same_interface"
	default:
		s.OwnedAddressRelation = "other_interface"
	}
	s.LiteralCIDRRelation = "no_match"
	for _, raw := range intent.ExcludedCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			s.LiteralCIDRRelation = "unknown"
			break
		}
		if prefix.Contains(n.address) {
			s.LiteralCIDRRelation = "match"
		}
	}
	return s
}

func TestIPv4LANPacketNativeHarnessNeighborClassPrivacyAndBounds(t *testing.T) {
	in, _ := scopeOptionsKernelFixture()
	intent := IPv4LANPacketIntent{Mode: "lan_except", NewDevices: "inherit", SegmentIDs: []string{"Bridge0"}, ExcludedDeviceIDs: []string{physicalDeviceID(projectionClientMAC)}, ExcludedCIDRs: []string{"198.51.100.0/24"}}
	topology, err := packetTopologyFromFacts(in, intent)
	if err != nil {
		t.Fatal("modeled topology refused")
	}
	links := map[int]Link{}
	for _, m := range in.links {
		link, err := decodeLink(m)
		if err != nil {
			t.Fatal("modeled link refused")
		}
		links[link.IfIndex] = link.Link
	}
	privateName := "secret0"
	nonEther := linkFrame(12, privateName, "", "", 0)
	binary.NativeEndian.PutUint16(nonEther.data[2:4], 512)
	link, err := decodeLink(nonEther)
	if err != nil {
		t.Fatal("modeled non-Ethernet link refused")
	}
	links[link.IfIndex] = link.Link
	address := "198.51.100.9"
	row := neighborFrame(12, address, "", 64)
	shape := packetNativeNeighborClass(2, row, topology, links, intent)
	if !shape.Parsed || shape.State != 64 || shape.Kind != 1 || shape.Ingress != "foreign" || shape.LinkClass != "non_ethernet" || shape.LLAddressClass != "absent" || shape.OwnedAddressRelation != "none" || shape.OwnedMACRelation != "unobservable" || shape.ExplicitMACRelation != "unobservable" || shape.LiteralCIDRRelation != "match" {
		t.Fatal("modeled shape guessed an identity or lost literal intent")
	}
	if _, _, err := packetDecodeNeighbor(row, topology); !slices.Contains(DiagnosticStages(err), "kernel.bindings.neighbor.mac") {
		t.Fatal("diagnostic classification weakened production decoder")
	}
	for _, state := range []uint16{1, 32} {
		unresolved := neighborFrame(9, "192.0.2.90", "", state)
		if _, _, err := packetDecodeNeighbor(unresolved, topology); err != nil {
			t.Fatal("ordinary unresolved row unexpectedly refused")
		}
	}
	unknown := packetNativeNeighborClass(2, neighborFrame(99, address, "", 64), topology, links, intent)
	if unknown.LinkPresent || unknown.LinkClass != "unknown" || unknown.HomeRelation != "unknown" || unknown.ExplicitMACRelation != "unobservable" {
		t.Fatal("missing kernel link became known non-Ethernet")
	}
	home := packetNativeNeighborClass(2, neighborFrame(9, "192.0.2.1", projectionClientMAC, 2), topology, links, intent)
	if home.Ingress != "home" || home.LinkClass != "ethernet" || home.OwnedAddressRelation != "same_interface" || home.ExplicitMACRelation != "match" {
		t.Fatal("exact modeled ownership/negative comparison lost")
	}
	encoded, _ := json.Marshal(home)
	for _, value := range []string{privateName, address, "192.0.2.1", projectionClientMAC, physicalDeviceID(projectionClientMAC), "Home", "Bridge0"} {
		if bytes.Contains(encoded, []byte(value)) {
			t.Fatal("modeled private value escaped closed shape")
		}
	}
	encoded, _ = json.Marshal(shape)
	if bytes.Contains(encoded, []byte(privateName)) || bytes.Contains(encoded, []byte(address)) {
		t.Fatal("non-Ethernet private value escaped closed shape")
	}
	frames := map[byte][]message{2: {}, 10: {}}
	for length := 1; length <= 18; length++ {
		m := neighborFrame(12, address, "", 64)
		m.data = append(m.data, attr(2, make([]byte, length))...)
		frames[2] = append(frames[2], m)
	}
	report, refusal, readErr := packetNativeNeighborClasses(context.Background(), topology, links, intent, frames)
	if readErr != nil || !slices.Contains(DiagnosticStages(refusal), "kernel.bindings.neighbor.mac") || report.MACRefusals != 18 || report.GroupCount != 18 || len(report.Groups) != 16 || report.GroupsOmitted != 2 || report.RecordsOmitted != 2 {
		t.Fatal("closed shape grouping bound lost")
	}
	frames[2] = make([]message, 4097)
	for i := range frames[2] {
		frames[2][i] = row
	}
	_, _, readErr = packetNativeNeighborClasses(context.Background(), topology, links, intent, frames)
	if !slices.Contains(DiagnosticStages(readErr), "kernel.bindings.neighbor.limit") {
		t.Fatal("diagnostic record bound lost")
	}
}

func TestIPv4LANPacketNativeHarnessNeighborOtherStagesPrivacyAndBounds(t *testing.T) {
	in, _ := scopeOptionsKernelFixture()
	intent := IPv4LANPacketIntent{Mode: "lan_except", NewDevices: "inherit", SegmentIDs: []string{"Bridge0"}}
	topology, err := packetTopologyFromFacts(in, intent)
	if err != nil {
		t.Fatal("modeled topology refused")
	}
	wrongType := neighborFrame(12, "198.51.100.9", projectionClientMAC, 2)
	wrongType.data[11] = 2
	frames := map[byte][]message{2: {
		neighborFrame(12, "198.51.100.8", "", 64),
		wrongType,
		neighborFrame(9, "192.0.2.1", projectionClientMAC, 2),
	}, 10: {}}
	report, refusal, readErr := packetNativeNeighborClasses(context.Background(), topology, nil, intent, frames)
	want := []packetNativeNeighborStageCount{{"kernel.bindings.neighbor.type", 1}, {"packet.owned.neighbor.conflict", 1}}
	if readErr != nil || !slices.Contains(DiagnosticStages(refusal), "kernel.bindings.neighbor.mac") || report.MACRefusals != 1 || report.OtherRefusals != 2 || report.OtherUnclassifiedRefusals != 0 || !slices.Equal(report.OtherStages, want) {
		t.Fatal("other stage counts changed the first decoder refusal or lost closed branches")
	}
	secret := "modeled-private-value"
	counts := map[string]int{}
	if packetNativeCountNeighborOtherRefusal(errors.Join(at("kernel.bindings.neighbor.type", errors.New(secret)), at("kernel.bindings.neighbor.type", nil)), counts) || counts["kernel.bindings.neighbor.type"] != 1 {
		t.Fatal("one record counted a repeated closed stage twice")
	}
	for _, hidden := range []error{errors.New(secret), at(secret, nil), at("kernel.bindings.neighbor."+secret, nil), at("packet.owned.neighbor."+secret, nil)} {
		if !packetNativeCountNeighborOtherRefusal(hidden, counts) || len(counts) != 1 {
			t.Fatal("opaque or lookalike label escaped classification")
		}
	}
	if !packetNativeCountNeighborOtherRefusal(errors.Join(at("packet.neighbor.mac", nil), at(secret, nil)), counts) || counts["packet.neighbor.mac"] != 1 {
		t.Fatal("partially unclassified refusal lost its closed stage")
	}
	encoded, encodeErr := json.Marshal(struct {
		Report packetNativeNeighborReport `json:"report"`
		Counts map[string]int             `json:"counts"`
	}{report, counts})
	if encodeErr != nil {
		t.Fatal("closed stage counts encoding refused")
	}
	for _, value := range []string{secret, "198.51.100.9", "198.51.100.8", "192.0.2.1", projectionClientMAC, "Bridge0"} {
		if bytes.Contains(encoded, []byte(value)) {
			t.Fatal("private value escaped other stage counts")
		}
	}
	counts = map[string]int{}
	for _, stage := range []string{"kernel.bindings.neighbor.header", "kernel.bindings.neighbor.family", "kernel.bindings.neighbor.attributes", "kernel.bindings.neighbor.index", "kernel.bindings.neighbor.address", "kernel.bindings.neighbor.state", "kernel.bindings.neighbor.flags", "kernel.bindings.neighbor.router-flag", "kernel.bindings.neighbor.bookkeeping-attributes", "kernel.bindings.neighbor.type", "kernel.bindings.neighbor.router-state", "kernel.bindings.neighbor.segment", "kernel.bindings.neighbor.bookkeeping-state", "kernel.bindings.neighbor.bookkeeping-mac", "kernel.bindings.neighbor.multicast-tuple", "kernel.bindings.neighbor.broadcast-tuple", "kernel.bindings.neighbor.broadcast-prefix", "kernel.bindings.neighbor.broadcast-type"} {
		if packetNativeCountNeighborOtherRefusal(at(stage, nil), counts) {
			t.Fatal("finite decoder stage unexpectedly unclassified")
		}
	}
	bounded := packetNativeNeighborReport{}
	packetNativeNeighborOtherSummary(&bounded, counts)
	if len(bounded.OtherStages) != 16 || bounded.OtherStagesOmitted != 2 || bounded.OtherStageCountsOmitted != 2 {
		t.Fatal("other stage output bound lost")
	}
	for i := 1; i < len(bounded.OtherStages); i++ {
		if bounded.OtherStages[i-1].Stage >= bounded.OtherStages[i].Stage {
			t.Fatal("closed stage output order is unstable")
		}
	}
}

func TestIPv4LANPacketNativeHarnessNeighborTypeShapePrivacyAndAggregateBound(t *testing.T) {
	in, _ := scopeOptionsKernelFixture()
	intent := IPv4LANPacketIntent{Mode: "lan_except", NewDevices: "inherit", SegmentIDs: []string{"Bridge0"}}
	topology, err := packetTopologyFromFacts(in, intent)
	if err != nil {
		t.Fatal("modeled topology refused")
	}
	privateName, privateAddress := "modeled-secret0", "2001:db8::90"
	links := map[int]Link{12: {IfIndex: 12, Interface: privateName, LinkType: 65534}}
	row := neighborFrame(12, privateAddress, "", 64)
	row.data = append(row.data, attr(2, nil)...)
	row.data[11] = 2
	frames := map[byte][]message{2: {}, 10: {row}}
	report, refusal, readErr := packetNativeNeighborClasses(context.Background(), topology, links, intent, frames)
	if readErr != nil || !slices.Contains(DiagnosticStages(refusal), "kernel.bindings.neighbor.type") || report.OtherRefusals != 1 || report.MACRefusals != 0 || len(report.Groups) != 1 {
		t.Fatal("exact non-MAC type refusal shape lost or decoder changed")
	}
	group := report.Groups[0]
	if group.Stage != "kernel.bindings.neighbor.type" || group.Count != 1 || !group.Shape.Parsed || group.Shape.Kind != 2 || group.Shape.LinkType != 65534 || group.Shape.HomeRelation != "unrelated" || group.Shape.LLAddressClass != "empty" || group.Shape.ExplicitMACRelation != "unobservable" || group.Shape.AddressClass != "ipv6_global" || group.Shape.LinkAttachments != "absent" {
		t.Fatal("type shape guessed or omitted a closed field")
	}
	encoded, encodeErr := json.Marshal(report)
	if encodeErr != nil || bytes.Contains(encoded, []byte(privateName)) || bytes.Contains(encoded, []byte(privateAddress)) || bytes.Contains(encoded, []byte("Bridge0")) {
		t.Fatal("private value escaped exact type shape")
	}
	for length := 1; length <= 17; length++ {
		m := neighborFrame(12, "198.51.100.9", "", 64)
		m.data = append(m.data, attr(2, make([]byte, length))...)
		frames[2] = append(frames[2], m)
	}
	report, _, readErr = packetNativeNeighborClasses(context.Background(), topology, links, intent, frames)
	if readErr != nil || report.MACRefusals != 17 || report.OtherRefusals != 1 || report.GroupCount != 18 || len(report.Groups) != 16 || report.GroupsOmitted != 2 || report.RecordsOmitted != 2 {
		t.Fatal("MAC and type shapes exceeded their shared aggregate bound")
	}
	for address, want := range map[string]string{"ff02::1": "ipv6_multicast", "fe80::90": "ipv6_link_local", "::1": "ipv6_loopback", "::": "ipv6_unspecified", privateAddress: "ipv6_global", "192.0.2.90": "other"} {
		facts := packetNativeNeighborTypeFacts(packetNativeNeighborShape{}, neighborFrame(12, address, "", 64), links)
		if facts.AddressClass != want {
			t.Fatal("closed address class was guessed")
		}
	}
	links[12] = Link{IfIndex: 12, Interface: privateName, LinkType: 772, Flags: 9}
	facts := packetNativeNeighborTypeFacts(packetNativeNeighborShape{}, row, links)
	if facts.LinkFlags != 9 || !facts.LinkLoopbackFlag || facts.LinkAttachments != "absent" {
		t.Fatal("observed loopback flags or absent attachments lost")
	}
	for _, attached := range []Link{{IfIndex: 12, MasterIfIndex: 9}, {IfIndex: 12, ParentIfIndex: 9}, {IfIndex: 12, ForeignParent: true}} {
		links[12] = attached
		if packetNativeNeighborTypeFacts(packetNativeNeighborShape{}, row, links).LinkAttachments != "present" {
			t.Fatal("present attachment was classified absent")
		}
	}
	if packetNativeNeighborTypeFacts(packetNativeNeighborShape{}, row, nil).LinkAttachments != "unknown" {
		t.Fatal("missing link became proof of absent attachments")
	}
	encoded, _ = json.Marshal(facts)
	if bytes.Contains(encoded, []byte(privateName)) || bytes.Contains(encoded, []byte(privateAddress)) {
		t.Fatal("private value escaped loopback facts")
	}
}
