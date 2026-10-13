//go:build linux && arm64

package physicalscope

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
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
	for _, prefix := range []string{"kernel.bindings.neighbor.", "ndm.duplicate-", "netlink.socket."} {
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
