package updatecheck

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

func ordinaryRoleFixture(t *testing.T) (fileReview, updateRecord, fileHelperIdentity, fileCommandReceipt, []bootstrapControllerFact) {
	t.Helper()
	_, u, review := fileAdapterFixture(t)
	review.OldVersion, review.NewVersion = "0.20.0", "0.20.1"
	review.JournalReaders = &journalReaderProof{Schema: selfupdatejournal.PairedSchema, RequiredReader: selfupdatejournal.PairedSchema, Controllers: []journalReaderImage{{Path: filepath.Join(t.TempDir(), "controller"), SHA256: review.OldExecutableSHA256, ReadVersion: selfupdatejournal.PairedSchema}}}
	record := u.record
	record.CurrentVersion, record.Job.Release.Version = review.OldVersion, review.NewVersion
	record.Job.State, record.Job.Stage, record.Job.ReviewToken = "restarting", "file-protocol", ""
	record.Job.CanApply, record.Job.CanCancel = false, false
	record.Job.HelperPID, record.ParentPID = 20, 21
	helper := fileProcess{Boot: "01234567-89ab-cdef-0123-456789abcdef", PID: 20, Start: "10", ExecutableSHA256: review.OldExecutableSHA256, Device: 1, Inode: 2}
	panel := helper
	panel.PID, panel.Start, panel.Inode = 21, "11", 3
	identity := fileHelperIdentity{selfUpdateProtocolSchema, review.ID, helper, panel}
	supervisor := helper
	supervisor.PID, supervisor.Start = 22, "12"
	child := helper
	child.PID, child.Start = 23, "13"
	command := fileCommandReceipt{Schema: selfUpdateProtocolSchema, ID: review.ID, Command: "quiesce-old-runtime", State: "running", Parent: helper, Supervisor: supervisor, DirectPID: child.PID}
	return review, record, identity, command, []bootstrapControllerFact{
		{helper, 1, []string{"control.bin", "self-update-helper", review.ID}},
		{supervisor, helper.PID, []string{"control.bin", "self-update-command-helper", review.ID, command.Command}},
		{child, supervisor.PID, []string{"control.bin", "self-update-runtime-quiesce", review.ID, bootstrapDecimal(review.Revision), "22"}},
	}
}

func TestOrdinaryControllerRoleRequiresOwnSealedFutureGroup(t *testing.T) {
	review, record, identity, command, facts := ordinaryRoleFixture(t)
	for i, role := range []string{"ordinary-installer", "quiesce-supervisor", "quiesce-child"} {
		if got := ordinaryControllerRole(review, record, identity, command, facts[i]); got != role {
			t.Fatal(i, got)
		}
	}
	for _, kind := range []string{"bootstrap", "old-version", "missing-reader", "reader3", "cold", "outer", "child-parent", "supervisor-parent", "changed-birth", "candidate-helper", "command-parent", "reaped", "cancelled", "old-panel", "review-token", "stage", "release", "downgrade"} {
		t.Run(kind, func(t *testing.T) {
			review, record, identity, command, facts := ordinaryRoleFixture(t)
			fact := facts[2]
			switch kind {
			case "bootstrap":
				review.Bootstrap = &fileBootstrapBinding{Role: externalOld193InstallerRole}
			case "old-version":
				review.OldVersion = "0.19.3"
			case "missing-reader":
				review.JournalReaders = nil
			case "reader3":
				review.JournalReaders.RequiredReader = 3
			case "cold":
				fact.Args = []string{"razvilka", "-config", "/opt/etc/razvilka/config.json"}
			case "outer":
				fact = facts[0]
				fact.Process.PID = 99
			case "child-parent":
				fact.Parent = 99
			case "supervisor-parent":
				fact = facts[1]
				fact.Parent = 99
			case "changed-birth":
				fact = facts[1]
				fact.Process.Start = "99"
			case "candidate-helper":
				identity.Process.ExecutableSHA256 = record.Job.Release.Binary.Digest[7:]
			case "command-parent":
				command.Parent = identity.OldPanel
			case "reaped":
				command.State, command.WaitECHILD, command.Reaped = "reaped", true, 1
			case "cancelled":
				command.Cancelled = true
			case "old-panel":
				fact = facts[0]
				fact.Process = identity.OldPanel
			case "review-token":
				record.Job.ReviewToken = "borrowed"
			case "stage":
				record.Job.Stage = "ready"
			case "release":
				record.Job.Release.Version = "0.20.2"
			case "downgrade":
				review.NewVersion = "0.19.3"
			}
			if ordinaryControllerRole(review, record, identity, command, fact) != "" {
				t.Fatal("incompatible facts received an ordinary role")
			}
		})
	}
}

func TestOrdinaryQuiesceJoinExpiresAndCannotBeReconstructed(t *testing.T) {
	_, _, _, command, _ := ordinaryRoleFixture(t)
	a := &SelfUpdateFileAdapter{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if c, err := ordinaryQuiesceJoinFor(ctx, a, command, command.Supervisor.PID); err != nil || c != nil {
		t.Fatal("receipt supplied an original wait capability", err)
	}
	joined, release := ordinaryJoinedQuiesceContext(a, ctx, command, 2) // model of the private producer boundary only
	defer release()
	c, err := ordinaryQuiesceJoinFor(joined, a, command, command.Supervisor.PID)
	if err != nil || c == nil {
		t.Fatal(err)
	}
	derived, stop := context.WithTimeout(joined, time.Second)
	defer stop()
	if fresh, err := ordinaryQuiesceJoinFor(derived, a, command, command.Supervisor.PID); err != nil || fresh != c {
		t.Fatal("original bounded observer lost the wait capability", err)
	}
	for _, kind := range []string{"copied", "cold-context", "other-adapter", "other-caller", "changed-command", "released", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			original, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			held, revoke := ordinaryJoinedQuiesceContext(a, original, command, 2)
			defer revoke()
			adapter, changed, caller := a, command, command.Supervisor.PID
			switch kind {
			case "copied":
				value := held.Value(ordinaryQuiesceJoinKey{}).(*ordinaryQuiesceJoin)
				copy := &ordinaryQuiesceJoin{self: value, adapter: value.adapter, original: value.original, deadline: value.deadline, command: value.command, reaped: value.reaped}
				copy.active.Store(true)
				held = context.WithValue(original, ordinaryQuiesceJoinKey{}, copy)
			case "cold-context":
				held = original
			case "other-adapter":
				adapter = &SelfUpdateFileAdapter{}
			case "other-caller":
				caller = command.Parent.PID
			case "changed-command":
				changed.DirectPID++
			case "released":
				revoke()
			case "cancelled":
				cancel()
			}
			value, err := ordinaryQuiesceJoinFor(held, adapter, changed, caller)
			if value != nil || kind != "cold-context" && err == nil {
				t.Fatal("borrowed original join was accepted", err)
			}
		})
	}
}

func TestOrdinaryRoleAPIFailsWithoutFiniteOriginalContext(t *testing.T) {
	a := &SelfUpdateFileAdapter{}
	for _, ctx := range []context.Context{nil, context.Background()} {
		if !errors.Is(a.VerifyOrdinaryInstallerControllerRole(ctx, "0123456789abcdef0123456789abcdef", 20), ErrOrdinaryInstallerControllerRole) {
			t.Fatal("unbounded context was accepted")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	cancel()
	if !errors.Is(a.VerifyOrdinaryInstallerControllerRole(ctx, "0123456789abcdef0123456789abcdef", 20), ErrOrdinaryInstallerControllerRole) {
		t.Fatal("cancelled role was accepted")
	}
}

// These are role-selector models after the original complete group reader;
// they do not supply a native process or mint an installer capability.
func TestOrdinaryCurrentControllerReadIsDistinctFromPeerClassification(t *testing.T) {
	review, record, identity, command, facts := ordinaryRoleFixture(t)
	child := facts[2]
	childRole := ordinaryControllerRole(review, record, identity, command, child)
	if !ordinaryControllerReadRole(childRole, child.Process.PID, child.Process.PID, false, true) {
		t.Fatal("live verified quiesce caller cannot bind its current-controller reader")
	}
	if ordinaryControllerReadRole(childRole, child.Process.PID, child.Process.PID, false, false) {
		t.Fatal("current caller was classified as a peer")
	}
	supervisor := facts[1]
	supervisorRole := ordinaryControllerRole(review, record, identity, command, supervisor)
	if !ordinaryControllerReadRole(supervisorRole, supervisor.Process.PID, child.Process.PID, false, false) ||
		!ordinaryControllerReadRole(supervisorRole, supervisor.Process.PID, supervisor.Process.PID, true, true) {
		t.Fatal("verified live peer or original joined caller was refused")
	}
	for _, invalid := range []struct {
		role         string
		pid, caller  int
		joined, self bool
	}{
		{childRole, child.Process.PID, child.Process.PID, true, true},
		{childRole, child.Process.PID, supervisor.Process.PID, true, false},
		{supervisorRole, supervisor.Process.PID, supervisor.Process.PID, false, true},
		{supervisorRole, supervisor.Process.PID, child.Process.PID, true, true},
		{"ordinary-installer", facts[0].Process.PID, facts[0].Process.PID, false, true},
		{"", child.Process.PID, child.Process.PID, false, true},
	} {
		if ordinaryControllerReadRole(invalid.role, invalid.pid, invalid.caller, invalid.joined, invalid.self) {
			t.Fatal("wrong current observer, peer incarnation or join role was accepted", invalid)
		}
	}
}

func TestOrdinaryCurrentControllerAPIRefusesUnprovenCaller(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef"
	finite, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cancelled, stop := context.WithTimeout(context.Background(), time.Minute)
	stop()
	for _, test := range []struct {
		adapter *SelfUpdateFileAdapter
		ctx     context.Context
		id      string
	}{
		{nil, finite, id},
		{&SelfUpdateFileAdapter{}, nil, id},
		{&SelfUpdateFileAdapter{}, context.Background(), id},
		{&SelfUpdateFileAdapter{}, cancelled, id},
		{&SelfUpdateFileAdapter{}, finite, "borrowed"},
		{&SelfUpdateFileAdapter{}, finite, id},
	} {
		if !errors.Is(test.adapter.VerifyCurrentOrdinaryInstallerControllerRole(test.ctx, test.id), ErrOrdinaryInstallerControllerRole) {
			t.Fatal("unproven caller acquired an ordinary current-controller read")
		}
	}
}

func TestOriginalOrdinaryAdapterAccessorSeparatesAbsentAndInvalidJoin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	id := "0123456789abcdef0123456789abcdef"
	if adapter, err := OriginalOrdinaryInstallerControllerAdapter(ctx, id); adapter != nil || err != nil {
		t.Fatal("absent join was conflated with a refused original owner", err)
	}
	for _, value := range []any{"forged", (*ordinaryQuiesceJoin)(nil), &ordinaryQuiesceJoin{}} {
		held := context.WithValue(ctx, ordinaryQuiesceJoinKey{}, value)
		if adapter, err := OriginalOrdinaryInstallerControllerAdapter(held, id); adapter != nil || !errors.Is(err, ErrOrdinaryInstallerControllerRole) {
			t.Fatal("present invalid join enabled fallback", err)
		}
	}
	cancel()
	if adapter, err := OriginalOrdinaryInstallerControllerAdapter(ctx, id); adapter != nil || err == nil {
		t.Fatal("cancelled original owner was accepted")
	}
}

type ordinaryRolePrivateDiagnosticError struct{}

func (ordinaryRolePrivateDiagnosticError) Error() string { panic("private cause text was inspected") }

func TestOrdinaryControllerDiagnosticRetainsOnlyOriginalTypedCause(t *testing.T) {
	private := ordinaryRolePrivateDiagnosticError{}
	failure := ordinaryInstallerRoleAt("facts-closing", errors.Join(private, context.DeadlineExceeded))
	if OrdinaryInstallerControllerFailureStage(failure) != "facts-closing" || !errors.Is(failure, private) ||
		!errors.Is(failure, context.DeadlineExceeded) || !errors.Is(failure, ErrOrdinaryInstallerControllerRole) {
		t.Fatal("original reader stage or causal chain was lost")
	}
	if failure.Error() != "ordinary installer controller observation failed" {
		t.Fatal("diagnostic formatted non-closed cause data")
	}
	if OrdinaryInstallerControllerFailureStage(errors.New("facts-closing private/PID/token")) != "" ||
		OrdinaryInstallerControllerFailureStage(ordinaryInstallerRoleAt("private/PID/token", private)) != "" {
		t.Fatal("unrecognized text became an original observation label")
	}
}
