package updatecheck

import (
	"context"
	"errors"
	"testing"
	"time"
)

func bootstrapRoleFixture(t *testing.T) (fileReview, updateRecord, fileHelperIdentity, fileCommandReceipt, []bootstrapControllerFact) {
	t.Helper()
	_, u, review := bootstrapOwnerFixture(t)
	record := u.record
	record.Job.State, record.Job.CanApply, record.Job.CanCancel, record.Job.ReviewToken = "restarting", false, false, ""
	record.Job.HelperPID, record.ParentPID = 20, 21
	helper := fileProcess{Boot: "01234567-89ab-cdef-0123-456789abcdef", PID: 20, Start: "10", ExecutableSHA256: reviewedHelperSHA(review), Device: 1, Inode: 2}
	panel := helper
	panel.PID, panel.Start, panel.Inode, panel.ExecutableSHA256 = 21, "11", 3, review.OldExecutableSHA256
	identity := fileHelperIdentity{selfUpdateProtocolSchema, review.ID, helper, panel}
	supervisor := helper
	supervisor.PID, supervisor.Start = 22, "12"
	child := helper
	child.PID, child.Start = 23, "13"
	command := fileCommandReceipt{Schema: selfUpdateProtocolSchema, ID: review.ID, Command: "quiesce-old-runtime", State: "running", Parent: helper, Supervisor: supervisor, DirectPID: child.PID}
	return review, record, identity, command, []bootstrapControllerFact{
		{helper, 1, []string{"candidate", "self-update-bootstrap-old193", review.ID, review.Bootstrap.ArchivePath, review.Bootstrap.ArchiveSHA256}},
		{supervisor, helper.PID, []string{"control.bin", "self-update-command-helper", review.ID, "quiesce-old-runtime"}},
		{child, supervisor.PID, []string{"control.bin", "self-update-runtime-quiesce", review.ID, bootstrapDecimal(review.Revision), "22"}},
	}
}

func TestBootstrapControllerRolesUseSealedGroupAndExactCommand(t *testing.T) {
	review, record, identity, command, facts := bootstrapRoleFixture(t)
	for i, role := range []string{externalOld193InstallerRole, "quiesce-supervisor", "quiesce-child"} {
		if got := bootstrapControllerRole(review, record, identity, command, facts[i]); got != role {
			t.Fatal(i, got)
		}
	}
	// Neither a different path nor a distinct inode hides an unclassified
	// controller. argv[0] alone grants nothing; an exact role still needs birth.
	for _, name := range []string{"razvilka", "renamed-controller", "control.bin"} {
		unknown := facts[0]
		unknown.Args = append([]string(nil), unknown.Args...)
		unknown.Args[0] = name
		unknown.Process.PID, unknown.Process.Start, unknown.Process.Inode = 24, "14", 999
		if bootstrapControllerRole(review, record, identity, command, unknown) != "" {
			t.Fatal("unsealed outer controller borrowed the installer role")
		}
	}
}

func TestBootstrapControllerRolesRefuseColdOuterChildAndUnjoinedEvidence(t *testing.T) {
	for _, kind := range []string{"cold-start", "outer-parent", "child-parent", "supervisor-parent", "source-as-helper", "reused-birth", "wrong-review-id", "wrong-job", "changed-archive", "wrong-revision", "wrong-worker", "armed", "reaped", "completed", "can-apply", "review-token", "panel-as-helper", "unknown-command"} {
		t.Run(kind, func(t *testing.T) {
			review, record, identity, command, facts := bootstrapRoleFixture(t)
			fact := facts[2]
			switch kind {
			case "cold-start":
				fact.Args = []string{"razvilka", "-config", "/opt/etc/razvilka/config.json"}
			case "outer-parent":
				fact = facts[0]
				fact.Process.PID, fact.Process.Start, fact.Process.Inode = 24, "14", 99
			case "child-parent":
				fact.Parent = 99
			case "supervisor-parent":
				fact = facts[1]
				fact.Parent = 99
			case "source-as-helper":
				fact.Process.ExecutableSHA256 = review.OldExecutableSHA256
			case "reused-birth":
				fact = facts[1]
				fact.Process.Start = "88"
			case "wrong-review-id":
				review.ID = "ffffffffffffffffffffffffffffffff"
			case "wrong-job":
				record.Job.HelperPID = 99
			case "changed-archive":
				fact = facts[0]
				fact.Args = append([]string(nil), fact.Args...)
				fact.Args[4] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			case "wrong-revision":
				fact.Args[3] = "999"
			case "wrong-worker":
				fact.Args[4] = "99"
			case "armed", "reaped":
				command.State = kind
				if kind == "reaped" {
					command.Reaped, command.WaitECHILD = 1, true
				}
			case "completed":
				record.Job.State = "completed"
			case "can-apply":
				record.Job.CanApply = true
			case "review-token":
				record.Job.ReviewToken = "borrowed"
			case "panel-as-helper":
				identity.OldPanel = identity.Process
			case "unknown-command":
				command.Command = "start-candidate-panel"
			}
			if bootstrapControllerRole(review, record, identity, command, fact) != "" {
				t.Fatal("unclassified controller received an installer role")
			}
		})
	}
}

func TestBootstrapControllerRoleAPIRequiresOriginalFiniteLiveContext(t *testing.T) {
	a, _, review := bootstrapOwnerFixture(t)
	for _, ctx := range []context.Context{nil, context.Background()} {
		if !errors.Is(a.VerifyInstallerControllerRole(ctx, review.ID, 20), ErrInstallerControllerRole) {
			t.Fatal("missing finite owner context was accepted")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	cancel()
	if !errors.Is(a.VerifyInstallerControllerRole(ctx, review.ID, 20), ErrInstallerControllerRole) {
		t.Fatal("expired controller role remained usable")
	}
}
