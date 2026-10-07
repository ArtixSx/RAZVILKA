package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func nfqws2ActiveCommandFixture(t *testing.T) (nfqws2ActiveProcessCommand, NFQWSScopedSpec, NFQWSExecutionBinding) {
	t.Helper()
	_, lease := nfqws2ManagedRecordFixture(t)
	_, spec := nfqwsScopedTypedSpec(t, netidentity.ReviewedSingleInitNet)
	c := lease.Command
	command := nfqws2ActiveProcessCommand{Version: 1, Mode: nfqws2ActiveProcessMode, ID: c.ID, StateRoot: c.StateRoot,
		Owner: c.Owner, ControlRoot: c.ControlRoot, InstallationID: c.InstallationID, Sequence: c.Sequence,
		Program: c.Program, Assets: c.Assets, Args: []string{"--intercept=1", "--qnum=40321", "--filter-udp=443", "--lua-desync=fake:blob=0x00000000"},
		Parent: c.Parent, NetworkIdentity: *spec.NetworkIdentity, ActivationDeadline: time.Now().Add(10 * time.Second).UTC()}
	spec.SessionID, spec.CommandSHA256 = command.ID, nfqws2ActiveCommandDigest(command)
	spec.Candidate.ArgumentsSHA256 = components.NFQWSRuntimeArgumentsSHA256(command.Program.Path, command.Args)
	binding := NFQWSExecutionBinding{ExecutionID: "dp-1123456789abcdef", PlanID: "dp-0123456789abcdef", PlanDigest: strings.Repeat("b", 64),
		ResourceID: "nq-" + strings.Repeat("c", 32), ResourceGeneration: strings.Repeat("d", 64), EffectsDigest: strings.Repeat("e", 64),
		SessionID: command.ID, CommandSHA256: spec.CommandSHA256}
	return command, spec, binding
}

func TestNFQWSActiveCommandSeparateClosedSchemaAndImmutableIdentity(t *testing.T) {
	command, spec, binding := nfqws2ActiveCommandFixture(t)
	if nfqws2ValidateActiveCommand(command) != nil || nfqws2ActiveCommandMatchesSpec(command, spec) != nil || !nfqws2ActiveBindingValid(binding, command) {
		t.Fatal("valid active metadata refused")
	}
	canary := binding
	canary.ExecutionID = "dp-check-" + strings.Repeat("1", 32)
	if nfqws2ActiveBindingValid(canary, command) {
		t.Fatal("temporary health/canary reservation became ordinary active binding")
	}
	wire, err := json.Marshal(command)
	decoded, decodeErr := nfqws2ActiveCommandDecode(wire)
	if err != nil || decodeErr != nil || !reflect.DeepEqual(decoded, command) {
		t.Fatal("active canonical typed identity roundtrip failed", err, decodeErr)
	}
	clone := decoded.clone()
	clone.Args[0] = "ALTERED"
	if command.Args[0] != "--intercept=1" || decoded.Args[0] != "--intercept=1" {
		t.Fatal("active command clone aliases immutable argv")
	}
	if nfqws2ActiveCommandDigest(command) == nfqws2ManagedCommandDigest(command.fileShape()) {
		t.Fatal("active command shares a timed command digest")
	}
	for _, change := range []func(*nfqws2ActiveProcessCommand){
		func(c *nfqws2ActiveProcessCommand) { c.Version = 2 },
		func(c *nfqws2ActiveProcessCommand) { c.Mode = "timed" },
		func(c *nfqws2ActiveProcessCommand) { c.ActivationDeadline = time.Time{} },
		func(c *nfqws2ActiveProcessCommand) { c.NetworkIdentity.Inode = 55 },
		func(c *nfqws2ActiveProcessCommand) { c.NetworkIdentity.PlatformReviewSHA256 = strings.Repeat("a", 64) },
		func(c *nfqws2ActiveProcessCommand) { c.NetworkIdentity.BootID = "11234567-89ab-cdef-0123-456789abcdef" },
	} {
		copy := command.clone()
		change(&copy)
		if nfqws2ValidateActiveCommand(copy) == nil || nfqws2ActiveCommandDigest(copy) != "" {
			t.Fatal("unknown/mixed active metadata accepted")
		}
	}
	for _, suffix := range []string{",\"Deadline\":\"2030-01-01T00:00:00Z\"", ",\"mode\":\"manager-active-v1\""} {
		changed := append(append([]byte{}, wire[:len(wire)-1]...), []byte(suffix+"}")...)
		if _, err := nfqws2ActiveCommandDecode(changed); err == nil {
			t.Fatal("old lifetime field or folded duplicate entered active schema")
		}
	}
	for _, args := range [][]string{
		{"--intercept=1", "--qnum=40321", "@unreviewed-config"},
		{"--intercept=1", "--qnum=40321", "--qnum=40322"},
		{"--intercept=1", "--qnum=40321", "-qnum=40321"},
		{"--intercept=1", "--qnum=40321", "--daemon"},
	} {
		copy := command.clone()
		copy.Args = args
		altered := spec.Clone()
		altered.CommandSHA256 = nfqws2ActiveCommandDigest(copy)
		altered.Candidate.ArgumentsSHA256 = components.NFQWSRuntimeArgumentsSHA256(copy.Program.Path, copy.Args)
		if nfqws2ActiveCommandMatchesSpec(copy, altered) == nil {
			t.Fatal("unreviewed positional/alias/global argv passed active Start metadata")
		}
	}
}

func TestNFQWSActiveActivationCannotDetachOriginalCancellationOrReplayExpiry(t *testing.T) {
	command, _, _ := nfqws2ActiveCommandFixture(t)
	type valueKey struct{}
	original, cancelOriginal := context.WithTimeout(context.WithValue(context.Background(), valueKey{}, "same-review"), time.Second)
	bounded, cancel, err := nfqws2ActiveActivationContext(original, command)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	want, _ := original.Deadline()
	got, _ := bounded.Deadline()
	if got != want || bounded.Value(valueKey{}) != "same-review" {
		t.Fatal("active activation replaced original deadline or review values")
	}
	cancelOriginal()
	if !errors.Is(bounded.Err(), context.Canceled) {
		t.Fatal("precommit activation detached original cancellation")
	}
	command.ActivationDeadline = time.Now().Add(-time.Second).UTC()
	if nfqws2ValidateActiveCommand(command) != nil || nfqws2ActiveCommandDigest(command) == "" {
		t.Fatal("static active metadata could not survive activation deadline")
	}
	if _, _, err := nfqws2ActiveActivationContext(context.Background(), command); err == nil {
		t.Fatal("expired metadata reconstructed activation authority")
	}
	command.ActivationDeadline = time.Now().Add(16 * time.Second).UTC()
	if _, _, err := nfqws2ActiveActivationContext(context.Background(), command); err == nil {
		t.Fatal("active schema extended activation beyond accepted 15s")
	}
}

func TestNFQWSActiveFramesCannotBecomeTimedPermissionOrForeignFinalACK(t *testing.T) {
	command, _, binding := nfqws2ActiveCommandFixture(t)
	helper := components.NFQWSSupervisionIdentity{BootID: command.Parent.BootID, Start: "200", PID: 2000, Group: 2000}
	base, err := nfqws2ActiveFrameBase(command, binding, helper)
	if err != nil {
		t.Fatal(err)
	}
	child := components.NFQWSRuntimeProcessIdentity{BootID: helper.BootID, Start: "201", PID: 2001, ParentPID: helper.PID,
		Group: 2001, Executable: command.Program.Path, ArgumentsSHA256: components.NFQWSRuntimeArgumentsSHA256(command.Program.Path, command.Args)}
	for _, kind := range []string{"ready", "permit", "started", "transfer", "transfer-ack", "finalize", "active"} {
		frame := base
		frame.Kind = kind
		if kind != "ready" && kind != "permit" {
			frame.Child = child
		}
		wire, err := json.Marshal(frame)
		decoded, decodeErr := nfqws2ActiveFrameDecode(wire)
		if err != nil || decodeErr != nil || decoded != frame || nfqws2ActiveExpectedFrame(command, base, decoded, kind, frame.Child) != nil {
			t.Fatal("closed active wire roundtrip refused", kind)
		}
		if _, err := nfqws2ManagedStartDecode(wire); err == nil {
			t.Fatal("active v2 wire became timed v1 launch permission")
		}
	}
	want := base
	want.Kind, want.Child = "active", child
	for _, change := range []func(*nfqws2ActiveFrame){
		func(f *nfqws2ActiveFrame) { f.Version = 1 },
		func(f *nfqws2ActiveFrame) { f.Kind = "transfer-ack" },
		func(f *nfqws2ActiveFrame) { f.Binding.ExecutionID = "foreign-execution" },
		func(f *nfqws2ActiveFrame) { f.Binding.CommandSHA256 = strings.Repeat("f", 64) },
		func(f *nfqws2ActiveFrame) { f.NetworkIdentity.Kind = netidentity.ProcNetInode },
		func(f *nfqws2ActiveFrame) { f.Helper.Start = "202" },
		func(f *nfqws2ActiveFrame) { f.Child.ParentPID++ },
	} {
		altered := want
		change(&altered)
		if nfqws2ActiveExpectedFrame(command, base, altered, "active", child) == nil {
			t.Fatal("provisional/foreign/mixed wire ACK became final transfer proof")
		}
	}
	private := errors.New("private-control-payload")
	err = nfqws2ActiveFailure("transfer ACK", private)
	if strings.Contains(err.Error(), private.Error()) || !errors.Is(err, private) || !errors.Is(err, ErrNFQWSManagedProcessUnknown) {
		t.Fatal("active diagnostics printed private payload or lost cause identity")
	}
}
