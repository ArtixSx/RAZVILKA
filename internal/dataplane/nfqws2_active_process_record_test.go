package dataplane

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func TestNFQWSActiveLeaseSeparateCompactClosedRecord(t *testing.T) {
	l, _, _ := nfqws2ActiveRunningFixture(t)
	for _, phase := range []string{"none", "provisional", "final"} {
		l.Transfer = phase
		image, err := nfqws2ActiveLeaseImage(l)
		if err != nil {
			t.Fatal(err)
		}
		got, err := nfqws2DecodeActiveLease(image, l.StateRoot, l.Owner)
		if err != nil || !reflect.DeepEqual(l, got) || nfqws2DeclaredLeaseVersion(image) != 3 || nfqws2ActiveProcessSettled(got) {
			t.Fatal("active image roundtrip failed", err)
		}
		if _, err = nfqws2DecodeManagedLease(image, l.StateRoot, l.Owner); err == nil {
			t.Fatal("lease3 became timed2")
		}
	}
	for _, change := range []func(*nfqws2ActiveProcessLease){
		func(l *nfqws2ActiveProcessLease) { l.Version = 2 },
		func(l *nfqws2ActiveProcessLease) { l.Transfer = "active" },
		func(l *nfqws2ActiveProcessLease) { l.Command.ActivationDeadline = l.Command.ActivationDeadline.Add(1) },
		func(l *nfqws2ActiveProcessLease) { l.Command.NetworkIdentity.Inode = 7 },
		func(l *nfqws2ActiveProcessLease) { l.Acknowledged = true },
		func(l *nfqws2ActiveProcessLease) { l.Child = components.NFQWSRuntimeProcessIdentity{} },
		func(l *nfqws2ActiveProcessLease) { l.Receipt.State = "reaped" },
	} {
		copy := l
		change(&copy)
		if nfqws2ValidateActiveLease(copy) == nil {
			t.Fatal("mixed/incomplete active record accepted")
		}
	}
	// SAME8 fields have shape, but the decoded record is not a live owner and
	// must be independently compared to the known command/binding by its owner.
	copy := l
	copy.Binding.PlanID = "dp-0000000000000000"
	if nfqws2ValidateActiveLease(copy) != nil {
		t.Fatal("well-shaped detached binding incorrectly treated as a grant check")
	}
	copy = l
	copy.Receipt.State = "reaped"
	copy.Receipt.DirectReaped = true
	copy.Receipt.WaitECHILD = true
	copy.Receipt.Reaped = 1
	copy.Receipt.ExitCode = 125
	copy.Receipt.Cancelled = true
	copy.Acknowledged = true
	if !nfqws2ActiveProcessSettled(copy) {
		t.Fatal("exact terminal parent ACK refused")
	}
	copy.Receipt.WaitECHILD = false
	if nfqws2ActiveProcessSettled(copy) {
		t.Fatal("absence replaced ECHILD")
	}
	data, _ := json.Marshal(l)
	for _, suffix := range []string{",\"version\":3", ",\"unreviewed\":true"} {
		bad := append(append([]byte{}, data[:len(data)-1]...), []byte(suffix+"}")...)
		if _, err := nfqws2DecodeActiveLease(restorejournal.Image{Exists: true, Data: bad}, l.StateRoot, l.Owner); err == nil {
			t.Fatal("duplicate/unknown lease field accepted")
		}
	}
}
