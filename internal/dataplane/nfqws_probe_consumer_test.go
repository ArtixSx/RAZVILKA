package dataplane

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/strategylab"
)

func TestNFQWSProbeUnversionedConfigurationIsKnownBeforeEffect(t *testing.T) {
	c := &ManagedNFQWSProbeConsumer{}
	c.self = c
	lease := &components.ManagedNFQWSRuntimeLease{}
	_, completed, err := c.Execute(context.Background(), &strategylab.CandidateProbeReview{}, &strategylab.ManagedProbeEpoch{}, lease, catalog.Service{}, 0, func(context.Context) error {
		t.Fatal("unversioned configuration reached source or effects")
		return nil
	})
	if !errors.Is(err, ErrNFQWSScopedOwner) || completed == nil || completed.runtime != lease || c.Pending() {
		t.Fatal("pre-effect refusal retained unknown resources", completed, err)
	}
}

func TestNFQWSProbeConsumerRejectsDetachedOwnersAndCompletionCopies(t *testing.T) {
	if c, err := NewManagedNFQWSProbeConsumer(New(t.TempDir()), &NetworkPolicyAdapter{}, &BackendInventory{}, &operationgate.ControlEpochReview{}, "unreviewed", netidentity.NewProcProvider(), context.Background()); err == nil || c != nil {
		t.Fatal("detached owners supplied consumer")
	}
	var zero ManagedNFQWSProbeConsumer
	if zero.OwnsContext(context.Background()) || zero.ScopeCurrent(context.Background(), "") == nil {
		t.Fatal("zero consumer admitted")
	}
	completion := newManagedNFQWSProbeCompletion(&components.ManagedNFQWSRuntimeLease{})
	forged := ManagedNFQWSProbeCompletion{self: completion, runtime: completion.runtime}
	if forged.CloseRuntime() == nil || completion.closed {
		t.Fatal("copy retired runtime")
	}
	var empty ManagedNFQWSProbeCompletion
	if empty.CloseRuntime() == nil {
		t.Fatal("zero completion granted runtime release")
	}
}

func TestNFQWSProbeExpectedScopeCloseNeverErasesNativeExceptions(t *testing.T) {
	if !nfqwsProbeOnlyPending(errors.Join(errNFQWSProbeScopeRetained, errNFQWSProbeScopeRetained), 0) {
		t.Fatal("own expected carrier refused")
	}
	for _, err := range []error{ErrNFQWSManagedProcessUnknown, errors.Join(ErrNFQWSManagedProcessUnknown, errNFQWSProbeScopeRetained), errors.Join(context.Canceled, errNFQWSProbeScopeRetained), errors.New("helper native failure")} {
		if nfqwsProbeOnlyPending(err, 0) {
			t.Fatal("native exception erased", err)
		}
	}
}

func TestNFQWSProbeKnownCleanupRetainsOwnerOnDescriptorFailure(t *testing.T) {
	c := &ManagedNFQWSProbeConsumer{}
	c.self = c
	e := &nfqwsProbeExecution{consumer: c, socket: &nfqwsProbeSocketOwner{}}
	e.self = e
	e.open.Store(true)
	c.active = e
	// Explicit descriptor-failure model, not a native resource or cleanup grant.
	if e.finishKnown() == nil || !e.open.Load() || c.active != e {
		t.Fatal("failed descriptor close released original owner")
	}
	e.socket = nil
	e.entered.Store(true)
	if e.finishKnown() == nil || c.active != e {
		t.Fatal("unknown entered COMMON released original owner")
	}
}

func TestNFQWSProbeCounterParserRejectsForeignQueueAndRows(t *testing.T) {
	base := "Chain RZP_012345678901234567_4 (1 references)\n pkts bytes target prot opt in out source destination\n 12 1024 NFQUEUE tcp -- * * 192.168.1.1 8.8.8.8 tcp spt:35001 dpt:443 mark match 0x0 NFQUEUE num 200\n"
	chain := "RZP_012345678901234567_4"
	if count, err := nfqwsProbeParseCounter([]byte(base), chain); err != nil || count != 12 {
		t.Fatal(count, err)
	}
	for _, bad := range []string{strings.Replace(base, "num 200", "num 2000", 1), strings.Replace(base, " 12 1024", " 12K 1024", 1), strings.Replace(base, "NFQUEUE tcp", "ACCEPT tcp", 1), base + " 1 20 ACCEPT all -- * * 0.0.0.0/0 0.0.0.0/0\n", strings.Replace(base, chain, "FOREIGN", 1)} {
		if _, err := nfqwsProbeParseCounter([]byte(bad), chain); err == nil {
			t.Fatal("untrusted counter accepted", bad)
		}
	}
}

func TestNFQWSProbeReadbackIncludesSourcePort(t *testing.T) {
	a := []string{"-A", "RZP_owned", "-s", "192.168.1.1/32", "-d", "8.8.8.8/32", "-p", "tcp", "-m", "tcp", "--sport", "35001", "--dport", "443", "-m", "mark", "--mark", "0x0/0xffffffff", "-j", "NFQUEUE", "--queue-num", "200"}
	b := []string{"-A", "RZP_owned", "-s", "192.168.1.1/32", "-d", "8.8.8.8/32", "-p", "tcp", "-m", "mark", "--mark", "0x0/0xffffffff", "-m", "tcp", "--sport", "35001", "--dport", "443", "-j", "NFQUEUE", "--queue-num", "200"}
	if !nfqwsScopedRuleEqual(a, b) {
		t.Fatal("canonical exact socket selector rejected")
	}
	b[11] = "0x0" // xtables -S omits the equivalent all-bits mask.
	if !nfqwsScopedRuleEqual(a, b) {
		t.Fatal("canonical default full mark mask rejected")
	}
	b[15] = "35002"
	if nfqwsScopedRuleEqual(a, b) {
		t.Fatal("changed source port inherited exact rule proof")
	}
}
