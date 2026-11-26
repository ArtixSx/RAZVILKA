package dataplane

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func (f *firstStartFixture) bootContext(t *testing.T, allow *bool) context.Context {
	t.Helper()
	ctx := WithRecoveryReview(firstStartContext(t), func(Plan) error {
		if !*allow {
			return ErrReviewChanged
		}
		return nil
	})
	return ctx
}

func (f *firstStartFixture) simulateBoot(t *testing.T) {
	t.Helper()
	f.running, f.ownedRules = false, false
	f.boot = "22345678-1234-1234-1234-123456789abc"
	f.a.inactivity = &NFQWSRuntimeInactiveSource{identity: netidentity.Identity{Version: 1, Kind: netidentity.ProcNetInode, BootID: f.boot, Inode: 1}}
	// These are modelled kernel observations. Real production construction binds
	// the protected provider and full collector; no native proof is claimed here.
	_ = os.Remove(f.a.firstStartPIDPath())
	_ = os.Remove(f.a.ConfigPath + ".run")
}

func TestNFQWS2FirstStartCommittedBootRequiresCurrentIntentAndFreshAbsence(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	f := newFirstStartFixture(t)
	f.apply(t)
	before, err := f.a.readLease()
	if err != nil {
		t.Fatal(err)
	}
	init := readText(t, f.a.InitPath)
	f.simulateBoot(t)
	allow := true
	if result, err := f.m.Recover(f.bootContext(t, &allow)); err != nil {
		t.Fatal("committed recovery", result, err)
	}
	after, err := f.a.readLease()
	if err != nil || after == nil || after.FirstStart.Process.BootID != f.boot || after.FirstStart.Process.BootID == before.FirstStart.Process.BootID || !f.running {
		t.Fatal("new controlled boot receipt missing", err)
	}
	if readText(t, f.a.InitPath) != init {
		t.Fatal("boot changed the stable inert init")
	}
	if err := f.a.Deactivate(firstStartContext(t)); err != nil {
		t.Fatal(err)
	}
	f.assertStopped(t)
}

func TestNFQWS2FirstStartUpgradeQuiesceResumesOnlyCurrentAppliedIntent(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	for _, allow := range []bool{true, false} {
		t.Run(map[bool]string{true: "upgrade", false: "user-stop"}[allow], func(t *testing.T) {
			f := newFirstStartFixture(t)
			f.apply(t)
			if err := f.a.Deactivate(firstStartContext(t)); err != nil {
				t.Fatal(err)
			}
			f.a.inactivity = &NFQWSRuntimeInactiveSource{identity: netidentity.Identity{Version: 1, Kind: netidentity.ProcNetInode, BootID: f.boot, Inode: 1}}
			start := len(f.calls)
			enabled := allow
			result, err := f.m.Recover(f.bootContext(t, &enabled))
			if allow {
				if err != nil || !f.running {
					t.Fatal("upgrade left the applied runtime stopped", result, err)
				}
			} else {
				if err == nil || f.running {
					t.Fatal("user Stop was bypassed", result, err)
				}
				for _, call := range f.calls[start:] {
					if firstStartRuntimeAction(call) {
						t.Fatal("revoked applied intent reached a runtime action", call)
					}
				}
			}
		})
	}
}

func TestNFQWS2FirstStartBootNeverAdoptsLiveOrUnknownIntent(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	for _, which := range []string{"no-review", "foreign-live", "starting", "same-boot-dead-rules"} {
		t.Run(which, func(t *testing.T) {
			f := newFirstStartFixture(t)
			f.apply(t)
			f.simulateBoot(t)
			if which == "foreign-live" {
				f.foreign = true
			}
			if which == "same-boot-dead-rules" {
				f.boot = "12345678-1234-1234-1234-123456789abc"
				f.a.inactivity.identity.BootID = f.boot
				f.ownedRules = true
			}
			if which == "starting" {
				lease, err := f.a.readLease()
				if err != nil {
					t.Fatal(err)
				}
				lease.FirstStart.Phase = nfqws2FirstStarting
				lease.FirstStart.Process = nil
				if err := f.a.writeLease(lease); err != nil {
					t.Fatal(err)
				}
			}
			ctx := firstStartContext(t)
			if which != "no-review" {
				enabled := true
				ctx = f.bootContext(t, &enabled)
			}
			start := len(f.calls)
			if _, err := f.m.Recover(ctx); err == nil {
				t.Fatal("unreviewed or unknown state recovered")
			}
			for _, call := range f.calls[start:] {
				if firstStartRuntimeAction(call) {
					t.Fatal("unknown runtime changed", call)
				}
			}
		})
	}
}

func TestNFQWS2FirstStartBootCancellationAfterReceiptCleansNewOwnedRuntime(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	f := newFirstStartFixture(t)
	f.apply(t)
	f.simulateBoot(t)
	allowed := true
	ctx, cancel := context.WithCancel(f.bootContext(t, &allowed))
	defer cancel()
	f.a.firstStartReceiptReady = cancel
	if _, err := f.m.Recover(ctx); err == nil {
		t.Fatal("post-receipt cancellation lost")
	}
	if f.running || f.ownedRules {
		t.Fatal("cancelled boot left its new confirmed runtime active")
	}
	f.assertStopped(t)
	if f.a.firstStartReview != nil {
		t.Fatal("cancelled recovery retained component writer")
	}
}

func TestNFQWS2FirstStartBootAmbiguousLaunchRetainsStartingFence(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	f := newFirstStartFixture(t)
	f.apply(t)
	f.simulateBoot(t)
	f.ambiguous = true
	allow := true
	start := len(f.calls)
	if _, err := f.m.Recover(f.bootContext(t, &allow)); err == nil {
		t.Fatal("ambiguous boot succeeded")
	}
	lease, err := f.a.readLease()
	if err != nil || lease == nil || lease.FirstStart.Phase != nfqws2FirstStarting {
		t.Fatal("ambiguous boot fence lost", err)
	}
	for _, call := range f.calls[start:] {
		if strings.HasSuffix(call, " owned_stop") {
			t.Fatal("ambiguous boot child was guessed as owned")
		}
	}
}

func TestNFQWS2FirstStartBootGuardChecksOriginalWholePlan(t *testing.T) {
	if firstStartNamespace(t) {
		return
	}
	f := newFirstStartFixture(t)
	f.apply(t)
	f.simulateBoot(t)
	allowed := true
	committed, exists, err := f.m.Committed()
	if err != nil || !exists {
		t.Fatal(err)
	}
	ctx, err := f.m.reviewedRecoveryContext(f.bootContext(t, &allowed), committed)
	if err != nil {
		t.Fatal(err)
	}
	changed := committed
	changed.Routes = nil
	lease, err := f.a.readLease()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.a.checkFirstStartBootReview(ctx, changed, lease); !errors.Is(err, ErrReviewChanged) {
		t.Fatal("subset borrowed full-plan grant", err)
	}
}
