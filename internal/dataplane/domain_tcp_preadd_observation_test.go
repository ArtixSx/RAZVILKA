package dataplane

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
)

func TestDomainPreAddGenericSequenceRetainsIntentOnEachFailure(t *testing.T) {
	for _, failAt := range []string{"presence-1", "guard-1", "presence-2", "guard-2"} {
		t.Run(failAt, func(t *testing.T) {
			f := newPolicyEffectFixture(t)
			witness := errors.New("readonly original observation failed")
			var order []string
			active, presence, guards := false, 0, 0
			f.options.fault = func(phase string, index int) error {
				if phase == "intent" && index == 0 {
					active = true
				}
				return nil
			}
			f.runtime.ExactPresence = func(ctx context.Context, index int) (int, error) {
				if !active {
					t.Fatal("presence preceded durable intent")
				}
				presence++
				name := "presence-1"
				if presence == 2 {
					name = "presence-2"
				}
				order = append(order, name)
				if name == failAt {
					return 0, witness
				}
				return 0, nil
			}
			f.runtime.Guard = func(ctx context.Context, index int) error {
				if !active {
					return nil
				}
				guards++
				name := "guard-1"
				if guards == 2 {
					name = "guard-2"
				}
				order = append(order, name)
				if name == failAt {
					return witness
				}
				return nil
			}
			err := f.apply()
			if !errors.Is(err, witness) || !errors.Is(err, ErrPolicyAdditionUnknown) || len(f.calls) != 0 || f.read(t).Steps[0].State != "intent" {
				t.Fatal("failure lost its exception, executed Add or erased intent", err, f.calls)
			}
			want := []string{"presence-1", "guard-1", "presence-2", "guard-2"}
			for i, step := range want {
				if step == failAt {
					want = want[:i+1]
					break
				}
			}
			if !reflect.DeepEqual(order, want) {
				t.Fatal("readonly call order changed", order)
			}
			if errors.Is(err, ErrPolicyAdditionReceipt) != (failAt == "presence-1") {
				t.Fatal("presence classification changed", err)
			}
		})
	}
}

func domainPreAddFileLoan(t *testing.T, ctx context.Context, process *XrayDomainTCPExecutionResource, use func(context.Context, *syntheticBaselineExecutionResource, *domainTCPPreAddLoan) error) error {
	t.Helper()
	baseline := &syntheticBaselineExecutionResource{}
	read := &domainTCPPreAddRead{baseline: baseline, process: process}
	read.self = read
	loan := &domainTCPPreAddLoan{read: read}
	loan.self = loan
	loan.ctx = context.WithValue(ctx, domainTCPPreAddKey{}, loan)
	return process.withFileObservation(loan.ctx, func(files *xrayDomainTCPFileObservation) error {
		loan.files = files
		loan.open.Store(true)
		defer loan.open.Store(false)
		return use(loan.ctx, baseline, loan)
	})
}

func TestDomainPreAddLoanRejectsForeignAndEscapedReaders(t *testing.T) {
	process, ctx := domainFileObservationModel(t)
	var saved context.Context
	var original *syntheticBaselineExecutionResource
	err := domainPreAddFileLoan(t, ctx, process, func(scoped context.Context, baseline *syntheticBaselineExecutionResource, loan *domainTCPPreAddLoan) error {
		saved, original = scoped, baseline
		read := func(files *xrayDomainTCPFileObservation) error {
			return process.filesCurrentForObservation(scoped, files)
		}
		if err := withDomainTCPPreAddFiles(scoped, process, baseline, nil, false, read); err != nil {
			return err
		}
		called := false
		deny := func(*xrayDomainTCPFileObservation) error { called = true; return nil }
		for _, input := range []struct {
			ctx      context.Context
			baseline *syntheticBaselineExecutionResource
		}{
			{scoped, &syntheticBaselineExecutionResource{}},
			{context.WithValue(scoped, struct{}{}, true), baseline},
		} {
			if err := withDomainTCPPreAddFiles(input.ctx, process, input.baseline, nil, false, deny); err == nil || called {
				t.Fatal("foreign original read accepted", err)
			}
		}
		// A file-only model cannot mint a successful source/child Current.
		if err := withDomainTCPPreAddFiles(scoped, process, baseline, nil, true, deny); err == nil || called {
			t.Fatal("file loan manufactured source Current", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	if err := withDomainTCPPreAddFiles(saved, process, original, nil, false, func(*xrayDomainTCPFileObservation) error { called = true; return nil }); err == nil || called {
		t.Fatal("escaped read fell back to full path", err)
	}
	// No marker: independent generic callers retain complete-byte fallback.
	if err := withDomainTCPPreAddFiles(ctx, process, original, nil, false, func(files *xrayDomainTCPFileObservation) error { return process.filesCurrentForObservation(ctx, files) }); err != nil {
		t.Fatal("independent generic path changed", err)
	}
}

func TestDomainPreAddLoanClosingRejectsLateByteMutation(t *testing.T) {
	process, ctx := domainFileObservationModel(t)
	witness := errors.New("last original source callback failed")
	err := domainPreAddFileLoan(t, ctx, process, func(scoped context.Context, baseline *syntheticBaselineExecutionResource, _ *domainTCPPreAddLoan) error {
		for range 4 {
			if err := withDomainTCPPreAddFiles(scoped, process, baseline, nil, false, func(files *xrayDomainTCPFileObservation) error {
				return process.filesCurrentForObservation(scoped, files)
			}); err != nil {
				return err
			}
		}
		f, err := os.OpenFile(process.executable.path, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		_, writeErr := f.WriteAt([]byte("X"), 0)
		if err := errors.Join(writeErr, f.Close()); err != nil {
			return err
		}
		if err := os.Chtimes(process.executable.path, process.executable.info.ModTime(), process.executable.info.ModTime()); err != nil {
			return err
		}
		return witness
	})
	if !errors.Is(err, witness) || !errors.Is(err, ErrXrayDomainTCPOriginal) {
		t.Fatal("closing mutation or original exception escaped", err)
	}
}

func TestDomainPreAddLoanCancellationRevokesFurtherReads(t *testing.T) {
	process, original := domainFileObservationModel(t)
	ctx, cancel := context.WithCancel(original)
	defer cancel()
	err := domainPreAddFileLoan(t, ctx, process, func(scoped context.Context, baseline *syntheticBaselineExecutionResource, _ *domainTCPPreAddLoan) error {
		cancel()
		called := false
		err := withDomainTCPPreAddFiles(scoped, process, baseline, nil, false, func(*xrayDomainTCPFileObservation) error { called = true; return nil })
		if err == nil || called {
			t.Fatal("cancelled loan accepted read", err)
		}
		return err
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancel lost", err)
	}
}

func TestDomainPreAddCanceledEntryPreservesCause(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	read := &domainTCPPreAddRead{}
	if err := read.current(ctx, PolicyEffectRuntime{}, PolicyEffectPlan{}, ""); !errors.Is(err, context.Canceled) {
		t.Fatal("entry Current swallowed cancellation", err)
	}
	if err := read.observe(ctx, nil, PolicyEffectRuntime{}, 0); !errors.Is(err, context.Canceled) || !errors.Is(err, ErrPolicyAdditionUnknown) {
		t.Fatal("entry observation swallowed cancellation/fence", err)
	}
}
