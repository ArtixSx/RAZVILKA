//go:build linux && razvilka_native_fixture

package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDomainPreparationMeasurementNativeSourceParity(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "policy_effect_receipt.go"))
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.ReplaceAll(string(data), "\r\n", "\n"))
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "receipt.go", data, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, declaration := range f.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "saveOriginal" {
			continue
		}
		found = true
		body := data[fset.Position(fn.Body.Pos()).Offset:fset.Position(fn.Body.End()).Offset]
		digest := sha256.Sum256(body)
		if hex.EncodeToString(digest[:]) != "67e401e6313f85d14d70c3c5239b39c63e9557a4bd8fdbfe0e3f2fb2df3f18ab" {
			t.Fatal("original writer body changed, including its close-error defer")
		}
		if len(fn.Type.Results.List) != 1 || len(fn.Type.Results.List[0].Names) != 1 || fn.Type.Results.List[0].Names[0].Name != "result" {
			t.Fatal("original named result changed")
		}
	}
	if !found {
		t.Fatal("original writer missing")
	}
}

type preparationMeasurementContext struct{ context.Context }

func (c preparationMeasurementContext) Err() error {
	panic("diagnostic must not call context Err")
}
func (c preparationMeasurementContext) Done() <-chan struct{} {
	DomainTCPNativePreparationMeasurementSnapshot()
	return c.Context.Done()
}
func (c preparationMeasurementContext) Deadline() (time.Time, bool) {
	DomainTCPNativePreparationMeasurementSnapshot()
	return c.Context.Deadline()
}

type preparationMeasurementError struct{}

func (preparationMeasurementError) Error() string {
	return "private-path-or-error-must-not-be-recorded"
}
func (preparationMeasurementError) Is(target error) bool {
	panic("diagnostic must not call error Is")
}

type preparationInterruptedContext struct {
	context.Context
	errorsRead int
	interrupt  func()
}

func (c *preparationInterruptedContext) Err() error {
	c.errorsRead++
	if c.errorsRead == 1 {
		c.interrupt() // Recorder never calls Err; this is the original save.
	}
	return nil
}

func TestDomainPreparationMeasurementNativeLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx = preparationMeasurementContext{ctx}
	r := &domainTCPCaptureExecutionResource{}
	stop := StartDomainTCPNativePreparationMeasurement(ctx)
	t.Cleanup(func() { stop() })
	m := domainTCPMeasurePreparation(r, "apply-effects", -1)
	if got := DomainTCPNativePreparationMeasurementSnapshot(); len(got.Stages) != 1 || got.Stages[0].Completed {
		t.Fatal("missing in-flight row")
	}
	err := preparationMeasurementError{}
	if m.end(err) != err {
		t.Fatal("error identity changed")
	}
	m.end(nil) // once: later completion must not replace first failure.
	late := domainTCPMeasurePreparation(r, "post-add-comparison", -1)
	first := stop()
	if len(first.Stages) != 2 || !first.Stages[0].Completed || !first.Stages[0].ReturnedError || first.Stages[1].Completed {
		t.Fatal(first)
	}
	if !first.Stages[0].HasParentDeadline || first.Stages[0].ParentRemainingStart <= 0 {
		t.Fatal("deadline not recorded")
	}
	data, _ := json.Marshal(first)
	if strings.Contains(string(data), err.Error()) {
		t.Fatal("private error leaked")
	}
	first.Stages[0].Stage = "changed-copy"
	if stop().Stages[0].Stage != "apply-effects" {
		t.Fatal("snapshot aliases recorder")
	}
	stop2 := StartDomainTCPNativePreparationMeasurement(ctx)
	defer stop2()
	late.end(context.DeadlineExceeded)
	if len(DomainTCPNativePreparationMeasurementSnapshot().Stages) != 0 {
		t.Fatal("late completion contaminated next generation")
	}
	cancel()
	m2 := domainTCPMeasurePreparation(r, "apply-effects", -1)
	m2.end(context.DeadlineExceeded)
	got := stop2().Stages[0]
	if !got.ParentCanceledStart || !got.ParentCanceledFinish {
		t.Fatal(got)
	}
}

func TestDomainPreparationMeasurementNativeBounds(t *testing.T) {
	stop := StartDomainTCPNativePreparationMeasurement(context.Background())
	t.Cleanup(func() { stop() })
	r := &domainTCPCaptureExecutionResource{}
	for _, label := range []string{"foreign", "/private/path", "save-intent"} {
		domainTCPMeasurePreparation(r, label, -1).end(nil)
	}
	if len(DomainTCPNativePreparationMeasurementSnapshot().Stages) != 0 {
		t.Fatal("unknown label/index admitted")
	}
	var workers sync.WaitGroup
	for n := 0; n < 128; n++ {
		workers.Add(1)
		go func() { defer workers.Done(); domainTCPMeasurePreparation(r, "apply-effects", -1).end(nil) }()
	}
	workers.Wait()
	got := stop()
	if len(got.Stages) != 96 || got.Dropped != 32 {
		t.Fatal(len(got.Stages), got.Dropped)
	}
	for _, row := range got.Stages {
		if !row.Completed {
			t.Fatal("lost concurrent completion")
		}
	}
	stop = StartDomainTCPNativePreparationMeasurement(context.Background())
	defer stop()
	for n := 0; n < 9; n++ {
		domainTCPMeasurePreparation(&domainTCPCaptureExecutionResource{}, "apply-effects", -1).end(nil)
	}
	got = stop()
	if len(got.Stages) != 8 || got.Dropped != 1 {
		t.Fatal("resource bound", len(got.Stages), got.Dropped)
	}
}

func TestDomainPreparationMeasurementNativeRecordsIndependentMappingClosings(t *testing.T) {
	stop := StartDomainTCPNativePreparationMeasurement(context.Background())
	defer stop()
	r := &domainTCPCaptureExecutionResource{}
	const stage = "capture-mapping-preparation-closing"
	first := domainTCPMeasurePreparation(r, stage, -1)
	if err := first.end(nil); err != nil {
		t.Fatal(err)
	}
	second := domainTCPMeasurePreparation(r, stage, -1)
	got := DomainTCPNativePreparationMeasurementSnapshot()
	if len(got.Stages) != 2 || !got.Stages[0].Completed || got.Stages[1].Completed {
		t.Fatal("closing intervals were not independent", got)
	}
	if got.Stages[0].FinishedOffset > got.Stages[1].StartedOffset || got.Stages[0].Resource != got.Stages[1].Resource {
		t.Fatal("mapping closing intervals overlapped or changed owner", got)
	}
	second.end(context.Canceled)
	closed := stop()
	if !closed.Stages[1].ReturnedError {
		t.Fatal("interrupted closing was not recorded", closed)
	}
}

func TestDomainPreparationMeasurementNativeWriterAndCommand(t *testing.T) {
	stop := StartDomainTCPNativePreparationMeasurement(context.Background())
	defer stop()
	ctx, cancel := context.WithCancel(context.Background())
	r := &domainTCPCaptureExecutionResource{}
	read := &domainTCPPreAddRead{capture: r}
	read.self = read
	s := &policyEffectSession{domainPreAdd: read, policyAdditionSession: &policyAdditionSession{}}
	s.doc.Steps = make([]policyAdditionStep, 7)
	for n := range s.doc.Steps {
		s.doc.Steps[n].State = "planned"
	}
	for n, stage := range []string{"save-initial", "save-intent", "save-added"} {
		if n == 1 {
			s.doc.Steps[0].State = "intent"
		}
		if n == 2 {
			s.doc.Steps[0].State = "added"
		}
		domainTCPMeasurePreparationSave(s).end(nil)
		rows := DomainTCPNativePreparationMeasurementSnapshot().Stages
		if rows[len(rows)-1].Stage != stage {
			t.Fatal(rows)
		}
	}
	// Actual save entry refuses canceled ctx before publication. The wrapper
	// preserves its original error, not a diagnostic error or success sentinel.
	s.borrow = &policyEffectReceiptBorrow{}
	cancel()
	if err := s.save(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	m := domainTCPMeasurePreparationCommand(&domainTCPCaptureEffectRunner{resource: r}, "command-run")
	payload := []byte{1, 2}
	got, err := m.bytes(payload, context.DeadlineExceeded)
	if err != context.DeadlineExceeded || &got[0] != &payload[0] {
		t.Fatal("runner return changed")
	}
	rows := DomainTCPNativePreparationMeasurementSnapshot().Stages
	last := rows[len(rows)-1]
	if last.Index != -1 || !last.ReturnedError {
		t.Fatal(last)
	}
	// Actual save panic propagates; no named-zero result is labeled success.
	before := len(rows)
	func() {
		defer func() {
			if recover() == nil {
				t.Error("original panic lost")
			}
		}()
		s.save(&preparationInterruptedContext{Context: context.Background(), interrupt: func() { panic("original save interrupted") }})
	}()
	rows = DomainTCPNativePreparationMeasurementSnapshot().Stages
	if len(rows) != before+1 || rows[len(rows)-1].Completed {
		t.Fatal("panic marked successful")
	}
	// Goexit also propagates through the actual save wrapper without invoking
	// the explicit completion call or manufacturing a nil return.
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.save(&preparationInterruptedContext{Context: context.Background(), interrupt: runtime.Goexit})
	}()
	<-done
	rows = stop().Stages
	if rows[len(rows)-1].Completed {
		t.Fatal("Goexit marked successful")
	}
}
