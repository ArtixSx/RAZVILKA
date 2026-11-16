package dataplane

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

// Actual independent files, modeled local associations only. This cannot
// satisfy an original child, manager operation or live guard.
func domainGuardReadModel(t *testing.T, use func(*domainTCPGuardReadLoan, context.CancelFunc) error) error {
	t.Helper()
	p, parent := domainFileObservationModel(t)
	parent, cancel := context.WithCancel(parent)
	defer cancel()
	m := &Manager{}
	s := &executionResourceScope{manager: m}
	p.scope = s
	binding := &SyntheticDNSExecutionBinding{scope: s}
	mapping := &dnscontrol.SyntheticDNSMapping{}
	p.material = &XrayDomainTCPOperationMaterial{binding: binding, mapping: mapping}
	owner := &DomainTCPOriginalScope{process: p, binding: binding}
	owner.self = owner
	capture := &DomainPolicyTCPCapture{owner: owner, xray: &DomainPolicyTCPXray{resource: p}}
	capture.self = capture
	tools, backend := &SyntheticDNSCommandTools{}, &BackendInventory{}
	r := &domainTCPCaptureExecutionResource{capture: capture, process: p, mapping: mapping, tools: tools, backend: backend}
	r.self = r
	b := &syntheticBaselineExecutionResource{capture: capture, binding: binding, mapping: mapping, tools: tools, backend: backend}
	b.self = b
	owner.capture, owner.captureResource, owner.baseline = capture, r, b
	pool := &domainTCPStandbyPool{manager: m}
	cursor := &domainTCPGlobalSuccessor{scope: s, pool: pool, records: &xraySelectedTCPExecutionRecords{scope: s}}
	cursor.self, s.domainSuccessor = cursor, cursor
	pool.self, pool.successor = pool, cursor
	witness := &domainTCPPoolListenerWitness{cursor: cursor, resource: p}
	witness.self = witness
	cursor.listener.Store(witness)
	parent = context.WithValue(parent, syntheticExecutionRegistrarKey{}, s)
	l := &domainTCPGuardReadLoan{owner: owner, baseline: b, capture: r, process: p, material: p.material, binding: binding, scope: s, mapping: mapping, tools: tools, backend: backend, cursor: cursor, witness: witness, parent: parent}
	l.self = l
	l.ctx = context.WithValue(parent, domainTCPGuardReadKey{}, l)
	var scratch xrayDomainTCPImageScratch
	lease := scratch.borrow(p.executable.info.Size())
	deadline, _ := l.ctx.Deadline()
	image := &xrayDomainTCPImageRead{resource: p, executable: p.executable, file: p.executable.file, info: p.executable.info, path: p.executable.path, hash: p.executable.sha256, ctx: l.ctx, deadline: deadline, lease: lease}
	image.self = image
	return l.observeFiles(image, func(context.Context, *xrayDomainTCPFileObservation) error { return use(l, cancel) })
}

func TestDomainGuardReadCarrierRefusesDrift(t *testing.T) {
	for _, mode := range []string{"copied", "expired", "mixed", "owner", "source", "process", "mapping", "cursor", "witness", "foreign-context", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			err := domainGuardReadModel(t, func(l *domainTCPGuardReadLoan, cancel context.CancelFunc) error {
				if _, err := l.cursor.originalSuccessorRead(l.ctx); err != nil {
					t.Fatal("opening", err)
				}
				ctx := l.ctx
				switch mode {
				case "copied":
					l.self = &domainTCPGuardReadLoan{}
				case "expired":
					l.open.Store(false)
				case "mixed":
					ctx = context.WithValue(ctx, domainTCPPreAddKey{}, &domainTCPPreAddLoan{})
				case "owner":
					l.owner.closed = true
				case "source":
					l.owner.source = &baselineCurrentComparisonRunner{}
				case "process":
					l.capture.process = &XrayDomainTCPExecutionResource{}
				case "mapping":
					l.material.mapping = &dnscontrol.SyntheticDNSMapping{}
				case "cursor":
					l.scope.domainSuccessor = &domainTCPGlobalSuccessor{}
				case "witness":
					l.cursor.listener.Store(&domainTCPPoolListenerWitness{})
				case "foreign-context":
					ctx = context.WithValue(ctx, struct{}{}, true)
				case "cancel":
					cancel()
				}
				if got, err := l.cursor.originalSuccessorRead(ctx); got != nil || err == nil {
					t.Fatal("drift admitted", mode)
				}
				return errors.New("deliberate refused model")
			})
			if err == nil {
				t.Fatal("failed body disappeared")
			}
		})
	}
}

func TestDomainGuardReadClosesAfterBodyAndRevokes(t *testing.T) {
	for _, mode := range []string{"clean", "mutate", "cancel", "body-error"} {
		t.Run(mode, func(t *testing.T) {
			var saved *domainTCPGuardReadLoan
			err := domainGuardReadModel(t, func(l *domainTCPGuardReadLoan, cancel context.CancelFunc) error {
				saved = l
				if l.process.Current(l.ctx) == nil {
					t.Fatal("file model minted process authority")
				}
				if l.ctx.Value(domainTCPPreAddKey{}) != nil {
					t.Fatal("readonly producer minted pre-Add marker")
				}
				switch mode {
				case "mutate":
					p := l.process.executable
					data, err := os.ReadFile(p.path)
					if err != nil {
						return err
					}
					data[len(data)-1] ^= 1
					if err := os.WriteFile(p.path, data, 0700); err != nil {
						return err
					}
					return os.Chtimes(p.path, p.info.ModTime(), p.info.ModTime())
				case "cancel":
					cancel()
				case "body-error":
					return errors.New("body refused")
				}
				return nil
			})
			if (err == nil) != (mode == "clean") {
				t.Fatal("closing outcome", mode, err)
			}
			if saved == nil || saved.open.Load() || saved.current(saved.ctx) == nil || saved.bytes.active || !saved.bytes.image.lease.closed.Load() || saved.bytes.image.lease.scratch.busy.Load() {
				t.Fatal("escaped guard observation remained usable")
			}
			for _, b := range saved.bytes.image.lease.scratch.data {
				if b != 0 {
					t.Fatal("released image was not cleared")
				}
			}
		})
	}
}

func TestDomainGuardReadOldFilesStayIndependent(t *testing.T) {
	for _, mode := range []string{"same", "different-image", "late-change"} {
		t.Run(mode, func(t *testing.T) {
			err := domainGuardReadModel(t, func(l *domainTCPGuardReadLoan, _ context.CancelFunc) error {
				root, err := l.cursor.originalSuccessorRead(l.ctx)
				if err != nil {
					return err
				}
				old, _ := domainFileObservationModel(t)
				old.scope = &executionResourceScope{manager: l.scope.manager}
				if mode != "different-image" {
					e := l.process.executable
					file, err := os.Open(e.path)
					if err != nil {
						return err
					}
					defer file.Close()
					info, err := file.Stat()
					if err != nil {
						return err
					}
					old.executable = &xrayDomainTCPExecutable{file: file, info: info, path: e.path, sha256: e.sha256}
				}
				ctx, read, err := root.forPriorContext(l.ctx, old)
				if err != nil {
					return err
				}
				if err := read.priorFilesCurrent(ctx, old); err != nil {
					return err
				}
				if old.Current(ctx) == nil {
					t.Fatal("shared bytes minted old process Current")
				}
				if mode == "late-change" {
					pair := boundPriorByteModel(read, old, l.bytes)
					old.executable.sha256 = "foreign"
					if pair.current(ctx) == nil {
						t.Fatal("bound old image silently fell back")
					}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDomainGuardReadInvalidMarkersCannotFallback(t *testing.T) {
	var cursor *domainTCPGlobalSuccessor
	for _, value := range []any{true, (*domainTCPGuardReadLoan)(nil), &domainTCPGuardReadLoan{}} {
		ctx := context.WithValue(context.Background(), domainTCPGuardReadKey{}, value)
		if got, err := cursor.originalSuccessorRead(ctx); got != nil || err == nil {
			t.Fatal("invalid marker fell back")
		}
	}
}
