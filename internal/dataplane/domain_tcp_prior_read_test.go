package dataplane

import (
	"context"
	"errors"
	"os"
	"testing"
)

// Real independent held files with modeled local associations. No process,
// listener, prior receipt or kernel authority can be produced by this model.
func domainPriorReadModel(t *testing.T, use func(*domainTCPPriorReadLoan, *domainTCPSuccessorRead, context.CancelFunc) error) error {
	t.Helper()
	p, ctx, cancel := domainPriorFileResourceModel(t)
	defer cancel()
	s, cursor := p.scope, p.scope.domainSuccessor
	witness := cursor.listener.Load()
	l := &domainTCPPriorReadLoan{cursor: cursor, witness: witness, process: p, material: p.material, child: p.child, ctx: ctx}
	l.self = l
	var scratch xrayDomainTCPImageScratch
	lease := scratch.borrow(p.executable.info.Size())
	deadline, _ := ctx.Deadline()
	image := &xrayDomainTCPImageRead{resource: p, executable: p.executable, file: p.executable.file, info: p.executable.info, path: p.executable.path, hash: p.executable.sha256, ctx: ctx, deadline: deadline, lease: lease}
	image.self = image
	// The real publisher can hold both locks. The byte carrier must never
	// reenter them; native authority still belongs to the unchanged readers.
	s.mu.Lock()
	p.mu.Lock()
	defer s.mu.Unlock()
	defer p.mu.Unlock()
	return l.observeFiles(image, func(read *domainTCPSuccessorRead) error { return use(l, read, cancel) })
}

func domainPriorFileResourceModel(t *testing.T) (*XrayDomainTCPExecutionResource, context.Context, context.CancelFunc) {
	t.Helper()
	p, ctx := domainFileObservationModel(t)
	ctx, cancel := context.WithCancel(ctx)
	m := &Manager{}
	s := &executionResourceScope{manager: m, ctx: ctx}
	p.scope, p.records = s, &xraySelectedTCPExecutionRecords{scope: s}
	p.material = &XrayDomainTCPOperationMaterial{resource: p}
	p.material.self = p.material
	p.child = &xraySelectedTCPProcess{done: make(chan struct{})}
	p.child.self = p.child
	pool := &domainTCPStandbyPool{manager: m}
	cursor := &domainTCPGlobalSuccessor{scope: s, pool: pool, records: p.records}
	cursor.self, s.domainSuccessor = cursor, cursor
	pool.self, pool.successor = pool, cursor
	witness := &domainTCPPoolListenerWitness{cursor: cursor, resource: p, process: p.child, ctx: ctx}
	witness.self = witness
	cursor.listener.Store(witness)
	return p, ctx, cancel
}

func TestDomainPriorReadKeepsIndependentPriorBytesAndOriginalContext(t *testing.T) {
	for _, mode := range []string{"same", "different-image", "old-mutation"} {
		t.Run(mode, func(t *testing.T) {
			err := domainPriorReadModel(t, func(l *domainTCPPriorReadLoan, root *domainTCPSuccessorRead, _ context.CancelFunc) error {
				old, _ := domainFileObservationModel(t)
				old.scope = &executionResourceScope{manager: l.cursor.pool.manager}
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
				if ctx.Value(syntheticExecutionRegistrarKey{}) != old.scope {
					t.Fatal("prior lost its original scope context")
				}
				if err := read.priorFilesCurrent(ctx, old); err != nil {
					return err
				}
				if l.witness.currentWithSuccessorRead(ctx, old, read) == nil {
					t.Fatal("file model fabricated native witness authority")
				}
				if mode == "old-mutation" {
					body, err := os.ReadFile(old.executable.path)
					if err != nil {
						return err
					}
					body[len(body)-1] ^= 1
					if err := os.WriteFile(old.executable.path, body, 0700); err != nil {
						return err
					}
					if err := os.Chtimes(old.executable.path, old.executable.info.ModTime(), old.executable.info.ModTime()); err != nil {
						return err
					}
					if err := read.priorFilesCurrent(ctx, old); !errors.Is(err, ErrXrayDomainTCPOriginal) {
						t.Fatal("prior bytes were not independently reread", err)
					}
				}
				return nil
			})
			if (err == nil) != (mode != "old-mutation") {
				t.Fatal("closing result", err)
			}
		})
	}
}

func TestDomainPriorReadRefusesDriftAndRevokesBeforeJournalContinuation(t *testing.T) {
	for _, mode := range []string{"clean", "copy", "closed", "foreign-context", "witness", "cursor", "process", "material", "joined", "cancel", "mixed", "body-error", "mutate", "panic"} {
		t.Run(mode, func(t *testing.T) {
			var saved *domainTCPPriorReadLoan
			var savedRead *domainTCPSuccessorRead
			run := func() (result error) {
				defer func() {
					if recovered := recover(); recovered != nil {
						if mode != "panic" {
							panic(recovered)
						}
						result = errors.New("expected model panic")
					}
				}()
				return domainPriorReadModel(t, func(l *domainTCPPriorReadLoan, read *domainTCPSuccessorRead, cancel context.CancelFunc) error {
					saved, savedRead = l, read
					ctx := l.ctx
					switch mode {
					case "copy":
						copy := *read
						read = &copy
					case "closed":
						l.open.Store(false)
					case "foreign-context":
						ctx = context.WithValue(ctx, struct{}{}, true)
					case "witness":
						l.cursor.listener.Store(&domainTCPPoolListenerWitness{})
					case "cursor":
						l.process.scope.domainSuccessor = &domainTCPGlobalSuccessor{}
					case "process":
						l.witness.resource = &XrayDomainTCPExecutionResource{}
					case "material":
						l.process.material = &XrayDomainTCPOperationMaterial{}
					case "joined":
						close(l.child.done)
					case "cancel":
						cancel()
					case "mixed":
						read.guard = &domainTCPGuardReadLoan{}
					case "body-error":
						return errors.New("body refused")
					case "mutate":
						p := l.process.executable
						body, err := os.ReadFile(p.path)
						if err != nil {
							return err
						}
						body[0] ^= 1
						if err := os.WriteFile(p.path, body, 0700); err != nil {
							return err
						}
						return os.Chtimes(p.path, p.info.ModTime(), p.info.ModTime())
					case "panic":
						panic("expected model panic")
					}
					if err := read.rootCurrent(ctx); (err == nil) != (mode == "clean") {
						t.Fatalf("drift result %s: %v", mode, err)
					}
					if mode != "clean" {
						return errors.New("expected refused model")
					}
					return nil
				})
			}
			err := run()
			if (err == nil) != (mode == "clean") {
				t.Fatalf("closing result %s: %v", mode, err)
			}
			if saved == nil || saved.open.Load() || saved.current(saved.ctx) == nil || savedRead.rootCurrent(saved.ctx) == nil || saved.bytes.active || !saved.bytes.image.lease.closed.Load() || saved.bytes.image.lease.scratch.busy.Load() {
				t.Fatal("prior view survived its comparison")
			}
			for _, b := range saved.bytes.image.lease.scratch.data {
				if b != 0 {
					t.Fatal("released private image was not cleared")
				}
			}
		})
	}
}
