package dataplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func boundPriorByteModel(read *domainTCPSuccessorRead, old *XrayDomainTCPExecutionResource, c *domainTCPSuccessorByteComparison) *domainTCPPriorByteRead {
	e := old.executable
	p := &domainTCPPriorByteRead{comparison: c, read: read, old: old, executable: e, file: e.file, info: e.info, path: e.path, hash: e.sha256}
	p.self = p
	return p
}

func TestDomainSuccessorBytesBoundPairNeverRebinds(t *testing.T) {
	for _, change := range []string{"old-executable", "old-hash", "old-info", "image-hash", "image-resource", "copied-pair", "phase"} {
		t.Run(change, func(t *testing.T) {
			err := successorByteModel(t, func(ctx context.Context, read *domainTCPSuccessorRead, old *XrayDomainTCPExecutionResource, c *domainTCPSuccessorByteComparison) error {
				p := boundPriorByteModel(read, old, c)
				if err := p.current(ctx); err != nil {
					t.Fatal(err)
				}
				switch change {
				case "old-executable":
					copy := *old.executable
					old.executable = &copy
				case "old-hash":
					old.executable.sha256 = "changed"
				case "old-info":
					info, err := old.executable.file.Stat()
					if err != nil {
						t.Fatal(err)
					}
					old.executable.info = info
				case "image-hash":
					c.image.hash = "changed"
				case "image-resource":
					c.image.resource = old
				case "copied-pair":
					copy := *p
					p = &copy
				case "phase":
					c.image.phase.Store(3)
				}
				if p.current(ctx) == nil {
					t.Fatal("bound pair silently rebound", change)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

type successorByteBlockedContext struct {
	context.Context
	once            sync.Once
	entered, resume chan struct{}
}

func (c *successorByteBlockedContext) Err() error {
	c.once.Do(func() { close(c.entered); <-c.resume })
	return c.Context.Err()
}

func TestDomainSuccessorBytesRevokeJoinsAdmittedReader(t *testing.T) {
	err := successorByteModel(t, func(ctx context.Context, read *domainTCPSuccessorRead, old *XrayDomainTCPExecutionResource, c *domainTCPSuccessorByteComparison) error {
		blocked := &successorByteBlockedContext{Context: ctx, entered: make(chan struct{}), resume: make(chan struct{})}
		read.ctx = blocked
		p := boundPriorByteModel(read, old, c)
		result := make(chan error, 1)
		go func() { result <- p.current(blocked) }()
		<-blocked.entered
		if c.mu.TryLock() {
			c.mu.Unlock()
			close(blocked.resume)
			<-result
			t.Fatal("admitted reader not joined by comparator lock")
		}
		revoking, revoked := make(chan struct{}), make(chan struct{})
		go func() { close(revoking); c.revoke(); close(revoked) }()
		<-revoking
		select {
		case <-revoked:
			t.Fatal("revoke returned while byte reader was admitted")
		default:
		}
		close(blocked.resume)
		readErr := <-result
		<-revoked
		if readErr != nil {
			return readErr
		}
		if p.current(blocked) == nil {
			t.Fatal("reader reused revoked pair")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Real independent held FDs/configs and authenticated bytes, modeled ownership
// links only. These fixtures cannot produce a native listener/Current/effect.
func successorByteModel(t *testing.T, use func(context.Context, *domainTCPSuccessorRead, *XrayDomainTCPExecutionResource, *domainTCPSuccessorByteComparison) error) error {
	t.Helper()
	return domainSuccessorReadModel(t, func(root *domainTCPSuccessorRead, priorScope *XrayDomainTCPExecutionResource) error {
		old, _ := domainFileObservationModel(t)
		old.scope = priorScope.scope
		p := root.process.executable
		file, err := os.Open(p.path)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			t.Fatal(err)
		}
		old.executable = &xrayDomainTCPExecutable{file: file, info: info, path: p.path, sha256: p.sha256}
		var scratch xrayDomainTCPImageScratch
		lease := scratch.borrow(info.Size())
		deadline, _ := root.rootCtx.Deadline()
		image := &xrayDomainTCPImageRead{resource: root.process, executable: p, file: p.file, info: p.info, path: p.path, hash: p.sha256, ctx: root.rootCtx, deadline: deadline, lease: lease}
		image.self = image
		defer image.release()
		if err := image.current(root.rootCtx); err != nil {
			t.Fatal(err)
		}
		comparison := &domainTCPSuccessorByteComparison{active: true, loan: root.loan, image: image}
		comparison.self = comparison
		root.loan.bytes = comparison
		defer comparison.revoke()
		ctx, read, err := root.forPriorContext(root.rootCtx, old)
		if err != nil {
			t.Fatal(err)
		}
		return use(ctx, read, old, comparison)
	})
}

func TestDomainSuccessorBytesIndependentOldFilesAndRevocation(t *testing.T) {
	var escaped *domainTCPSuccessorRead
	var old *XrayDomainTCPExecutionResource
	var ctx context.Context
	err := successorByteModel(t, func(c context.Context, read *domainTCPSuccessorRead, p *XrayDomainTCPExecutionResource, comparison *domainTCPSuccessorByteComparison) error {
		ctx, escaped, old = c, read, p
		if p == read.process || p.executable.file == read.process.executable.file || p.config == read.process.config {
			t.Fatal("independent old owner/FD/config fixture required")
		}
		if err := read.priorFilesCurrent(c, p); err != nil {
			return err
		}
		if err := p.Current(c); err == nil {
			t.Fatal("byte equality minted original process Current")
		}
		comparison.revoke()
		if read.priorFilesCurrent(c, p) == nil {
			t.Fatal("revoked comparator silently fell back")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if escaped.priorFilesCurrent(ctx, old) == nil {
		t.Fatal("escaped pair accepted")
	}
}

func TestDomainSuccessorBytesPreserveOldConfigAndFreshBytes(t *testing.T) {
	for _, change := range []string{"old-config", "rewritten-same-size-mtime", "old-path", "old-FD", "successor-phase", "copied-comparator", "copied-read", "old-context", "successor-context", "old-inode-fallback"} {
		t.Run(change, func(t *testing.T) {
			err := successorByteModel(t, func(ctx context.Context, read *domainTCPSuccessorRead, old *XrayDomainTCPExecutionResource, c *domainTCPSuccessorByteComparison) error {
				if read.priorFilesCurrent(ctx, old) != nil {
					t.Fatal("positive failed before mutation")
				}
				switch change {
				case "old-config":
					if err := os.WriteFile(filepath.Join(old.rootPath, xrayDomainTCPConfigName), bytes.Repeat([]byte{'x'}, int(old.configInfo.Size())), 0600); err != nil {
						t.Fatal(err)
					}
				case "rewritten-same-size-mtime":
					p := old.executable
					if err := os.WriteFile(p.path, bytes.Repeat([]byte{'x'}, int(p.info.Size())), p.info.Mode()); err != nil {
						t.Fatal(err)
					}
					if err := os.Chtimes(p.path, p.info.ModTime(), p.info.ModTime()); err != nil {
						t.Fatal(err)
					}
				case "old-path":
					old.executable.path += ".foreign"
				case "old-FD":
					old.executable.file = old.config
				case "successor-phase":
					c.image.phase.Store(4)
				case "copied-comparator":
					read.loan.bytes = &domainTCPSuccessorByteComparison{self: c, active: true, loan: c.loan, image: c.image}
				case "copied-read":
					copy := *read
					read = &copy
				case "old-context":
					cancelCtx, cancel := context.WithCancel(ctx)
					cancel()
					ctx = cancelCtx
				case "successor-context":
					c.image.ctx = context.Background()
				case "old-inode-fallback":
					other, _ := domainFileObservationModel(t)
					old.executable = other.executable
					if read.priorFilesCurrent(ctx, old) != nil {
						t.Fatal("different-inode original SHA fallback refused")
					}
					if err := os.WriteFile(old.executable.path, bytes.Repeat([]byte{'x'}, int(old.executable.info.Size())), old.executable.info.Mode()); err != nil {
						t.Fatal(err)
					}
					if err := os.Chtimes(old.executable.path, old.executable.info.ModTime(), old.executable.info.ModTime()); err != nil {
						t.Fatal(err)
					}
				}
				if read.priorFilesCurrent(ctx, old) == nil {
					t.Fatal("changed byte/config/ownership accepted", change)
				}
				return nil
			})
			// Deliberate successor-file mutations also invalidate the real outer
			// observation. No successful final admission is claimed in these cases.
			if change != "rewritten-same-size-mtime" && change != "old-path" && change != "old-FD" && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDomainSuccessorBytesPreAddClosesAfterRevoke(t *testing.T) {
	for _, mode := range []string{"clean", "closing-mutation", "callback-error", "panic"} {
		t.Run(mode, func(t *testing.T) {
			process, ctx := domainFileObservationModel(t)
			process.scope = &executionResourceScope{domainSuccessor: &domainTCPGlobalSuccessor{}}
			read := &domainTCPPreAddRead{process: process}
			read.self = read
			loan := &domainTCPPreAddLoan{read: read, ctx: ctx}
			loan.self = loan
			witness := errors.New("pure callback refused")
			var comparison *domainTCPSuccessorByteComparison
			var err error
			func() {
				if mode == "panic" {
					defer func() {
						if recover() == nil {
							t.Fatal("panic disappeared")
						}
					}()
				}
				err = process.withPreAddFileObservation(ctx, loan, func(files *xrayDomainTCPFileObservation) error {
					comparison = loan.bytes
					if comparison == nil || !comparison.active || !comparison.image.captured() {
						t.Fatal("authenticated private image unavailable")
					}
					loan.files = files
					loan.open.Store(true)
					defer loan.open.Store(false)
					switch mode {
					case "closing-mutation":
						p := process.executable
						if err := os.WriteFile(p.path, bytes.Repeat([]byte{'z'}, int(p.info.Size())), p.info.Mode()); err != nil {
							t.Fatal(err)
						}
						if err := os.Chtimes(p.path, p.info.ModTime(), p.info.ModTime()); err != nil {
							t.Fatal(err)
						}
					case "callback-error":
						return witness
					case "panic":
						panic(witness)
					}
					return nil
				})
			}()
			if mode == "clean" && err != nil || mode == "closing-mutation" && err == nil || mode == "callback-error" && !errors.Is(err, witness) {
				t.Fatal(mode, err)
			}
			if comparison == nil || comparison.active || comparison.image.captured() || domainTCPImageScratch.busy.Load() {
				t.Fatal("comparison/image survived outer return")
			}
			if !bytes.Equal(domainTCPImageScratch.data, make([]byte, len(domainTCPImageScratch.data))) {
				t.Fatal("private bytes not cleared")
			}
		})
	}
}
