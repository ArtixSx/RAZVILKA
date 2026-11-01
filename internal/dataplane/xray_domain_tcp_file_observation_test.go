package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Actual original file inodes only. Non-ELF bytes deliberately cannot issue a
// native resource or process; the tests exercise the read-only file protocol.
func domainFileObservationModel(t *testing.T) (*XrayDomainTCPExecutionResource, context.Context) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private-original-files")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := ownedfs.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	anchor, err := root.RootInfo()
	if err != nil {
		t.Fatal(err)
	}
	configBytes := []byte("original private config")
	config, err := root.WriteAtomicRetained(xrayDomainTCPConfigName, configBytes, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { config.Close() })
	info, err := config.Stat()
	if err != nil {
		t.Fatal(err)
	}
	exeBytes := []byte("original non-ELF file comparison fixture")
	exe, err := root.WriteAtomicRetained("xray", exeBytes, 0700)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { exe.Close() })
	exeInfo, err := exe.Stat()
	if err != nil {
		t.Fatal(err)
	}
	r := &XrayDomainTCPExecutionResource{root: root, rootPath: path, anchor: anchor, config: config, configInfo: info,
		executable: &xrayDomainTCPExecutable{file: exe, info: exeInfo, path: filepath.Join(path, "xray"), sha256: nodeDefaultSourceMaterialHash(exeBytes)},
		definition: ExecutionXrayDomainTCPDefinition{ConfigSHA256: nodeDefaultSourceMaterialHash(configBytes)}}
	r.self = r
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	return r, ctx
}

func TestXrayDomainFileObservationIsOriginalAndSynchronous(t *testing.T) {
	r, ctx := domainFileObservationModel(t)
	var retained *xrayDomainTCPFileObservation
	err := r.withFileObservation(ctx, func(view *xrayDomainTCPFileObservation) error {
		retained = view
		if err := r.filesCurrentForObservation(ctx, view); err != nil {
			return err
		}
		copy := &xrayDomainTCPFileObservation{self: view, resource: r, executable: r.executable, config: r.config, info: r.configInfo, ctx: ctx}
		copy.open.Store(true)
		if err := r.filesCurrentForObservation(ctx, copy); err == nil {
			t.Fatal("copied view admitted")
		}
		other := &XrayDomainTCPExecutionResource{root: r.root, rootPath: r.rootPath, anchor: r.anchor, config: r.config, configInfo: r.configInfo, executable: r.executable, definition: r.definition}
		other.self = other
		if err := other.filesCurrentForObservation(ctx, view); err == nil {
			t.Fatal("view crossed original resource")
		}
		type otherContext struct{}
		if err := r.filesCurrentForObservation(context.WithValue(ctx, otherContext{}, true), view); err == nil {
			t.Fatal("view crossed original observation context")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.filesCurrentForObservation(ctx, retained); err == nil {
		t.Fatal("retired view admitted a later call")
	}
}

func TestXrayDomainFileObservationClosingFullHashRefusesRestoredMetadata(t *testing.T) {
	r, ctx := domainFileObservationModel(t)
	witness := errors.New("actual read callback failed")
	err := r.withFileObservation(ctx, func(view *xrayDomainTCPFileObservation) error {
		file, err := os.OpenFile(r.executable.path, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		if _, err := file.WriteAt([]byte("X"), 0); err != nil {
			file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
		if err := os.Chtimes(r.executable.path, r.executable.info.ModTime(), r.executable.info.ModTime()); err != nil {
			return err
		}
		if err := r.filesCurrentForObservation(ctx, view); err != nil {
			t.Fatal("fixture did not restore original metadata", err)
		}
		return witness
	})
	if !errors.Is(err, witness) || !errors.Is(err, ErrXrayDomainTCPOriginal) {
		t.Fatal("callback error or closing full-byte proof omitted", err)
	}
	if err := r.filesCurrent(ctx); err == nil {
		t.Fatal("independent Current cached an earlier hash")
	}
}

func TestXrayDomainFileObservationRevokesDuringPanic(t *testing.T) {
	r, ctx := domainFileObservationModel(t)
	var retained *xrayDomainTCPFileObservation
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("panic masked")
			}
		}()
		_ = r.withFileObservation(ctx, func(v *xrayDomainTCPFileObservation) error { retained = v; panic("original read panic") })
	}()
	if retained == nil || retained.open.Load() {
		t.Fatal("panic retained a live observation")
	}
	if err := r.filesCurrentForObservation(ctx, retained); err == nil {
		t.Fatal("panic view reused")
	}
}

func TestXrayDomainFileObservationRefusesReboundSameInodeDescriptor(t *testing.T) {
	r, ctx := domainFileObservationModel(t)
	duplicate, err := os.Open(r.executable.path)
	if err != nil {
		t.Fatal(err)
	}
	defer duplicate.Close()
	err = r.withFileObservation(ctx, func(v *xrayDomainTCPFileObservation) error {
		r.executable.file = duplicate
		if err := r.filesCurrentForObservation(ctx, v); err == nil {
			t.Fatal("same-inode descriptor replacement entered original read")
		}
		return nil
	})
	if err == nil {
		t.Fatal("closing read accepted replaced original descriptor")
	}
}

// This model has no Cmd, kernel birth, material or registrar: it cannot grant a
// process read. It tests only the one-use transfer of a completed file opening.
func domainFileOpeningModel(t *testing.T) (*XrayDomainTCPExecutionResource, context.Context, func(), *xrayDomainTCPFileOpening) {
	t.Helper()
	r, ctx := domainFileObservationModel(t)
	if err := r.filesCurrent(ctx); err != nil {
		t.Fatal(err)
	}
	r.child = &xraySelectedTCPProcess{}
	read, closeRead, err := r.processReadContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeRead)
	return r, read, closeRead, r.fileOpeningAfterOriginalRead(read)
}

func TestXrayDomainFileOpeningIsSingleOriginalRead(t *testing.T) {
	r, ctx, closeRead, o := domainFileOpeningModel(t)
	copied := xrayDomainTCPFileOpening{self: o, files: o.files, read: o.read}
	if copied.consume(ctx, r) == nil {
		t.Fatal("copied opening accepted")
	}
	if o.consume(context.Background(), r) == nil {
		t.Fatal("unrelated context accepted")
	}
	other := &XrayDomainTCPExecutionResource{child: r.child}
	other.self = other
	if o.consume(ctx, other) == nil {
		t.Fatal("cross-resource opening accepted")
	}
	type providerKey struct{}
	held := context.WithValue(ctx, providerKey{}, true)
	if err := r.withFileObservationAfterOpening(held, o, func(v *xrayDomainTCPFileObservation) error { return r.filesCurrentForObservation(held, v) }); err != nil {
		t.Fatal(err)
	}
	if o.consume(held, r) == nil {
		t.Fatal("opening replay accepted")
	}
	_, ctx2, close2, o2 := domainFileOpeningModel(t)
	close2()
	if o2.consume(ctx2, o2.files.resource) == nil {
		t.Fatal("retired read opening accepted")
	}
	closeRead()
}

func TestXrayDomainFileOpeningClosingHashRejectsMutationAfterOpening(t *testing.T) {
	r, ctx, _, o := domainFileOpeningModel(t)
	witness := errors.New("actual readonly callback failure")
	err := r.withFileObservationAfterOpening(ctx, o, func(v *xrayDomainTCPFileObservation) error {
		f, err := os.OpenFile(r.executable.path, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		_, writeErr := f.WriteAt([]byte("Y"), 0)
		closeErr := f.Close()
		if writeErr != nil || closeErr != nil {
			return errors.Join(writeErr, closeErr)
		}
		if err := os.Chtimes(r.executable.path, r.executable.info.ModTime(), r.executable.info.ModTime()); err != nil {
			return err
		}
		if err := r.filesCurrentForObservation(ctx, v); err != nil {
			t.Fatal(err)
		}
		return witness
	})
	if !errors.Is(err, witness) || !errors.Is(err, ErrXrayDomainTCPOriginal) {
		t.Fatal("closing proof or original exception omitted", err)
	}
}

func TestXrayDomainFileObservationDerivedViewNeedsLiveParent(t *testing.T) {
	r, ctx := domainFileObservationModel(t)
	r.child = &xraySelectedTCPProcess{}
	scope := &executionResourceScope{}
	r.scope = scope
	r.material = &XrayDomainTCPOperationMaterial{resource: r}
	r.material.self = r.material
	ctx = context.WithValue(ctx, syntheticExecutionRegistrarKey{}, scope)
	if err := r.withFileObservation(ctx, func(parent *xrayDomainTCPFileObservation) error {
		read, closeRead, err := r.processReadContext(ctx)
		if err != nil {
			return err
		}
		defer closeRead()
		nested, closeFiles, err := parent.forOriginalProcessRead(ctx, read, r)
		if err != nil {
			return err
		}
		defer closeFiles()
		if err := nested.current(read, r); err != nil {
			return err
		}
		parent.open.Store(false)
		if nested.current(read, r) == nil {
			t.Fatal("derived view outlived original parent")
		}
		parent.open.Store(true)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
