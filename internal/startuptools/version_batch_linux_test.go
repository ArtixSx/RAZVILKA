//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVersionBatchBoundaryRefusesBorrowedMarkersWithoutFallback(t *testing.T) {
	base, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	l := &Lease{lifetime: base, review: &heldReview{}}
	foreign := &Lease{lifetime: base, review: &heldReview{}}
	o := &toolReadObservation{lease: l, review: l.review, active: true, deadline: time.Now().Add(time.Second)}
	o.self = o
	scoped := context.WithValue(base, toolReadObservationKey{}, o)
	o.ctx = scoped
	for name, source := range map[string]*Lease{"foreign": foreign, "closed": l} {
		if name == "closed" {
			o.active = false
		}
		if err := source.versionBatchBoundary(scoped); !errors.Is(err, ErrUnknown) {
			t.Fatal("unissued marker reached graph fallback", name, err)
		}
	}
	o.active = true
	copy := &toolReadObservation{self: o, lease: l, review: l.review, active: true, deadline: o.deadline, ctx: scoped}
	if err := l.versionBatchBoundary(context.WithValue(base, toolReadObservationKey{}, copy)); !errors.Is(err, ErrUnknown) {
		t.Fatal("copied marker admitted", err)
	}
	cancel()
	if err := l.versionBatchBoundary(scoped); !errors.Is(err, ErrUnknown) {
		t.Fatal("canceled marker admitted", err)
	}
}

func TestVersionReadBatchRejectsForeignAndExpiredInvocation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l := &Lease{review: &heldReview{}, lifetime: ctx}
	b := &versionReadBatch{lease: l, ctx: ctx, active: true}
	b.self = b
	foreign := &Lease{review: &heldReview{}, lifetime: ctx}
	for _, tc := range []struct {
		name  string
		token *versionReadBatch
		ctx   context.Context
		lease *Lease
		index int
	}{
		{"copied", &versionReadBatch{self: b, lease: l, ctx: ctx, active: true}, ctx, l, 0},
		{"expired", &versionReadBatch{lease: l, ctx: ctx}, ctx, l, 0},
		{"foreign-lease", b, ctx, foreign, 0},
		{"foreign-context", b, context.Background(), l, 0},
		{"nil-context", b, nil, l, 0},
		{"out-of-order", b, ctx, l, 1},
		{"non-version-index", b, ctx, l, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.token.read(tc.ctx, tc.lease, tc.index)
			var refused *failure
			if !errors.Is(err, ErrUnknown) || !errors.As(err, &refused) || refused.stage != "VERSION_BATCH_SCOPE" {
				t.Fatal("invocation escaped", err)
			}
		})
	}
	b.active = false
	err := b.read(ctx, l, 0)
	var refused *failure
	if !errors.Is(err, ErrUnknown) || !errors.As(err, &refused) || refused.stage != "VERSION_BATCH_SCOPE" {
		t.Fatal("revoked invocation survived", err)
	}
}

// This is a metadata-only fixture: it cannot acquire or issue any tool lease.
// It verifies that the fixed version batch cannot Start using a changed graph
// even when an attacker restores the bytes and mtime before the final SHA.
func TestVersionBatchMetadataRejectsRestoredMtimeAndMembershipDrift(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("protected metadata requires root")
	}
	for _, change := range []string{"same-bytes-new-ctime", "named-replacement", "new-extension"} {
		t.Run(change, func(t *testing.T) {
			dir := t.TempDir()
			ext := filepath.Join(dir, "extensions")
			if err := os.Mkdir(ext, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "image")
			if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			info, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			extInfo, err := os.Lstat(ext)
			if err != nil {
				t.Fatal(err)
			}
			r := &heldReview{profile: profile{extension: ext}, nodes: map[string]heldNode{path: {path: path, info: info}, ext: {path: ext, info: extInfo}}, images: map[string]*heldImage{path: {path: path, file: file, info: info}}}
			if err := r.retainExtensionPath(ext); err != nil {
				t.Fatal(err)
			}
			if err := r.versionMetadataCurrent(context.Background()); err != nil {
				t.Fatal("baseline", err)
			}
			switch change {
			case "same-bytes-new-ctime":
				if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
					t.Fatal(err)
				}
			case "named-replacement":
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
					t.Fatal(err)
				}
			case "new-extension":
				if err := os.WriteFile(filepath.Join(ext, "unreviewed.so"), []byte("unreviewed"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := r.versionMetadataCurrent(context.Background()); !errors.Is(err, ErrUnknown) {
				t.Fatal("changed graph escaped per-Start proof", err)
			}
		})
	}
}
