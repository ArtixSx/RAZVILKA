package restorejournal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func TestFileLeaseAdmissionClassificationDoesNotIncludeUnknownMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	f, err := OpenFileTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if other, err := OpenFileTarget(path); !errors.Is(err, ErrBusy) || !RetryableFileAdmission(err) || RetryableFileAdmission(errors.Join(err, ErrRecovery)) {
		if other != nil {
			_ = other.Close()
		}
		t.Fatal("kernel lease refusal is not classified as prewrite", err)
	}
	_ = f.Close()
	marker := filepath.Join(filepath.Dir(path), ".state-"+sum([]byte(filepath.Base(path)))+".lock")
	data, _ := os.ReadFile(marker)
	if err := os.WriteFile(marker, []byte(strings.Repeat("?", len(data))), 0600); err != nil {
		t.Fatal(err)
	}
	if other, err := OpenFileTarget(path); !errors.Is(err, ErrBusy) || RetryableFileAdmission(err) {
		if other != nil {
			_ = other.Close()
		}
		t.Fatal("unknown marker became retryable", err)
	}
}

func TestFileLeaseAdmissionRetryNeverClassifiesUncertainPublication(t *testing.T) {
	f, _ := publicationFixture(t)
	write := f.write
	f.write = func(after Image) error {
		if err := write(after); err != nil {
			return err
		}
		return errors.New("publication succeeded but acknowledgement was lost")
	}
	err := f.CompareAndSwap(context.Background(), content("before"), content("after"))
	got, readErr := f.Read(context.Background())
	if !errors.Is(err, ErrRecovery) || RetryableFileAdmission(err) || readErr != nil || !equal(got, content("after")) {
		t.Fatal("uncertain successful publication was classified as prewrite", err, readErr)
	}
}

func TestTransientKernelAdmissionIOErrorDoesNotChangeExistingMarker(t *testing.T) {
	root, err := ownedfs.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	closeLease, err := acquireNamedLease(root, leaseFile, leaseMarker)
	if err != nil {
		t.Fatal(err)
	}
	closeLease()
	private := errors.New("private syscall details must not be exposed")
	_, err = acquireNamedLeaseWithLock(root, leaseFile, leaseMarker, func(*os.File) error { return private })
	var refusal *leaseLockRefusal
	if !errors.As(err, &refusal) || !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrBusy) || strings.Contains(err.Error(), "private syscall") {
		t.Fatal("non-contention kernel failure misclassified or leaked", err)
	}
	data, readErr := root.ReadLimited(leaseFile, 128)
	if readErr != nil || string(data) != leaseMarker {
		t.Fatal("prewrite refusal changed marker")
	}
	closeLease, err = acquireNamedLease(root, leaseFile, leaseMarker)
	if err != nil {
		t.Fatal("unchanged marker could not be admitted after transient failure", err)
	}
	closeLease()
}
