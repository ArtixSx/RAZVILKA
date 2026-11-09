//go:build linux && (amd64 || arm64)

package startuptools

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func TestFreshHeldNodeActualMutationAndClosedFileParity(t *testing.T) {
	for _, cut := range []string{"same", "content", "size", "mode", "unlinked", "closed"} {
		t.Run(cut, func(t *testing.T) {
			dir, _ := rootReviewFixture(t)
			path := filepath.Join(dir, "held")
			if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			before, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			switch cut {
			case "content":
				err = os.WriteFile(path, []byte("replaced"), 0600)
			case "size":
				err = os.Truncate(path, 1)
			case "mode":
				err = os.Chmod(path, 0640)
			case "unlinked":
				err = os.Remove(path)
			case "closed":
				err = file.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			current, legacyErr := file.Stat()
			want := legacyErr == nil && sameNode(before, current)
			got, freshErr := freshHeldNode(file, before)
			if got != want || (freshErr == nil) != (legacyErr == nil) {
				t.Fatal("fresh held comparison differs", got, want, freshErr, legacyErr)
			}
			if cut == "closed" && !errors.Is(freshErr, os.ErrClosed) {
				t.Fatal("closed file classification lost", freshErr)
			}
		})
	}
	if got, err := freshHeldNode(nil, nil); got || !errors.Is(err, os.ErrInvalid) {
		t.Fatal("nil held FD admitted", got, err)
	}
}

func TestFreshHeldNodeConcurrentScratchAndCloseNeverReuseFD(t *testing.T) {
	file, err := os.Open("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	expected, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	failures := make(chan error, 16)
	for range 16 {
		group.Add(1)
		go func() {
			defer group.Done()
			for range 100 {
				if same, err := freshHeldNode(file, expected); err != nil || !same {
					failures <- errors.Join(os.ErrInvalid, err)
					return
				}
			}
		}()
	}
	group.Wait()
	close(failures)
	for err := range failures {
		t.Fatal("independent scratch borrowers interfered", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	// Opening another actual file can reuse the OS descriptor number. The old
	// os.File's Control still refuses; no stale naked integer is retained.
	replacement, err := os.Open("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	for range 100 {
		if same, err := freshHeldNode(file, expected); same || !errors.Is(err, os.ErrClosed) {
			t.Fatal("closed original FD adopted replacement", same, err)
		}
	}
}

// Repeated bounded races cover the actual helper versus Close, not only
// concurrent pool users. A result is either the original inode or ErrClosed;
// observing a recycled foreign descriptor would instead produce false/nil.
func TestFreshHeldNodeCloseRacesOriginalControl(t *testing.T) {
	for range 16 {
		file, err := os.Open("/bin/sh")
		if err != nil {
			t.Fatal(err)
		}
		expected, err := file.Stat()
		if err != nil {
			file.Close()
			t.Fatal(err)
		}
		start := make(chan struct{})
		started := make(chan struct{})
		var once sync.Once
		var group sync.WaitGroup
		failures := make(chan error, 4)
		for range 4 {
			group.Add(1)
			go func() {
				defer group.Done()
				<-start
				once.Do(func() { close(started) })
				for range 64 {
					same, err := freshHeldNode(file, expected)
					if err != nil && !errors.Is(err, os.ErrClosed) || err == nil && !same {
						failures <- errors.Join(os.ErrInvalid, err)
						return
					}
				}
			}()
		}
		close(start)
		<-started
		runtime.Gosched()
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		replacement, err := os.Open("/bin/ls")
		if err != nil {
			t.Fatal(err)
		}
		group.Wait()
		close(failures)
		_ = replacement.Close()
		for err := range failures {
			t.Fatal("Close allowed a foreign held comparison", err)
		}
	}
}

func BenchmarkFreshHeldNode(b *testing.B) {
	file, err := os.Open("/bin/sh")
	if err != nil {
		b.Fatal(err)
	}
	defer file.Close()
	expected, err := file.Stat()
	if err != nil {
		b.Fatal(err)
	}
	for _, before := range []bool{true, false} {
		b.Run(map[bool]string{true: "before_fileinfo", false: "after_fstat"}[before], func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var same bool
				var err error
				if before {
					var got os.FileInfo
					got, err = file.Stat()
					same = err == nil && sameNode(expected, got)
				} else {
					same, err = freshHeldNode(file, expected)
				}
				if err != nil || !same {
					b.Fatal("fresh original comparison failed", same, err)
				}
			}
		})
	}
}
