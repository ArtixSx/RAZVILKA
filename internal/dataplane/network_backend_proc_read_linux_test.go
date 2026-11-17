//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBackendInventoryProcReadRefusals(t *testing.T) { checkBackendInventoryProcReadRefusals(t) }

func checkBackendInventoryProcReadRefusals(t *testing.T) {
	for _, limit := range []int{4096, 1 << 20} {
		for _, size := range []int{0, 1, limit - 1, limit, limit + 1} {
			input := bytes.Repeat([]byte{0x5a}, size)
			pos, calls := 0, 0
			got, err := backendInventoryReadProcBounded(context.Background(), limit, func(p []byte) (int, error) {
				calls++
				n := min(len(p), min(37, len(input)-pos))
				copy(p, input[pos:pos+n])
				pos += n
				return n, nil
			})
			if size <= limit {
				if err != nil || !bytes.Equal(got, input) || calls < 1 {
					t.Fatal("short/EOF changed", size, err)
				}
			} else if err == nil || got != nil {
				t.Fatal("limit+1 accepted")
			}
		}
	}
	for _, cut := range []string{"eintr", "eintr-minus-one", "eagain", "eagain-minus-one", "cancel-eintr", "cancel-eof", "error", "invalid-negative", "invalid-size"} {
		t.Run(cut, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			got, err := backendInventoryReadProcBounded(ctx, 4096, func(p []byte) (int, error) {
				calls++
				switch cut {
				case "eintr":
					if calls <= 3 {
						return 0, unix.EINTR
					}
					return 0, nil
				case "eintr-minus-one":
					if calls <= 3 {
						return -1, unix.EINTR
					}
					return 0, nil
				case "eagain":
					return 0, unix.EAGAIN
				case "eagain-minus-one":
					return -1, unix.EAGAIN
				case "cancel-eintr":
					cancel()
					return 0, unix.EINTR
				case "cancel-eof":
					cancel()
					return 0, nil
				case "error":
					return 0, unix.EIO
				case "invalid-negative":
					return -1, nil
				default:
					return len(p) + 1, nil
				}
			})
			if cut == "eintr" || cut == "eintr-minus-one" {
				if err != nil || len(got) != 0 || calls != 4 {
					t.Fatal("EINTR contract", err, calls)
				}
			} else if err == nil || got != nil || calls != 1 {
				t.Fatal("failure lost", cut, err, calls)
			}
		})
	}
}

func TestBackendInventoryProcReadFDKeepsCallerOwnership(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "leaf-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	wanted := []byte("bounded proc-like fixture\n")
	if _, err := file.Write(wanted); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	fd := int(file.Fd())
	got, err := backendInventoryReadProcFD(context.Background(), fd, 4096)
	if err != nil || !bytes.Equal(got, wanted) {
		t.Fatal("read", err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		t.Fatal("reader closed caller FD", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err := backendInventoryReadProcFD(context.Background(), fd, 4096); got != nil || !errors.Is(err, unix.EBADF) {
		t.Fatal("closed descriptor error lost", err)
	}
}

func TestBackendInventoryProcReadInvalidEntryDoesNotRead(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, row := range []struct {
		ctx   context.Context
		limit int
	}{{nil, 4096}, {context.Background(), 0}, {context.Background(), -1}, {context.Background(), (1 << 20) + 1}, {canceled, 4096}} {
		calls := 0
		got, err := backendInventoryReadProcBounded(row.ctx, row.limit, func([]byte) (int, error) { calls++; return 0, nil })
		if got != nil || err == nil || calls != 0 {
			t.Fatal("invalid read entered", calls, err)
		}
	}
	if got, err := backendInventoryReadProcBounded(context.Background(), 4096, nil); got != nil || err == nil {
		t.Fatal("nil reader accepted")
	}
}

func TestBackendInventoryProcReadScratchIsolation(t *testing.T) {
	var workers sync.WaitGroup
	for worker := 0; worker < 12; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for iteration := 0; iteration < 20; iteration++ {
				wanted := bytes.Repeat([]byte{byte(worker + 1)}, 137+iteration)
				calls := 0
				got, err := backendInventoryReadProcBounded(context.Background(), 4096, func(p []byte) (int, error) {
					calls++
					if calls == 1 {
						if !bytes.Equal(p, make([]byte, len(p))) {
							t.Error("previous invocation's proc bytes exposed")
						}
						return copy(p, wanted), nil
					}
					return 0, nil
				})
				if err != nil || !bytes.Equal(got, wanted) {
					t.Errorf("concurrent detached read: %v", err)
					return
				}
				// A failed following read must neither expose old scratch bytes
				// nor corrupt the previous caller's still-retained result.
				failed, err := backendInventoryReadProcBounded(context.Background(), 4096, func(p []byte) (int, error) {
					if !bytes.Equal(p, make([]byte, len(p))) {
						t.Error("scratch was not cleared after successful return")
					}
					for i := range p {
						p[i] = 0xff
					}
					return 0, unix.EIO
				})
				if failed != nil || !errors.Is(err, unix.EIO) || !bytes.Equal(got, wanted) {
					t.Error("failure or retained result changed")
					return
				}
			}
		}()
	}
	workers.Wait()
}

func TestBackendInventoryProcReadScratchNested(t *testing.T) {
	calls := 0
	wanted := []byte("outer proc result remains owned until copied")
	got, err := backendInventoryReadProcBounded(context.Background(), 4096, func(p []byte) (int, error) {
		calls++
		if calls != 1 {
			return 0, nil
		}
		n := copy(p, wanted)
		innerCalls := 0
		inner, innerErr := backendInventoryReadProcBounded(context.Background(), 4096, func(q []byte) (int, error) {
			innerCalls++
			if innerCalls != 1 {
				return 0, nil
			}
			return copy(q, "independent nested read"), nil
		})
		if innerErr != nil || string(inner) != "independent nested read" || !bytes.Equal(p[:n], wanted) {
			t.Fatal("nested read borrowed still-live scratch", innerErr)
		}
		return n, nil
	})
	if err != nil || !bytes.Equal(got, wanted) {
		t.Fatal("outer result changed", err)
	}
}
