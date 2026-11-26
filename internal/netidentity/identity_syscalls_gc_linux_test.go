//go:build linux && (amd64 || arm64)

package netidentity

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"testing"
)

// Exercise the actual pointer-bearing identity syscalls under concurrent GC.
// This targets a native test's GC failure; it cannot prove that failure's cause
// or turn any observation into a cached process/network identity.
func TestIdentitySyscallsConcurrentGC(t *testing.T) {
	fd, err := syscall.Open("/proc", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	expected := strconv.Itoa(os.Getpid())
	release, machine, ok := kernelTuple()
	if !ok {
		t.Fatal("actual kernel tuple unavailable")
	}
	failures := make(chan error, 8)
	var joined sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		joined.Add(1)
		go func() {
			defer joined.Done()
			for iteration := 0; iteration < 128; iteration++ {
				if iteration%16 == 0 {
					runtime.GC()
				}
				got, ok := linkAt(fd, "self")
				if !ok || got != expected {
					failures <- fmt.Errorf("actual proc self changed: %q, %t", got, ok)
					return
				}
				r, m, ok := kernelTuple()
				if !ok || r != release || m != machine {
					failures <- fmt.Errorf("actual kernel tuple changed")
					return
				}
			}
		}()
	}
	joined.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
}
