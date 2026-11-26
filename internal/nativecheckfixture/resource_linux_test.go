//go:build linux

package nativecheckfixture

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestResourceSampleChild(t *testing.T) {
	raw := os.Getenv("RAZVILKA_RESOURCE_TEST_CHILD_MIB")
	if raw == "" {
		t.Skip("resource observation child only")
	}
	mib, err := strconv.Atoi(raw)
	if err != nil || mib < 1 || mib > 256 {
		t.Fatal("child allocation bound")
	}
	memory := make([]byte, mib<<20)
	for i := 0; i < len(memory); i += 4096 {
		memory[i] = 1
	}
	// Include actual CPU, then retain the touched pages until the test parent
	// closes its original pipe. No serialized PID participates in control.
	until := time.Now().Add(20 * time.Millisecond)
	var sum uint64
	for time.Now().Before(until) {
		for i := 0; i < 10000; i++ {
			sum += uint64(i)
		}
	}
	fmt.Fprintln(os.Stdout, "READY")
	_, _ = io.Copy(io.Discard, os.Stdin)
	runtime.KeepAlive(memory)
	runtime.KeepAlive(sum)
}

func resourceTestChild(t *testing.T, mib int) (*exec.Cmd, io.WriteCloser) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestResourceSampleChild$")
	command.Env = append(os.Environ(), "RAZVILKA_RESOURCE_TEST_CHILD_MIB="+strconv.Itoa(mib))
	in, err := command.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	out, err := command.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		in.Close()
		cancel()
		if command.ProcessState == nil {
			_ = command.Wait()
		}
	})
	if line, err := bufio.NewReader(out).ReadString('\n'); err != nil || line != "READY\n" {
		t.Fatal("real child readiness", line, err)
	}
	return command, in
}

func TestResourceSampleExitDuringProcRead(t *testing.T) {
	child, input := resourceTestChild(t, 1)
	path := fmt.Sprintf("/proc/%d/statm", child.Process.Pid)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	// Hold the open descriptor across the actual exit, then observe its first
	// read and a fresh open separately. The parent joined the child above.
	if _, err := io.ReadAll(file); !procTaskGone(err) {
		t.Fatalf("read after wait: %v", err)
	}
	if _, err := os.Stat(path); !procTaskGone(err) {
		t.Fatalf("stat after wait: %v", err)
	}
}

func TestResourceSampleOnlySkipsVanishedProcTasks(t *testing.T) {
	for _, code := range []error{unix.ENOENT, unix.ESRCH, unix.EACCES, unix.EIO, unix.EINVAL, errors.New("invalid fixture statm")} {
		err := &os.PathError{Op: "read", Path: "/proc/17/statm", Err: code}
		if got, want := procTaskGone(err), code == unix.ENOENT || code == unix.ESRCH; got != want {
			t.Errorf("procTaskGone(%v) = %t, want %t", err, got, want)
		}
	}
}

func TestResourceSampleActualCPUObservedRSSAndPeerExclusion(t *testing.T) {
	peer, _ := resourceTestChild(t, 96)
	_, peerRSS, err := processRSS(peer.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := StartResourceSample()
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(40 * time.Millisecond)
	empty, err := baseline.Stop()
	if err != nil {
		t.Fatal(err)
	}
	if empty.SelfRSSSamples < 2 || empty.SelfPeakRSSKiB <= 0 || empty.ChildrenRSSSamples != 0 || empty.CSV()[6] != "" {
		t.Fatal("preexisting peer became measured child or missing observation fabricated zero", empty)
	}
	sample, err := StartResourceSample()
	if err != nil {
		t.Fatal(err)
	}
	defer sample.Stop()
	child, input := resourceTestChild(t, 16)
	time.Sleep(60 * time.Millisecond)
	input.Close()
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	usage, err := sample.Stop()
	if err != nil {
		t.Fatal(err)
	}
	if usage.ChildrenRSSSamples < 1 || usage.NewChildrenPeakRSSKiB < 16<<10 || usage.NewChildrenPeakRSSKiB >= peerRSS || usage.JoinedChildrenUserMS+usage.JoinedChildrenSystemMS <= 0 {
		t.Fatal("actual child CPU/RSS or peer exclusion missing", usage, "peerRSS", peerRSS)
	}
	if len(usage.CSV()) != len(ResourceCSVHeaders) || usage.Interval != 10*time.Millisecond {
		t.Fatal("resource serialization mismatch", usage)
	}
	again, err := sample.Stop()
	if err != nil || !reflect.DeepEqual(usage, again) {
		t.Fatal("Stop was not idempotent", err)
	}
}
