package nodestore

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestNodeStoreProcessHelper(t *testing.T) {
	path := os.Getenv("RAZVILKA_NODESTORE_CRASH_TEST")
	if path == "" {
		t.Skip("subprocess helper")
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Import(context.Background(), manual, good, testTime, time.Hour, false); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(os.Stdout, "node-store-ready")
	time.Sleep(2 * time.Minute) // Parent kills this process with the lease held.
}

func TestProcessDeathReleasesLeaseAndPreservesAtomicCopy(t *testing.T) {
	path := t.TempDir()
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNodeStoreProcessHelper$")
	cmd.Env = append(os.Environ(), "RAZVILKA_NODESTORE_CRASH_TEST="+path)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(pipe)
		for scanner.Scan() {
			if scanner.Text() == "node-store-ready" {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("child failed before private commit (output suppressed)")
		}
	case <-ctx.Done():
		t.Fatal("child readiness timeout")
	}
	if other, err := Open(path); err == nil {
		other.Close()
		t.Fatal("child lease ignored")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	snap, err := s.Snapshot(context.Background(), testTime)
	if err != nil || len(snap.Nodes) != 1 || snap.Nodes[0].State != "quarantined" {
		t.Fatal("child copy missing or promoted after restart")
	}
}
