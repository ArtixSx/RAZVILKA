//go:build linux

package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNFQWSOwnedStopNativeWorker(t *testing.T) {
	role := os.Getenv("RAZVILKA_OWNED_STOP_WORKER")
	if role == "" {
		return
	}
	dir := os.Getenv("RAZVILKA_OWNED_STOP_DIRECTORY")
	if role == "child" {
		for {
			_ = os.WriteFile(filepath.Join(dir, "ticks"), []byte(strconv.FormatInt(time.Now().UnixNano(), 10)), 0600)
			time.Sleep(10 * time.Millisecond)
		}
	}
	if role != "parent" {
		t.Fatal("unknown test worker role")
	}
	child := exec.Command(os.Args[0], "-test.run=^TestNFQWSOwnedStopNativeWorker$", "-test.count=1")
	child.Env = append(os.Environ(), "RAZVILKA_OWNED_STOP_WORKER=child")
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal([]int{os.Getpid(), child.Process.Pid})
	if err := os.WriteFile(filepath.Join(dir, "processes.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	for {
		time.Sleep(time.Second)
	}
}

// Execute the actual Linux owned-stop runner and a foreground shell->child
// tree. This proves command lifetime/cancellation only, not NFQ ownership,
// inactivity, packet behavior or a complete retirement transaction.
func TestNFQWSOwnedStopNativeCancellationJoinsParentAndStopsForegroundChild(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("RAZVILKA_OWNED_STOP_WORKER", "parent")
			t.Setenv("RAZVILKA_OWNED_STOP_DIRECTORY", dir)
			quoted := "'" + strings.ReplaceAll(os.Args[0], "'", "'\\''") + "'"
			script := filepath.Join(dir, "owned-init")
			if err := os.WriteFile(script, []byte("#!/bin/sh\nexec "+quoted+" -test.run=^TestNFQWSOwnedStopNativeWorker$ -test.count=1\n"), 0700); err != nil {
				t.Fatal(err)
			}
			duration := 3 * time.Second
			if mode == "deadline" {
				duration = 2 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), duration)
			defer cancel()
			type result struct {
				out []byte
				err error
			}
			done := make(chan result, 1)
			go func() { out, err := (nfqws2ExecRunner{}).Run(ctx, script, "owned_stop"); done <- result{out, err} }()
			var ids []int
			until := time.Now().Add(1500 * time.Millisecond)
			for time.Now().Before(until) {
				if raw, err := os.ReadFile(filepath.Join(dir, "processes.json")); err == nil && json.Unmarshal(raw, &ids) == nil && len(ids) == 2 {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("native worker did not start before deadline")
				case <-time.After(5 * time.Millisecond):
				}
			}
			if len(ids) != 2 {
				t.Fatal("native worker process identities absent")
			}
			// Open the actual child handle while its identity is known. Cleanup is
			// confined to this test-owned descendant, including unexpected test failure.
			child, err := os.FindProcess(ids[1])
			if err != nil {
				t.Fatal(err)
			}
			defer child.Release()
			defer child.Kill()
			if mode == "cancel" {
				cancel()
			}
			select {
			case got := <-done:
				want := context.Canceled
				if mode == "deadline" {
					want = context.DeadlineExceeded
				}
				if !errors.Is(got.err, want) {
					t.Fatal("native cancellation cause lost", got.err, string(got.out))
				}
			case <-time.After(3 * time.Second):
				t.Fatal("native owned stop did not join bounded parent")
			}
			if _, err := os.Stat(filepath.Join("/proc", strconv.Itoa(ids[0]))); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("original parent was not joined", err)
			}
			stopped := false
			until = time.Now().Add(time.Second)
			for time.Now().Before(until) {
				raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(ids[1]), "stat"))
				if errors.Is(err, os.ErrNotExist) {
					stopped = true
					break
				}
				if err == nil {
					end := strings.LastIndex(string(raw), ") ")
					if end >= 0 && strings.HasPrefix(string(raw[end+2:]), "Z ") {
						stopped = true
						break
					}
				}
				time.Sleep(5 * time.Millisecond)
			}
			if !stopped {
				t.Fatal("foreground child outlived owned process group cancellation")
			}
			before, _ := os.ReadFile(filepath.Join(dir, "ticks"))
			time.Sleep(25 * time.Millisecond)
			after, _ := os.ReadFile(filepath.Join(dir, "ticks"))
			if string(before) != string(after) {
				t.Fatal("canceled child kept executing after runner returned")
			}
		})
	}
}
