//go:build linux

package strategylab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type compatibilityFixtureChild struct {
	PID   int
	Birth string
}

// Real process/pipe regression for the coordinator. No Lua, NFQUEUE, service,
// PID namespace, subreaper, package transaction or live network is used.
func TestNFQWSNativeCompatibilityInheritedPipes(t *testing.T) {
	if os.Getenv("RAZVILKA_NFQWS_PROCESS_FIXTURE") != "1" {
		t.Skip("coordinator-only Linux process fixture")
	}
	root := t.TempDir()
	t.Cleanup(func() {
		// A detached child can be reaped by init and its numeric PID reused.
		// Ask only our private fixture to exit; this marker is not a tree receipt.
		if err := os.WriteFile(filepath.Join(root, "release"), nil, 0600); err != nil {
			t.Error(err)
			return
		}
		if _, err := os.Stat(filepath.Join(root, "child.json")); os.IsNotExist(err) {
			return
		} else if err != nil {
			t.Error(err)
			return
		}
		until := time.Now().Add(2 * time.Second)
		for time.Now().Before(until) {
			if _, err := os.Stat(filepath.Join(root, "child.done")); err == nil {
				return // acknowledgement only; descendant quiescence stays unknown
			} else if !os.IsNotExist(err) {
				t.Error(err)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Error("fixture child did not acknowledge release within cleanup bound")
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p := &CompatibilityProcessProvider{}
	started := time.Now()
	completion, err := p.Run(ctx, os.Args[0], "-test.run=^TestNFQWSCompatibilityPipeFixture$", "--", "pipe-parent", root)
	if !completion.Started || completion.Quiescent || !errors.Is(err, ErrCompatibilityQuiescenceUnknown) || !errors.Is(err, exec.ErrWaitDelay) || time.Since(started) > 5*time.Second {
		t.Fatalf("inherited pipes blocked/claimed quiescence: %+v %v", completion, err)
	}
	data, err := os.ReadFile(filepath.Join(root, "child.json"))
	if err != nil {
		t.Fatal(err)
	}
	var child compatibilityFixtureChild
	if err := json.Unmarshal(data, &child); err != nil {
		t.Fatal(err)
	}
	birth, err := compatibilityFixtureBirth(child.PID)
	if err != nil || birth != child.Birth {
		t.Fatalf("fixture descendant identity was lost: birth=%q err=%v", birth, err)
	}
	command, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", child.PID))
	if err != nil || !strings.Contains(string(command), "\x00pipe-child\x00"+root+"\x00") {
		t.Fatalf("fixture descendant command was lost: %v", err)
	}
}

func TestNFQWSCompatibilityPipeFixture(t *testing.T) {
	args := fixtureProcessArguments()
	if len(args) != 2 || (args[0] != "pipe-parent" && args[0] != "pipe-child") {
		t.Skip("process fixture child only")
	}
	if os.Getenv("RAZVILKA_NFQWS_PROCESS_FIXTURE") != "1" {
		t.Fatal("fixture requires coordinator opt-in")
	}
	if args[0] == "pipe-child" {
		defer func() {
			if err := os.WriteFile(filepath.Join(args[1], "child.done"), nil, 0600); err != nil {
				t.Error(err)
			}
		}()
		watchdog := time.NewTimer(20 * time.Second) // bounded even if fixture parent dies
		defer watchdog.Stop()
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			if _, err := os.Stat(filepath.Join(args[1], "release")); err == nil {
				return
			} else if !os.IsNotExist(err) {
				t.Fatal(err)
			}
			select {
			case <-watchdog.C:
				return
			case <-tick.C:
			}
		}
	}
	child := exec.Command(os.Args[0], "-test.run=^TestNFQWSCompatibilityPipeFixture$", "--", "pipe-child", args[1])
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	released := false
	defer func() {
		if !released {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	birth, err := compatibilityFixtureBirth(child.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(compatibilityFixtureChild{PID: child.Process.Pid, Birth: birth})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(args[1], "child.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := child.Process.Release(); err != nil {
		t.Fatal(err)
	}
	released = true // zero exit of direct parent, child keeps its inherited pipes
}

func compatibilityFixtureBirth(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	end := strings.LastIndex(string(data), ")")
	if end < 0 {
		return "", errors.New("invalid process stat")
	}
	fields := strings.Fields(string(data)[end+1:])
	if len(fields) < 20 {
		return "", errors.New("incomplete process stat")
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return "", err
	}
	return fields[19], nil
}
