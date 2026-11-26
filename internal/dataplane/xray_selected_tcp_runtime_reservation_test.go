package dataplane

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestXraySelectedTCPRuntimeReservedWaitOwnsActualStartAndSingleJoin(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(filepath.Clean(binary), "-test.run=^TestXraySelectedTCPRuntimeChild$")
	cmd.Dir = t.TempDir()
	cmd.Env = []string{"RAZVILKA_XRAY_WAIT_HELPER=1", "RAZVILKA_XRAY_WAIT_EXIT=0"}
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	p, err := reserveXraySelectedTCPProcessWait(xrayRuntimeFinite(t), cmd)
	if err != nil {
		t.Fatal(err)
	}
	started := false
	t.Cleanup(func() {
		_ = input.Close()
		if !started {
			_ = p.abandonUnstartedWait()
			return
		}
		if p.child == nil {
			_ = p.acknowledgeStart()
		}
		if !p.waitStarted {
			_ = p.beginReservedWait()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if p.Joined(ctx) != nil {
			_ = cmd.Process.Kill()
			<-p.done
		}
	})
	if p.acknowledgeStart() == nil || p.beginReservedWait() == nil {
		t.Fatal("unstarted Cmd acquired native ACK")
	}
	if _, err := reserveXraySelectedTCPProcessWait(xrayRuntimeFinite(t), cmd); err == nil {
		t.Fatal("duplicate pre-Start Wait owner")
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	started = true
	line, err := bufio.NewReader(output).ReadString('\n')
	if err != nil || line != "ready\n" {
		t.Fatal("actual helper ACK", err)
	}
	if err := p.acknowledgeStart(); err != nil {
		t.Fatal(err)
	}
	if p.abandonUnstartedWait() == nil {
		t.Fatal("actual started child discarded")
	}
	_ = input.Close()
	select {
	case <-p.done:
		t.Fatal("child reaped before original birth-capture boundary")
	default:
	}
	if err := p.beginReservedWait(); err != nil {
		t.Fatal(err)
	}
	if p.beginReservedWait() == nil {
		t.Fatal("two Wait goroutines admitted")
	}
	if err := p.Joined(xrayRuntimeFinite(t)); err != nil {
		t.Fatal(err)
	}
	if err := p.Joined(xrayRuntimeFinite(t)); err != nil {
		t.Fatal("repeat join", err)
	}
}

func TestXraySelectedTCPRuntimeUnstartedReservationFailureAndBound(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	makeCommand := func() *exec.Cmd {
		cmd := exec.Command(filepath.Clean(binary), "version")
		cmd.Dir = t.TempDir()
		cmd.Env = []string{}
		return cmd
	}
	var owners []*xraySelectedTCPProcess
	t.Cleanup(func() {
		for _, p := range owners {
			_ = p.abandonUnstartedWait()
		}
	})
	for range maxExecutionResources {
		p, err := reserveXraySelectedTCPProcessWait(xrayRuntimeFinite(t), makeCommand())
		if err != nil {
			t.Fatal(err)
		}
		owners = append(owners, p)
	}
	if _, err := reserveXraySelectedTCPProcessWait(xrayRuntimeFinite(t), makeCommand()); err == nil {
		t.Fatal("unbounded reservation pool")
	}
	if err := owners[0].abandonUnstartedWait(); err != nil {
		t.Fatal(err)
	}
	if owners[0].abandonUnstartedWait() == nil {
		t.Fatal("abandoned slot replayed")
	}
	cmd := makeCommand()
	cmd.Path = filepath.Join(cmd.Dir, "absent-helper")
	p, err := reserveXraySelectedTCPProcessWait(xrayRuntimeFinite(t), cmd)
	if err != nil {
		t.Fatal(err)
	}
	owners = append(owners, p)
	if err := cmd.Start(); err == nil {
		t.Fatal("absent helper started")
	}
	if err := p.abandonUnstartedWait(); err != nil {
		t.Fatal("failed syscall reservation retained", err)
	}
}
