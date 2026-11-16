//go:build linux && razvilka_native_fixture

package dataplane

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestInactiveProcTerminalNativeDiagnosticVocabulary(t *testing.T) {
	reasons := []string{
		"process-terminal-invalid", "process-terminal-self", "process-terminal-observed-dead", "process-terminal-observed-multithread-zombie",
		"process-terminal-named-not-gone", "process-terminal-gone-closing", "process-terminal-read", "process-terminal-parse",
		"process-terminal-unbound-birth", "process-terminal-birth-changed", "process-terminal-live-state", "process-terminal-multithread-zombie",
		"process-terminal-identity-closing", "process-terminal-zombie-closing",
		"process-terminal-pf-exiting", "process-terminal-no-pf-exiting", "process-terminal-state-running", "process-terminal-state-sleeping",
		"process-terminal-state-disk-wait", "process-terminal-state-stopped", "process-terminal-state-dead", "process-terminal-state-other",
	}
	var retained *linuxInactiveProcPID
	rows, err := WithMihomoSameBootNativeMeasurements(t.Context(), func(ctx context.Context) error {
		h := &linuxInactiveProcPID{pass: &linuxInactiveProcPass{ctx: ctx}}
		retained = h
		for _, reason := range reasons {
			if inactiveProcTerminalRefused(h, reason) {
				t.Fatal("diagnostic granted terminal permission")
			}
		}
		for _, foreign := range []string{"processes", "private-path-secret", "process-terminal-private-pid-123", ""} {
			if inactiveProcTerminalRefused(h, foreign) {
				t.Fatal("foreign reason granted permission")
			}
		}
		return nil
	})
	if err != nil || len(rows) != len(reasons) {
		t.Fatal(err, len(rows))
	}
	for _, row := range rows {
		if !strings.HasPrefix(row.Phase, "failure-process-terminal-") || row.Calls != 1 || row.Nanoseconds != 0 || strings.Contains(row.Phase, "secret") {
			t.Fatal(row)
		}
	}
	if inactiveProcTerminalRefused(retained, reasons[0]) || inactiveProcTerminalRefused(nil, reasons[0]) {
		t.Fatal("closed/nil diagnostic granted permission")
	}
	m := retained.pass.ctx.Value(mihomoSameBootMeasurementsKey{}).(*mihomoSameBootMeasurements)
	if m.rows["failure-"+reasons[0]].Calls != 1 {
		t.Fatal("late callback changed completed measurement")
	}
}

func TestInactiveProcTerminalNativeDiagnosticExistingStat(t *testing.T) {
	for _, flags := range []string{"0", "4", "2097152", "2097156", "bad"} {
		fields := strings.Fields(string(inactiveReaderStat(102, 'R', "1", "17")))
		fields[8] = flags // stat field9: flags, after PID/comm/state.
		raw := []byte(strings.Join(fields, " ") + "\n")
		before := bytes.Clone(raw)
		if got := inactiveProcTerminalExiting(raw, 102); got != (flags == "4" || flags == "2097156") {
			t.Fatal(flags, got)
		}
		if !bytes.Equal(raw, before) {
			t.Fatal("diagnostic changed original stat bytes")
		}
	}
	if inactiveProcTerminalExiting([]byte("private malformed stat"), 102) {
		t.Fatal("malformed flags accepted")
	}
	for _, state := range []byte{'R', 'S', 'D', 'T', 't', 'X', 'x', 'I', '?'} {
		for _, exiting := range []bool{false, true} {
			rows, err := WithMihomoSameBootNativeMeasurements(t.Context(), func(ctx context.Context) error {
				if inactiveProcTerminalLiveRefused(&linuxInactiveProcPID{pass: &linuxInactiveProcPass{ctx: ctx}}, state, exiting) {
					t.Fatal("PF_EXITING/live state bypassed terminal refusal")
				}
				return nil
			})
			if err != nil || len(rows) != 3 {
				t.Fatal(state, exiting, err, rows)
			}
		}
	}
}

func TestInactiveProcTerminalNativeDiagnosticChild(t *testing.T) {
	if os.Getenv("RAZVILKA_TERMINAL_DIAGNOSTIC_CHILD") != "1" {
		return
	}
	if _, err := fmt.Fprintln(os.Stdout, "ready"); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	_, _ = os.Stdin.Read(one[:])
}

// A real held procfs PID remains live throughout the original process
// observation. The diagnostic explains refusal; it cannot turn it terminal.
func TestInactiveProcTerminalNativeDiagnosticActualLive(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestInactiveProcTerminalNativeDiagnosticChild$")
	cmd.Env = append(os.Environ(), "RAZVILKA_TERMINAL_DIAGNOSTIC_CHILD=1")
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = input.Close()
		if err := cmd.Wait(); err != nil {
			t.Error("original child Wait", err)
		}
	}()
	if line, err := bufio.NewReader(output).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatal("original live child readiness", err)
	}
	rows, err := WithMihomoSameBootNativeMeasurements(ctx, func(observed context.Context) (result error) {
		pass, err := openLinuxInactiveProc(observed, "/proc", os.Getpid())
		if err != nil {
			return err
		}
		defer func() { result = errors.Join(result, pass.Close()) }()
		child, err := pass.OpenPID(cmd.Process.Pid)
		if err != nil {
			return err
		}
		defer func() { result = errors.Join(result, child.Close()) }()
		if _, err := child.Stat(); err != nil {
			return err
		}
		if child.Terminal() {
			return errors.New("actual live child accepted as terminal")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, row := range rows {
		if row.Phase == "failure-process-terminal-live-state" && row.Calls == 1 {
			seen = true
		}
	}
	if !seen || len(rows) != 3 {
		t.Fatal("actual original refusal not classified", rows)
	}
}
