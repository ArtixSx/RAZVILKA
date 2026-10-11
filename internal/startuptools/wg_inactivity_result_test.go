package startuptools

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestWGInactivityResultChild(t *testing.T) {
	if os.Getenv("RAZVILKA_WG_INACTIVITY_RESULT_CHILD") != "1" {
		return
	}
	fmt.Fprint(os.Stdout, "[]\n")
	fmt.Fprint(os.Stderr, "Error: ipv6: FIB table does not exist.\nDump terminated\n")
	os.Exit(2)
}

func TestWGInactivityResultPreservesOnlyCompletedCurrentBoundedRead(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr := &output{limit: maxOutputBytes}, &output{limit: 4096}
	command := exec.Command(executable, "-test.run=^TestWGInactivityResultChild$")
	command.Env = append(os.Environ(), "RAZVILKA_WG_INACTIVITY_RESULT_CHILD=1")
	command.Stdout, command.Stderr = stdout, stderr
	commandErr := command.Run() // Actual portable Go child; no IP/native issuer.
	if _, ok := commandErr.(*exec.ExitError); !ok {
		t.Fatal("child did not perform an actual ordinary exit", commandErr)
	}
	data, err := wgInactivityReadResult(stdout, stderr, commandErr, nil)
	want := "[]\nError: ipv6: FIB table does not exist.\nDump terminated\n"
	if string(data) != want || !errors.Is(err, commandErr) || !errors.Is(err, ErrUnknown) {
		t.Fatal("genuine bounded diagnostic/command failure lost", err)
	}
	data[0] = 'x'
	if string(stdout.data) != "[]\n" {
		t.Fatal("diagnostic aliases child output storage")
	}
	for _, test := range []struct {
		name           string
		out, stderr    *output
		command, scope error
	}{
		{"cancelled", stdout, stderr, commandErr, context.Canceled},
		{"closing-source-refused", stdout, stderr, commandErr, at("CHECK_HELD_FILE", nil)},
		{"overflow", &output{data: stdout.data, overflow: true}, stderr, commandErr, nil},
		{"stderr-overflow", stdout, &output{data: stderr.data, overflow: true}, commandErr, nil},
		{"combined-limit", &output{data: []byte(strings.Repeat("x", maxOutputBytes))}, stderr, commandErr, nil},
		{"wait-delay", stdout, stderr, exec.ErrWaitDelay, nil},
		{"incomplete-wait", stdout, stderr, errors.New("modeled Wait/read failure"), nil},
		{"stderr-with-success", stdout, stderr, nil, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			if data, err := wgInactivityReadResult(test.out, test.stderr, test.command, test.scope); len(data) != 0 || err == nil {
				t.Fatal("unknown/incomplete source supplied diagnostic evidence")
			}
		})
	}
	if data, err := wgInactivityReadResult(stdout, &output{}, nil, nil); err != nil || string(data) != "[]\n" {
		t.Fatal("ordinary successful read changed", err)
	}
}
