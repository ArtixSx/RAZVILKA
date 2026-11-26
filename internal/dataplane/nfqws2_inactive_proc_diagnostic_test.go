package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNFQWSInactiveProcessDiagnosticFixtureBranches(t *testing.T) {
	const private = "private-path-address-command-775"
	for _, scenario := range []string{"clear", "coordinates", "context", "inventory.open", "inventory.read", "inventory.entry", "stat.read", "stat.parse", "name", "zombie", "self.state", "cmdline.read", "cmdline.empty", "cmdline.parse", "budget", "exe", "exe.name", "argument", "stat.close", "startticks", "inventory.closure", "context-during"} {
		t.Run(scenario, func(t *testing.T) {
			f := newNFQWS2InactiveFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			path := filepath.Join(f.proof.procRoot, "1")
			write := func(name, data string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(path, name), []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			remove := func(name string) {
				t.Helper()
				if err := os.Remove(filepath.Join(path, name)); err != nil {
					t.Fatal(err)
				}
			}
			switch scenario {
			case "coordinates":
				f.proof.selfPID = 0
			case "context":
				cancel()
			case "inventory.open":
				f.proof.procRoot = filepath.Join(f.proof.procRoot, private)
			case "inventory.read":
				f.proof.procRoot = t.TempDir()
			case "inventory.entry":
				if err := os.Mkdir(filepath.Join(f.proof.procRoot, "02"), 0700); err != nil {
					t.Fatal(err)
				}
			case "stat.read":
				remove("stat")
			case "stat.parse":
				write("stat", private)
			case "name":
				f.process(t, 1, "nfqws2", 'S', 0, private+"\x00")
			case "zombie":
				f.process(t, 1, "nfqws2", 'Z', 0, "")
			case "self.state":
				f.process(t, 1, private, 'Z', 0, "")
			case "cmdline.read":
				remove("cmdline")
			case "cmdline.empty":
				write("cmdline", "")
			case "cmdline.parse":
				write("cmdline", "\x00"+private)
			case "budget":
				for pid := 2; pid <= 257; pid++ {
					f.process(t, pid, "controller", 'S', 0, strings.Repeat("x", 64<<10))
				}
			case "exe.name":
				f.proof.readlink = func(string) (string, error) { return "/private/nfqws2", nil }
			case "exe":
				f.proof.readlink = func(string) (string, error) { return "", errors.New(private) }
			case "argument":
				write("cmdline", "controller\x00--config="+f.a.ConfigPath+"\x00")
			case "stat.close", "startticks":
				f.proof.readlink = func(string) (string, error) {
					raw, err := os.ReadFile(filepath.Join(path, "stat"))
					if err != nil {
						t.Fatal(err)
					}
					data := private
					if scenario == "startticks" {
						data = strings.Replace(string(raw), "123", "124", 1)
					}
					write("stat", data)
					return private, nil
				}
			case "inventory.closure":
				f.proof.selfPID = 99
			case "context-during":
				f.proof.readlink = func(string) (string, error) { cancel(); return private, nil }
			}
			err := nfqws2InactiveProcesses(ctx, f.proof, f.a)
			if scenario == "clear" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			label := scenario
			cause := ErrNFQWSManagedProcessUnknown
			if scenario == "context-during" {
				label, cause = "context", context.Canceled
			}
			if !errors.Is(err, cause) || errors.Is(err, ErrNFQWSManagedProcessUnknown) != (cause == ErrNFQWSManagedProcessUnknown) {
				t.Fatalf("refusal identity changed: %v", err)
			}
			public := nfqws2InactiveAt("observation", nfqws2InactiveAt("processes", fmt.Errorf(private+": %w", err)))
			want := "NFQWS runtime inactivity: observation/processes/proc." + label
			if public.Error() != want || strings.Contains(public.Error(), private) || strings.Contains(err.Error(), private) || NFQWSRuntimeInactiveStage(public) != "processes" {
				t.Fatalf("unsafe or missing diagnostic: got %q want %q", public, want)
			}
		})
	}
}

func TestNFQWSInactiveProcessDiagnosticOnlyProjectsClosedTypedLabels(t *testing.T) {
	private := "private-path-address-command-775"
	cause := errors.New(private)
	for _, label := range []string{"budget", "exemption", "exemption.current", "exemption.wrapper", private} {
		expected := label
		if label == private {
			expected = "unknown"
		}
		typed := nfqws2InactiveProcessAt(label, cause)
		wrapped := nfqws2InactiveAt("processes", fmt.Errorf(private+": %w", typed))
		if wrapped.Error() != "NFQWS runtime inactivity: processes/proc."+expected || strings.Contains(typed.Error(), private) || !errors.Is(wrapped, cause) {
			t.Fatal("unsafe diagnostic or lost cause", wrapped)
		}
	}
	foreign := nfqws2InactiveAt("processes", errors.New("NFQWS process inventory refused at startticks: "+private))
	if foreign.Error() != "NFQWS runtime inactivity: processes" {
		t.Fatal("foreign text forged process diagnostic", foreign)
	}
	// The public traversal remains bounded even with repeated typed wrappers.
	var nested error = cause
	for i := 0; i < 1000; i++ {
		nested = nfqws2InactiveProcessAt("exe", nested)
	}
	if got := nfqws2InactiveAt("processes", nested).Error(); got != "NFQWS runtime inactivity: processes/proc.exe" {
		t.Fatal(got)
	}
}
