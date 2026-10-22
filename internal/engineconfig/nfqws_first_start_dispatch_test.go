package engineconfig

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func firstStartDispatchShell(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		if git, err := exec.LookPath("git"); err == nil {
			bash := filepath.Join(filepath.Dir(filepath.Dir(git)), "bin", "bash.exe")
			if info, err := os.Stat(bash); err == nil && info.Mode().IsRegular() {
				return bash
			}
		}
		t.Skip("Git Bash is required for the private shell model on Windows")
	}
	if bash, err := exec.LookPath("bash"); err == nil {
		return bash
	}
	t.Skip("bash is required for stock source syntax in the private shell model")
	return ""
}

func TestNFQWSFirstStartDispatchOrdinaryActionsNeverSourceOrMutate(t *testing.T) {
	shell := firstStartDispatchShell(t)
	stock, err := os.ReadFile(filepath.Join("..", "components", "testdata", "nfqws2-keenetic-1.3.1", "S51nfqws2"))
	if err != nil {
		t.Fatal(err)
	}
	guarded, err := NFQWSFirstStartInit(stock, "0123456789abcdef01234567")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	fullPath := filepath.Join(root, "exact-guarded.sh")
	if err := os.WriteFile(fullPath, guarded, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, shell, "-n", filepath.ToSlash(fullPath)).CombinedOutput(); err != nil {
		t.Fatalf("guarded script syntax: %v %s", err, out)
	}
	sourceAt := bytes.Index(guarded, []byte("source \"$CONFFILE\"\n"))
	caseAt := bytes.LastIndex(guarded, []byte("case \"$1\" in\n  start)\n"))
	if sourceAt < 0 || caseAt <= sourceAt {
		t.Fatal("stock source/dispatch statement moved")
	}
	prefix := bytes.Replace(guarded[:sourceAt], []byte(`CONFFILE="/opt/etc/nfqws2/nfqws2.conf"`), []byte(`CONFFILE="$RZ_TEST_CONFIG"`), 1)
	// The production dispatcher and final stock case are exact. Only stock
	// action bodies and the config destination are replaced with trace stubs;
	// this model cannot run iptables, modules, sysctl, kill or a daemon.
	stub := `source "$CONFFILE"
start() { printf 'start\n' >> "$RZ_TEST_EFFECTS"; }
stop() { printf 'stop\n' >> "$RZ_TEST_EFFECTS"; }
status_service() { printf 'status\n' >> "$RZ_TEST_EFFECTS"; }
firewall_iptables() { printf 'firewall\n' >> "$RZ_TEST_EFFECTS"; }
firewall_ip6tables() { printf 'firewall\n' >> "$RZ_TEST_EFFECTS"; }
firewall_stop() { printf 'firewall\n' >> "$RZ_TEST_EFFECTS"; }
kernel_modules() { printf 'kernel\n' >> "$RZ_TEST_EFFECTS"; }
`
	script := append(append(append([]byte(nil), prefix...), []byte(stub)...), guarded[caseAt:]...)
	scriptPath := filepath.Join(root, "dispatch-model.sh")
	configPath := filepath.Join(root, "trace.conf")
	if err := os.WriteFile(scriptPath, script, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("printf 'config\\n' >> \"$RZ_TEST_EFFECTS\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"", "start", "restart", "stop", "status", "firewall_iptables", "firewall_ip6tables", "firewall_stop", "kernel_modules", "owned_firewall", "unknown", "owned_start", "owned_stop", "owned_status"} {
		t.Run(action, func(t *testing.T) {
			trace := filepath.Join(t.TempDir(), "effects")
			args := []string{filepath.ToSlash(scriptPath)}
			if action != "" {
				args = append(args, action)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, shell, args...)
			cmd.Env = append(os.Environ(), "RZ_TEST_CONFIG="+filepath.ToSlash(configPath), "RZ_TEST_EFFECTS="+filepath.ToSlash(trace))
			out, err := cmd.CombinedOutput()
			if action == "status" {
				if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 3 {
					t.Fatal("ordinary status must report unmanaged observation", err)
				}
			} else if err != nil {
				t.Fatalf("shell model failed: %v %s", err, out)
			}
			data, readErr := os.ReadFile(trace)
			if strings.HasPrefix(action, "owned_") && action != "owned_firewall" {
				want := "config\n" + strings.TrimPrefix(action, "owned_") + "\n"
				if readErr != nil || string(data) != want {
					t.Fatalf("internal dispatch changed: got %q error %v", data, readErr)
				}
			} else {
				if !os.IsNotExist(readErr) {
					t.Fatalf("ordinary action sourced config or performed action: %s %q %v", action, data, readErr)
				}
				text := string(out)
				if !strings.Contains(text, "managed by RAZVILKA") || strings.Contains(text, "is running") || strings.Contains(text, "is stopped") {
					t.Fatal("inert result claims runtime health", text)
				}
			}
		})
	}
}
