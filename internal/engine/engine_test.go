package engine

import (
	"strings"
	"testing"
)

func TestRegistryIDsUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, spec := range Registry() {
		if spec.ID == "" {
			t.Fatal("engine id must not be empty")
		}
		if seen[spec.ID] {
			t.Fatalf("duplicate engine id %q", spec.ID)
		}
		seen[spec.ID] = true
	}
}

func TestNFQWS2RegistryContract(t *testing.T) {
	var got *Spec
	for _, spec := range Registry() {
		if spec.ID == "nfqws2" {
			s := spec
			got = &s
			break
		}
	}
	if got == nil {
		t.Fatal("nfqws2 spec missing")
	}
	if got.Package != "nfqws2-keenetic" {
		t.Fatalf("unexpected package: %q", got.Package)
	}
	if len(got.BinaryCandidates) == 0 || got.BinaryCandidates[0] != "/opt/usr/bin/nfqws2" {
		t.Fatalf("unexpected primary binary: %#v", got.BinaryCandidates)
	}
	if len(got.InitScripts) != 1 || got.InitScripts[0] != "/opt/etc/init.d/S51nfqws2" {
		t.Fatalf("unexpected init scripts: %#v", got.InitScripts)
	}
	if len(got.ConfigPaths) != 1 || got.ConfigPaths[0] != "/opt/etc/nfqws2/nfqws2.conf" {
		t.Fatalf("unexpected config paths: %#v", got.ConfigPaths)
	}
	if !got.Capabilities.Config || !got.Capabilities.Validate || !got.Capabilities.Lifecycle {
		t.Fatalf("unexpected capabilities: %#v", got.Capabilities)
	}
}

func TestParseOpkgStatus(t *testing.T) {
	version, installed := parseOpkgStatus(`Package: nfqws2-keenetic
Version: 1.2.4
Status: install user installed
Architecture: aarch64-3.10_kn
`)
	if !installed || version != "1.2.4" {
		t.Fatalf("version=%q installed=%v", version, installed)
	}

	version, installed = parseOpkgStatus("Package: nfqws2-keenetic\nVersion: 1.2.5-r1\n")
	if !installed || version != "1.2.5-r1" {
		t.Fatalf("fallback version=%q installed=%v", version, installed)
	}

	_, installed = parseOpkgStatus("Package: nfqws2-keenetic\nStatus: deinstall user not-installed\n")
	if installed {
		t.Fatal("not-installed package must not be classified installed")
	}
}

func TestStatusOutputRunning(t *testing.T) {
	positive := []string{
		"Service NFQWS2 is running",
		"Checking NFQWS2... alive.",
		"active",
	}
	for _, sample := range positive {
		if !statusOutputRunning(sample) {
			t.Fatalf("expected running for %q", sample)
		}
	}
	negative := []string{"Service is not running", "stopped", "inactive", "dead", ""}
	for _, sample := range negative {
		if statusOutputRunning(sample) {
			t.Fatalf("expected stopped for %q", sample)
		}
	}
}

func TestPSOutputHasProcessExactCommand(t *testing.T) {
	out := strings.Join([]string{
		"  PID USER       VSZ STAT COMMAND",
		" 1201 root      1456 S    /opt/usr/bin/nfqws2 --qnum=200 --daemon",
	}, "\n")
	if !psOutputHasProcess(out, []string{"nfqws2"}) {
		t.Fatal("nfqws2 executable should be detected")
	}

	out = strings.Join([]string{
		"  PID USER       VSZ STAT COMMAND",
		" 1202 root      1456 S    /bin/sh /tmp/nfqws2-maintenance.sh",
	}, "\n")
	if psOutputHasProcess(out, []string{"nfqws2"}) {
		t.Fatal("substring in arguments/script name must not become a running nfqws2 process")
	}
}
