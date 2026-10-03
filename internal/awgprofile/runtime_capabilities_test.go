package awgprofile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runtimeCapabilityFixture(t *testing.T) (runtimeInspector, map[string]string, *[]string) {
	t.Helper()
	files := map[string]string{
		"/proc/sys/kernel/osrelease":       "6.8.0-native",
		"/proc/sys/kernel/tainted":         "12288", // out-of-tree + unsigned are not force-loading.
		"/sys/module/amneziawg/version":    "3.1.20260906",
		"/sys/module/amneziawg/srcversion": "0123456789ABCDEF01234567",
		"/sys/module/amneziawg/initstate":  "live",
		"/sys/module/amneziawg/taint":      "OE",
	}
	tool, modinfo := filepath.Join(t.TempDir(), "awg.exe"), filepath.Join(t.TempDir(), "modinfo.exe")
	calls := []string{}
	inspect := runtimeInspector{
		read: func(path string) string { return files[path] },
		look: func(name string) (string, error) {
			if name == "awg" {
				return tool, nil
			}
			if name == "modinfo" {
				return modinfo, nil
			}
			return "", errors.New("not found")
		},
		hash: func(context.Context, string) (string, error) { return strings.Repeat("a", 64), nil },
		run: func(_ context.Context, path string, args ...string) (string, error) {
			calls = append(calls, filepath.Base(path)+" "+strings.Join(args, " "))
			if path == tool && strings.Join(args, " ") == "--version" {
				return "amneziawg-tools v3.1.20260812 - https://amnezia.org\n", nil
			}
			if path == modinfo && strings.Join(args, " ") == "amneziawg" {
				return "filename: /lib/modules/new/amneziawg.ko\nname: amneziawg\nversion: 3.1.20260906\nsrcversion: 0123456789ABCDEF01234567\nvermagic: 6.8.0-native SMP preempt mod_unload modversions\n", nil
			}
			return "", errors.New("unexpected command")
		},
	}
	return inspect, files, &calls
}

func TestAWGRuntimeReceiptBindsLoadedModuleKernelAndCLI(t *testing.T) {
	inspect, _, calls := runtimeCapabilityFixture(t)
	c := inspectRuntime(context.Background(), []string{"awg"}, inspect)
	if !c.CompatibilityVerified || !c.SupportsAWG31 || c.HardwareVerified || len(CheckRuntime(Preview{MinimumMajor: 3, MinimumMinor: 1}, c)) != 0 {
		t.Fatal("complete inventory not accepted", c)
	}
	if strings.Join(*calls, "|") != "awg.exe --version|modinfo.exe amneziawg" {
		t.Fatal("detection used a mutative or unexpected command", *calls)
	}
	for name, mutate := range map[string]func(*Capabilities){
		"new module only on disk": func(c *Capabilities) { c.LoadedModuleVersion = "3.0.20260101" },
		"different source":        func(c *Capabilities) { c.LoadedSourceVersion = "ABCDEF0123456789ABCDEF01" },
		"missing source":          func(c *Capabilities) { c.LoadedSourceVersion = "" },
		"kernel mismatch":         func(c *Capabilities) { c.Kernel = "6.8.1-native" },
		"forced load":             func(c *Capabilities) { c.KernelTaint = "12290" },
		"forced unload":           func(c *Capabilities) { c.KernelTaint = "12296" },
		"module forced":           func(c *Capabilities) { c.ModuleTaint = "OEF" },
		"unknown taint":           func(c *Capabilities) { c.KernelTaint = "" },
		"module initializing":     func(c *Capabilities) { c.ModuleInitState = "coming" },
		"wrong module name":       func(c *Capabilities) { c.ModuleName = "wireguard" },
		"plain WG tool":           func(c *Capabilities) { c.ToolVersion = "wireguard-tools v3.1.0" },
		"unknown tool identity":   func(c *Capabilities) { c.ToolVersion = "awg v3.1.0" },
		"missing tool digest":     func(c *Capabilities) { c.ToolSHA256 = "" },
		"unknown vermagic":        func(c *Capabilities) { c.ModuleVermagic = "" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := c
			mutate(&changed)
			// An injected display boolean cannot vouch for missing raw facts.
			changed.CompatibilityVerified, changed.SupportsAWG31 = true, true
			if len(CheckRuntime(Preview{MinimumMajor: 3, MinimumMinor: 1}, changed)) == 0 || len(CheckRuntime(Preview{MinimumMajor: 1}, changed)) == 0 {
				t.Fatal("incompatible or unknown runtime accepted", changed)
			}
		})
	}
}

func TestAWGDetectionFailsClosedOnMissingChangingOrAmbiguousInventory(t *testing.T) {
	for _, kind := range []string{"missing module", "missing modinfo", "command failure", "ambiguous metadata", "runtime changed", "tool changed", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			inspect, files, _ := runtimeCapabilityFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "missing module":
				delete(files, "/sys/module/amneziawg/version")
			case "missing modinfo":
				look := inspect.look
				inspect.look = func(name string) (string, error) {
					if name == "modinfo" {
						return "", errors.New("missing")
					}
					return look(name)
				}
			case "command failure":
				inspect.run = func(context.Context, string, ...string) (string, error) { return "", errors.New("failed") }
			case "ambiguous metadata":
				run := inspect.run
				inspect.run = func(ctx context.Context, path string, args ...string) (string, error) {
					out, err := run(ctx, path, args...)
					if args[0] == "amneziawg" {
						out += "srcversion: ABCDEF0123456789ABCDEF01\n"
					}
					return out, err
				}
			case "runtime changed":
				run := inspect.run
				inspect.run = func(ctx context.Context, path string, args ...string) (string, error) {
					out, err := run(ctx, path, args...)
					files["/sys/module/amneziawg/initstate"] = "going"
					return out, err
				}
			case "tool changed":
				reads := 0
				inspect.hash = func(context.Context, string) (string, error) {
					reads++
					if reads > 1 {
						return strings.Repeat("b", 64), nil
					}
					return strings.Repeat("a", 64), nil
				}
			case "cancel":
				cancel()
			}
			c := inspectRuntime(ctx, []string{"awg"}, inspect)
			if c.CompatibilityVerified || c.SupportsAWG31 || len(CheckRuntime(Preview{MinimumMajor: 3, MinimumMinor: 1}, c)) == 0 && kind != "cancel" {
				t.Fatal("incomplete detection granted readiness", c)
			}
		})
	}
}

func TestAWGSourceVersionKbuildFormatsAndExactIdentity(t *testing.T) {
	inspect, _, _ := runtimeCapabilityFixture(t)
	baseline := inspectRuntime(context.Background(), []string{"awg"}, inspect)
	for _, source := range []string{"8B43245B4272244B0CB9617", "0123456789ABCDEF01234567"} {
		c := baseline
		c.LoadedSourceVersion, c.ModuleSourceVersion = source, source
		if len(CheckRuntime(Preview{MinimumMajor: 3, MinimumMinor: 1}, c)) != 0 {
			t.Fatalf("supported kbuild srcversion length %d rejected", len(source))
		}
		c.ModuleSourceVersion = strings.ToLower(source)
		if len(CheckRuntime(Preview{MinimumMajor: 3, MinimumMinor: 1}, c)) == 0 {
			t.Fatal("source identity normalized rather than compared exactly")
		}
	}
	for _, source := range []string{"", strings.Repeat("A", 22), strings.Repeat("A", 25), "8B43245B4272244B0CB961G", "8B43245B4272244B0CB9617\n"} {
		c := baseline
		c.LoadedSourceVersion, c.ModuleSourceVersion = source, source
		if len(CheckRuntime(Preview{MinimumMajor: 3, MinimumMinor: 1}, c)) == 0 {
			t.Fatal("malformed source identity accepted")
		}
	}
	c := baseline
	c.LoadedSourceVersion, c.ModuleSourceVersion = "8B43245B4272244B0CB9617", "8B43245B4272244B0CB9618"
	if len(CheckRuntime(Preview{MinimumMajor: 3, MinimumMinor: 1}, c)) == 0 {
		t.Fatal("different loaded and installed source identities accepted")
	}
}

func TestAWGVerifyToolRejectsReplacementAndAnotherPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "awg.exe")
	if err := os.WriteFile(path, []byte("fixture executable A"), 0700); err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveToolPath(path)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := hashTool(context.Background(), resolved)
	if err != nil {
		t.Fatal(err)
	}
	c := Capabilities{ToolPath: resolved, ToolSHA256: digest}
	if _, err := VerifyTool(context.Background(), c, path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("fixture executable B"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyTool(context.Background(), c, path); err == nil {
		t.Fatal("changed executable accepted")
	}
	if _, err := VerifyTool(context.Background(), c, filepath.Join(t.TempDir(), "foreign.exe")); err == nil {
		t.Fatal("other path accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifyTool(ctx, c, path); err == nil {
		t.Fatal("canceled inspection accepted")
	}
}
