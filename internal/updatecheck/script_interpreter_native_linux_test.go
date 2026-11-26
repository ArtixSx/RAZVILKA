//go:build linux

package updatecheck

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func nativeScriptInterpreterFixture(t *testing.T) (base, alias, target, script string) {
	t.Helper()
	base, _, _ = ordinaryNativeRunnerImage(t)
	alias = filepath.Join(base, "opt/bin/sh")
	target = filepath.Join(base, "opt/bin/busybox")
	script = filepath.Join(base, "script.sh")
	if err := os.MkdirAll(filepath.Dir(alias), 0755); err != nil {
		t.Fatal(err)
	}
	binary, err := exec.LookPath("busybox")
	if err != nil {
		t.Fatal("real BusyBox required for native interpreter regression", err)
	}
	data, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, data, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf executed > '"+filepath.Join(base, "executed")+"'\nif true; then :; fi\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return
}

func TestNativeScriptInterpreterBusyBoxAndGenericParseWithoutExecution(t *testing.T) {
	base, alias, target, script := nativeScriptInterpreterFixture(t)
	path, sha, current, err := reviewOwnedScriptInterpreter(alias, target, base)
	if err != nil || path != target {
		t.Fatal("exact Entware shell alias refused", path, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	starts := 0
	admit := func(_ context.Context, e string, begin func() error) error {
		if e != "ordinary-prepare-syntax" {
			t.Fatal("unexpected effect", e)
		}
		starts++
		return begin()
	}
	guard := func() error { return nil }
	if err := runPinnedScriptSyntax(ctx, path, sha, script, current, admit, guard, guard, guard); err != nil {
		t.Fatal("real BusyBox sh applet refused valid syntax", err)
	}
	if starts != 1 {
		t.Fatal("syntax did not execute held interpreter", starts)
	}
	if _, err := os.Lstat(filepath.Join(base, "executed")); !os.IsNotExist(err) {
		t.Fatal("syntax parse executed script body", err)
	}
	if err := runReviewedScriptSyntax(ctx, base, script, admit, guard, guard, guard); err != nil {
		t.Fatal("generic Linux POSIX shell regressed", err)
	}
	if _, err := os.Lstat(filepath.Join(base, "executed")); !os.IsNotExist(err) {
		t.Fatal("generic parse executed script body", err)
	}
	if err := os.WriteFile(script, []byte("if then\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runPinnedScriptSyntax(ctx, path, sha, script, current, admit, guard, guard, guard); err == nil {
		t.Fatal("invalid syntax falsely accepted")
	}
}

func TestNativeScriptInterpreterFirmwareRejectsNButEntwareParses(t *testing.T) {
	base, alias, target, script := nativeScriptInterpreterFixture(t)
	source := filepath.Join(base, "firmware.c")
	firmware := filepath.Join(base, "firmware-sh")
	code := []byte("#include <stdio.h>\n#include <string.h>\nint main(int argc,char **argv){if(argc>1 && strcmp(argv[1],\"-n\")==0){fputs(\"Invalid option -n\\n\",stderr);return 245;}return 0;}\n")
	if err := os.WriteFile(source, code, 0600); err != nil {
		t.Fatal(err)
	}
	compiler, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal("native compiler required for firmware CLI regression", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, compiler, "-O2", "-o", firmware, source).CombinedOutput(); err != nil {
		t.Fatal("firmware fixture compilation failed", err, string(output))
	}
	path, sha, current, err := reviewOwnedScriptInterpreter(firmware, firmware, base)
	if err != nil {
		t.Fatal(err)
	}
	admit := func(_ context.Context, _ string, begin func() error) error { return begin() }
	guard := func() error { return nil }
	if err := runPinnedScriptSyntax(ctx, path, sha, script, current, admit, guard, guard, guard); err == nil {
		t.Fatal("firmware CLI accepted POSIX parser role")
	}
	path, sha, current, err = reviewOwnedScriptInterpreter(alias, target, base)
	if err != nil {
		t.Fatal(err)
	}
	if err := runPinnedScriptSyntax(ctx, path, sha, script, current, admit, guard, guard, guard); err != nil {
		t.Fatal("Entware parser failed despite valid syntax", err)
	}
	if _, err := os.Lstat(filepath.Join(base, "executed")); !os.IsNotExist(err) {
		t.Fatal("script body executed", err)
	}
}

func TestNativeScriptInterpreterRefusesAliasImageAndAdmissionDrift(t *testing.T) {
	for _, kind := range []string{"alias-replaced", "alias-metadata", "target-metadata", "image-replaced", "image-content", "inside-admission", "after-start"} {
		t.Run(kind, func(t *testing.T) {
			base, alias, target, script := nativeScriptInterpreterFixture(t)
			path, sha, current, err := reviewOwnedScriptInterpreter(alias, target, base)
			if err != nil {
				t.Fatal(err)
			}
			replaceAlias := func() error {
				if err := os.Remove(alias); err != nil {
					return err
				}
				return os.Symlink(target, alias)
			}
			if kind == "alias-replaced" {
				if err := replaceAlias(); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "alias-metadata" {
				if err := os.Lchown(alias, 0, 1); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "target-metadata" {
				if err := os.Chmod(target, 0755); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "image-replaced" {
				data, err := os.ReadFile(target)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(target, target+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target, data, 0755); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "image-content" {
				f, err := os.OpenFile(target, os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.WriteAt([]byte("X"), 0)
				f.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			starts := 0
			admit := func(_ context.Context, _ string, begin func() error) error {
				if kind == "inside-admission" {
					if err := replaceAlias(); err != nil {
						return err
					}
				}
				err := begin()
				if err == nil {
					starts++
				}
				if kind == "after-start" {
					if changeErr := replaceAlias(); changeErr != nil {
						return changeErr
					}
				}
				return err
			}
			guard := func() error { return nil }
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := runPinnedScriptSyntax(ctx, path, sha, script, current, admit, guard, guard, guard); err == nil {
				t.Fatal("changed shell review accepted")
			}
			if kind != "after-start" && starts != 0 {
				t.Fatal("changed interpreter started", starts)
			}
			if _, err := os.Lstat(filepath.Join(base, "executed")); !os.IsNotExist(err) {
				t.Fatal("syntax ran script body", err)
			}
		})
	}
}

func TestNativeScriptInterpreterKeepsUnknownAliasAndOwnershipClosed(t *testing.T) {
	for _, kind := range []string{"wrong-target", "relative", "chain", "alias-owner", "target-owner", "unsafe-parent", "unsafe-target"} {
		t.Run(kind, func(t *testing.T) {
			base, alias, target, _ := nativeScriptInterpreterFixture(t)
			switch kind {
			case "wrong-target":
				_ = os.Remove(alias)
				_ = os.Symlink(filepath.Join(base, "sh"), alias)
			case "relative":
				_ = os.Remove(alias)
				_ = os.Symlink("busybox", alias)
			case "chain":
				_ = os.Rename(target, target+".real")
				_ = os.Symlink(target+".real", target)
			case "alias-owner":
				if err := os.Lchown(alias, 1, 0); err != nil {
					t.Fatal(err)
				}
			case "target-owner":
				if err := os.Chown(target, 1, 0); err != nil {
					t.Fatal(err)
				}
			case "unsafe-parent":
				if err := os.Chmod(filepath.Dir(alias), 0777); err != nil {
					t.Fatal(err)
				}
			case "unsafe-target":
				if err := os.Chmod(target, 0777); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, _, err := reviewOwnedScriptInterpreter(alias, target, base); err == nil {
				t.Fatal("unsafe interpreter alias accepted")
			}
		})
	}
}

// Mount proc only in the child namespace and chroot into a private fixture.
// The shared production parser is exercised with exact /opt paths while the
// firmware /bin/sh deliberately is not a POSIX executable. Host /opt is untouched.
func TestNativeScriptInterpreterProductionEntwareSelection(t *testing.T) {
	if root := os.Getenv("RAZVILKA_SCRIPT_INTERPRETER_CHROOT"); root != "" {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := syscall.Unshare(syscall.CLONE_NEWNS); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mount("proc", filepath.Join(root, "proc"), "proc", 0, ""); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Chroot(root); err != nil {
			t.Fatal(err)
		}
		if err := os.Chdir("/"); err != nil {
			t.Fatal(err)
		}
		path, _, current, err := reviewScriptInterpreter("/opt")
		if err != nil || path != "/opt/bin/busybox" {
			t.Fatal("production selected firmware shell", path, err)
		}
		if err := current(); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		admit := func(_ context.Context, _ string, begin func() error) error { return begin() }
		guard := func() error { return nil }
		// This is the exact shared parser used by ordinary and external bootstrap
		// preflight; their distinct producer/authority guards remain separate.
		if err := runReviewedScriptSyntax(ctx, "/opt", "/opt/script.sh", admit, guard, guard, guard); err != nil {
			t.Fatal("production Entware syntax parser failed", err)
		}
		if _, err := os.Lstat("/opt/executed"); !os.IsNotExist(err) {
			t.Fatal("preflight executed script", err)
		}
		command, check, closeProgram, err := newReviewedScriptCommand(ctx, "/opt", []string{"/opt/script.sh"})
		if err != nil {
			t.Fatal(err)
		}
		defer closeProgram()
		command.Env = commandEnvironment()
		if err := check(); err != nil {
			t.Fatal(err)
		}
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatal("held production init interpreter failed", err, string(output))
		}
		if err := check(); err != nil {
			t.Fatal(err)
		}
		if data, err := os.ReadFile("/opt/executed"); err != nil || string(data) != "executed" {
			t.Fatal("held init command was not executed", err)
		}
		return
	}
	base, _, target, _ := nativeScriptInterpreterFixture(t)
	root := filepath.Join(base, "production-root")
	for _, name := range []string{"opt/bin", "bin", "proc", "dev"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0755); err != nil {
			t.Fatal(err)
		}
	}
	// exec's nil stdin opens /dev/null. A private empty read-only fixture
	// file provides EOF; no host device or global mount is changed.
	if err := os.WriteFile(filepath.Join(root, "dev/null"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "opt/bin/busybox"), data, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/opt/bin/busybox", filepath.Join(root, "opt/bin/sh")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin/sh"), []byte("firmware CLI is not a POSIX shell"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "opt/script.sh"), []byte("printf executed > /opt/executed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "-test.run=^TestNativeScriptInterpreterProductionEntwareSelection$", "-test.count=1")
	command.Env = append(os.Environ(), "RAZVILKA_SCRIPT_INTERPRETER_CHROOT="+root)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatal("isolated production shell fixture failed", err, string(output))
	}
}
