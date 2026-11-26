//go:build linux

package awgprofile

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuntimeUtilityPreservesMulticallSymlinkInvocation(t *testing.T) {
	dir := t.TempDir()
	canonical, invocation := filepath.Join(dir, "kmod"), filepath.Join(dir, "modinfo")
	// An actual executable reached through a symlink selects its applet by $0,
	// like kmod/BusyBox. The fake output contains only public module metadata.
	program := "#!/bin/sh\n[ \"${0##*/}\" = modinfo ] || exit 9\n[ \"$1\" = amneziawg ] || exit 10\nprintf 'name: amneziawg\\nversion: 3.1.20260906\\n'\n"
	if err := os.WriteFile(canonical, []byte(program), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(canonical, invocation); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	inspect := nativeRuntimeInspector()
	path, err := inspect.utility("modinfo")
	if err != nil || path != invocation {
		t.Fatal("utility invocation path lost", path, err)
	}
	out, err := inspect.run(context.Background(), path, "amneziawg")
	if err != nil || !strings.Contains(out, "name: amneziawg") {
		t.Fatal("multicall invocation failed", err)
	}
	toolPath, err := inspect.look("modinfo")
	if err != nil || toolPath != canonical {
		t.Fatal("canonical AWG lookup no longer resolves executable identity", toolPath, err)
	}
	if _, err := inspect.run(context.Background(), toolPath, "amneziawg"); err == nil {
		t.Fatal("regression fixture did not reject the former canonical invocation")
	}
}
