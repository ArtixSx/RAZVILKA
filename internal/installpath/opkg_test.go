package installpath

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestEntwareOpkgFixedDiscovery(t *testing.T) {
	for _, tc := range []struct {
		name      string
		available map[string]string
		want      string
		calls     []string
	}{
		{"bin-first", map[string]string{"/opt/bin/opkg": "/storage/usb/bin/opkg", "/opt/sbin/opkg": "/opt/sbin/opkg"}, "/opt/bin/opkg", []string{"/opt/bin/opkg"}},
		{"sbin", map[string]string{"/opt/sbin/opkg": "/storage/usb/sbin/opkg"}, "/opt/sbin/opkg", []string{"/opt/bin/opkg", "/opt/sbin/opkg"}},
		{"missing", nil, "", []string{"/opt/bin/opkg", "/opt/sbin/opkg"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			got := entwareOpkg(func(path string) (string, error) {
				calls = append(calls, path)
				if result, ok := tc.available[path]; ok {
					return result, nil
				}
				return "", os.ErrNotExist
			})
			if got != tc.want || !reflect.DeepEqual(calls, tc.calls) {
				t.Fatalf("got %q calls %v", got, calls)
			}
		})
	}
}

func TestEntwareOpkgDoesNotDiscoverFirmwarePATH(t *testing.T) {
	dir := t.TempDir()
	name := "opkg"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte("lookup fixture only; never executed"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if _, err := exec.LookPath("opkg"); err != nil {
		t.Fatal("PATH control unavailable", err)
	}
	var absoluteCalls int
	got := entwareOpkg(func(path string) (string, error) {
		if path == "/opt/bin/opkg" || path == "/opt/sbin/opkg" {
			absoluteCalls++
			return "", os.ErrNotExist
		}
		return exec.LookPath(path)
	})
	if got != "" || absoluteCalls != 2 {
		t.Fatalf("firmware discovered: %q, fixed lookups %d", got, absoluteCalls)
	}
}

func TestEntwareOpkgRequiresExecutable(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "not-executable")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{dir, file} {
		// Windows LookPath uses extension policy rather than Unix mode bits.
		if _, err := exec.LookPath(target); err == nil {
			t.Fatalf("negative lookup control executable: %s", target)
		}
		if got := entwareOpkg(func(string) (string, error) { return exec.LookPath(target) }); got != "" {
			t.Fatal("non-executable accepted", got)
		}
	}
	if got := entwareOpkg(func(string) (string, error) { return "", errors.New("permission denied") }); got != "" {
		t.Fatal(got)
	}
}
