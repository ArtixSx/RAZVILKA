//go:build linux && razvilka_native_fixture

package startuptools

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func TestNativePolicyOuterNamespaceRequiresDifferentGenuineNetFD(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("actual root namespace descriptor validation; dedicated native script requires root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	regularPath := filepath.Join(t.TempDir(), "regular")
	if err := os.WriteFile(regularPath, []byte("not namespace"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/proc/self/ns/net", "/proc/self/ns/pid", regularPath} {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		lease, err := AcquireNativeFixturePolicyWithOuterNetFD(ctx, netidentity.NewProcProvider(), "/does-not-exist", file)
		if lease != nil || !errors.Is(err, errNativeFixtureOuterNamespace) {
			t.Fatal("current/wrong namespace or regular descriptor did not fail at actual kernel FD gate", path, err)
		}
		if _, err := file.Stat(); err != nil {
			t.Fatal("borrowed outer descriptor was closed", err)
		}
		file.Close()
	}
}
