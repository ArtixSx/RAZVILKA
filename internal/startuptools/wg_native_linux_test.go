//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Reuse the existing original Provider/profile native fixture. This only
// proves acquisition/version/closure and unadmitted refusal, never a native
// WG route, handshake, App Ready or a fake CommandAdmission effect proof.
func TestProductionStartupWGNative(t *testing.T) {
	engine, mode := os.Getenv("RAZVILKA_STARTUP_WG_NATIVE"), os.Getenv("RAZVILKA_STARTUP_TOOLS_NATIVE")
	if engine == "" {
		t.Skip("Root WG startup source native opt-in disabled")
	}
	if engine != "wireguard" && engine != "amneziawg" || mode != "ubuntu-legacy" && mode != "stock-nc1812" {
		t.Fatal("explicit existing platform/backend profile required")
	}
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	setup, cancelSetup := context.WithTimeout(lifetime, operationTimeout)
	provider := nativeProvider(t, setup, mode)
	cancelSetup()
	t.Setenv("LD_PRELOAD", "/unreviewed-wg-preload.so")
	t.Setenv("LD_LIBRARY_PATH", "/unreviewed-wg-libraries")
	started := time.Now()
	l, err := acquireWG(lifetime, provider, wgProfile(mode == "stock-nc1812", engine))
	if err != nil {
		t.Fatalf("actual WG acquisition refused: ms=%d stages=%s", time.Since(started).Milliseconds(), nativeStages(err))
	}
	defer l.Close()
	tools, err := l.WGCommandTools(engine)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.PolicyRuntimeTools(); err != nil {
		t.Fatal("same lease lost IP/xtables", err)
	}
	read, cancelRead := context.WithTimeout(lifetime, operationTimeout)
	defer cancelRead()
	if err := tools.Runner.CheckWG(read, tools.Identity); err != nil {
		t.Fatalf("actual held closure check: %s", nativeStages(err))
	}
	primary := 0
	if engine == "amneziawg" {
		primary = 1
	}
	err = func() error {
		if err := l.lock(read); err != nil {
			return err
		}
		defer l.unlock()
		return provider.WithCurrent(read, func(held context.Context, actual netidentity.Identity) error {
			if actual != l.identity {
				return at("WG_VERSION_IDENTITY", nil)
			}
			data, err := l.execute(held, primary+3, 256, "--version")
			if err != nil || !validWGVersion(primary, data) {
				return at("WG_VERSION", err)
			}
			return held.Err()
		})
	}()
	if err != nil {
		t.Fatalf("actual held version: %s", nativeStages(err))
	}
	name := tools.WG
	if engine == "amneziawg" {
		name = tools.AWG
	}
	if out, err := tools.Runner.RunWG(read, nil, name, "show", "all", "public-key"); !errors.Is(err, ErrUnknown) || len(out) != 0 {
		t.Fatal("descriptor alone issued command", err)
	}
	t.Logf("actual WG source acquisition-ms=%d images=%d bytes=%d review=%s; no effect admission", time.Since(started).Milliseconds(), len(l.review.images), l.review.bytes, l.digest)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tools.Runner.CheckWG(read, tools.Identity); !errors.Is(err, ErrUnknown) {
		t.Fatal("saved source survived Close", err)
	}
}
