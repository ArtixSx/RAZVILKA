//go:build linux

package components

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/backendprofile"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestMihomoOfficialProbeOwnsNativeStartWaitAndPendingCleanup(t *testing.T) {
	archive := os.Getenv("RAZVILKA_MIHOMO_ARCHIVE")
	if archive == "" {
		t.Skip("requires official pinned gzip asset")
	}
	m, info := mihomoReleaseFixture(t)
	compressed, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	image, err := m.stageMihomoArtifact(context.Background(), compressed, info.PinnedSHA256, mihomoFixtureAdmission)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.installMihomoImage(context.Background(), info, image, mihomoFixtureAdmission, mihomoFixtureAdmission); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"complete", "cancel", "panic", "pending"} {
		t.Run(scenario, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "control")
			if _, err := operationgate.InitializeSelfUpdateControl(context.Background(), root); err != nil {
				t.Fatal(err)
			}
			gate := &operationgate.Gate{}
			held, release, err := gate.ExclusiveContext(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			control, err := gate.ReviewControlEpoch(held, root)
			if err != nil {
				t.Fatal(err)
			}
			defer control.Close()
			cleanup, err := control.ReviewExclusiveCleanup(held)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(held, 20*time.Second)
			defer cancel()
			reservation, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := reservation.Addr().(*net.TCPAddr).Port
			_ = reservation.Close()
			raw := "vless://123e4567-e89b-12d3-a456-426614174000@edge.example:443?security=tls&sni=edge.example&type=tcp"
			options := backendprofile.MihomoOptions{SOCKSPort: port}
			config, err := backendprofile.Mihomo(raw, options)
			if err != nil {
				t.Fatal(err)
			}
			source, err := m.ReviewMihomoProbe(ctx, raw, options, digest([]byte(config.Config)), "edge.example", netip.MustParseAddr("1.1.1.2"), mihomoFixtureAdmission)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			var observed *MihomoProbeProcess
			var native *mihomoProbeNativeLinux
			panicked := false
			func() {
				defer func() {
					if value := recover(); value != nil {
						if value != "fixture panic" {
							panic(value)
						}
						panicked = true
					}
				}()
				_, err = source.RunProbe(ctx, control, cleanup, func(ctx context.Context, child *MihomoProbeProcess) error {
					observed = child
					native = child.native.(*mihomoProbeNativeLinux)
					if child.PID() < 1 || source.Close() != ErrMihomoProbePending || source.CleanupProbe(ctx) != ErrMihomoProbePending {
						t.Fatal("live borrower was released")
					}
					for kind, path := range map[string]string{"binary": "exe", "profile": "fd/4", "home": "fd/5"} {
						info, e := os.Stat(fmt.Sprintf("/proc/%d/%s", child.PID(), path))
						if e != nil || !child.MatchesFile(kind, info) {
							t.Fatal("child changed original file", kind, e)
						}
					}
					// Actual SOCKS protocol greeting; this is process proof only,
					// never an external-service, route or WAN result.
					for {
						c, e := (&net.Dialer{Timeout: 50 * time.Millisecond}).DialContext(ctx, "tcp4", fmt.Sprintf("127.0.0.1:%d", port))
						if e == nil {
							_ = c.SetDeadline(time.Now().Add(time.Second))
							_, e = c.Write([]byte{5, 1, 0})
							var answer [2]byte
							if e == nil {
								_, e = io.ReadFull(c, answer[:])
							}
							_ = c.Close()
							if e != nil || answer != [2]byte{5, 0} {
								t.Fatal("native SOCKS greeting", e)
							}
							break
						}
						select {
						case <-ctx.Done():
							return ctx.Err()
						case <-time.After(20 * time.Millisecond):
						}
					}
					switch scenario {
					case "cancel":
						cancel()
					case "panic":
						panic("fixture panic")
					case "pending":
						_ = control.Close()
					}
					return nil
				})
			}()
			if observed == nil || native == nil {
				t.Fatal("actual child missing", err)
			}
			if scenario == "pending" {
				if err == nil || !errors.Is(source.Close(), ErrMihomoProbePending) {
					t.Fatal("unknown cleanup lost original owner", err)
				}
				// Fixture teardown uses the held actual child only. This is not
				// a production recovery grant or a reconstructed PID kill.
				if e := native.command.Process.Kill(); e != nil {
					t.Fatal(e)
				}
				select {
				case <-native.done:
				case <-time.After(3 * time.Second):
					t.Fatal("sole Wait not joined")
				}
				bounded, finish := context.WithTimeout(context.Background(), time.Second)
				defer finish()
				if e := source.CleanupProbe(bounded); e != nil {
					t.Fatal(e)
				}
			} else if scenario == "complete" && err != nil || scenario == "cancel" && err == nil || scenario == "panic" && !panicked {
				t.Fatal(scenario, err, panicked)
			}
			if !native.closed || source.probe != nil || observed.Current(context.Background()) == nil {
				t.Fatal("native cleanup incomplete")
			}
			if e := source.Close(); e != nil {
				t.Fatal(e)
			}
			if _, e := source.RunProbe(ctx, control, cleanup, func(context.Context, *MihomoProbeProcess) error { t.Fatal("replayed native process"); return nil }); e == nil {
				t.Fatal("source replayed")
			}
		})
	}
}
