//go:build linux

package components

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/backendprofile"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func TestMihomoLiveStartBarrierPanicLateRepeatAndCancellation(t *testing.T) {
	archive := os.Getenv("RAZVILKA_MIHOMO_ARCHIVE")
	if archive == "" {
		t.Skip("official native asset required")
	}
	compressed, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	m, info := mihomoReleaseFixture(t)
	image, err := m.stageMihomoArtifact(context.Background(), compressed, info.PinnedSHA256, mihomoFixtureAdmission)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := m.installMihomoImage(context.Background(), info, image, mihomoFixtureAdmission, mihomoFixtureAdmission); err != nil || !result.OK {
		t.Fatal(result, err)
	}
	for _, scenario := range []string{"skip", "repeat", "error", "panic-before", "panic-after", "foreign-thread", "cancel-during", "cleanup-during-start"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			source, err := m.OpenMihomoLiveSource(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			gate := &operationgate.Gate{}
			root := filepath.Join(t.TempDir(), "control")
			if _, err := operationgate.InitializeSelfUpdateControl(ctx, root); err != nil {
				t.Fatal(err)
			}
			held, release, err := gate.ExclusiveContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			control, err := gate.ReviewControlEpoch(held, root)
			if err != nil {
				t.Fatal(err)
			}
			cleanup, err := gate.ReviewExclusiveCleanup(held)
			if err != nil {
				control.Close()
				t.Fatal(err)
			}
			reservation, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				control.Close()
				t.Fatal(err)
			}
			port := reservation.Addr().(*net.TCPAddr).Port
			reservation.Close()
			raw := "vless://123e4567-e89b-12d3-a456-426614174000@edge.example:443?security=tls&sni=edge.example&type=tcp"
			options := backendprofile.MihomoOptions{SOCKSPort: port}
			base, err := backendprofile.Mihomo(raw, options)
			if err != nil {
				control.Close()
				t.Fatal(err)
			}
			profile, err := source.ReviewProfile(held, raw, options, digest([]byte(base.Config)), "edge.example", netip.MustParseAddr("1.1.1.2"))
			if err != nil {
				control.Close()
				t.Fatal(err)
			}
			child, err := source.ReserveLiveChild(held, profile, control, cleanup)
			if err != nil {
				control.Close()
				t.Fatal(err)
			}
			defer func() {
				cleanCtx, done := context.WithTimeout(context.WithoutCancel(held), 5*time.Second)
				defer done()
				if err := child.Cleanup(cleanCtx, cleanup); err != nil {
					t.Error("original test child cleanup", err)
				}
			}()
			apply, cancelApply := context.WithCancel(held)
			defer cancelApply()
			var late func() error
			entered, resume := make(chan struct{}), make(chan struct{})
			resumed := false
			defer func() {
				if !resumed {
					close(resume)
				}
			}()
			admission := func(_ context.Context, begin func() error) error {
				late = begin
				switch scenario {
				case "skip":
					return nil
				case "panic-before":
					panic("actual live barrier panic")
				case "foreign-thread":
					reply := make(chan error, 1)
					go func() { reply <- begin() }()
					<-reply
					return nil
				}
				if err := begin(); err != nil {
					return err
				}
				switch scenario {
				case "repeat":
					_ = begin()
				case "error":
					return errors.New("actual live barrier error")
				case "panic-after":
					panic("actual live barrier panic")
				case "cancel-during":
					cancelApply()
					return apply.Err()
				case "cleanup-during-start":
					close(entered)
					<-resume
				}
				return nil
			}
			panicked := false
			start := func() (err error) {
				defer func() {
					if value := recover(); value != nil {
						if value != "actual live barrier panic" {
							panic(value)
						}
						panicked = true
					}
				}()
				return child.StartAdmitted(apply, admission)
			}
			if scenario == "cleanup-during-start" {
				reply := make(chan error, 1)
				go func() { reply <- start() }()
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal("actual Start never entered", ctx.Err())
				}
				short, done := context.WithTimeout(held, 50*time.Millisecond)
				if err := child.Cleanup(short, cleanup); !errors.Is(err, context.DeadlineExceeded) {
					done()
					t.Fatal("in-flight actor cleanup fabricated completion", err)
				}
				done()
				if source.Close() == nil {
					t.Fatal("in-flight original owner released")
				}
				close(resume)
				resumed = true
				if err := <-reply; err != nil {
					t.Fatal("joined original Start", err)
				}
			} else {
				err = start()
				if scenario == "panic-before" || scenario == "panic-after" {
					if !panicked {
						t.Fatal("panic lost")
					}
				} else if err == nil {
					t.Fatal("bad barrier became successful Start")
				}
			}
			if late == nil || late() == nil {
				t.Fatal("late retained callback admitted after return or panic")
			}
			if scenario == "skip" || scenario == "panic-before" || scenario == "foreign-thread" {
				if child.PID() != 0 {
					t.Fatal("denied actor created runtime")
				}
			}
			if scenario == "cancel-during" && !errors.Is(err, context.Canceled) {
				t.Fatal("original cancellation lost", err)
			}
			if err := child.Cleanup(held, cleanup); err != nil {
				t.Fatal("same original child did not join", err)
			}
			if err := source.Close(); err != nil {
				t.Fatal("source lease retained after known cleanup", err)
			}
		})
	}
}
