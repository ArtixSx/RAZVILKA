//go:build linux

package components

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// These exercise an actual abrupt subprocess exit and durable file recovery,
// with explicitly modeled executable bytes and no runtime inactivity claim.
func TestMihomoReplacementCrashParticipant(t *testing.T) {
	root := os.Getenv("RAZVILKA_MIHOMO_REPLACEMENT_CRASH_ROOT")
	if root == "" {
		t.Skip("owned crash subprocess only")
	}
	m := New()
	m.BinDir = filepath.Join(root, "bin")
	m.StateDir = filepath.Join(root, "state")
	m.Arch = "amd64"
	info, err := mihomoPinnedRelease(m.Arch)
	if err != nil {
		t.Fatal(err)
	}
	image := mihomoFixtureStage(t, m, []byte("new modeled replacement image\n"))
	m.updateFault = func(point string) error {
		if point == os.Getenv("RAZVILKA_MIHOMO_REPLACEMENT_CRASH_CUT") {
			os.Exit(93)
		}
		return nil
	}
	_, err = m.installMihomoImageWithReplacement(context.Background(), info, image, mihomoFixtureAdmission, mihomoFixtureAdmission, func(ctx context.Context, r *MihomoReplacementReview) error { return r.Current(ctx) })
	t.Fatal("owned crash cut not reached", err)
}

func TestMihomoReplacementCrashRecoversExactPreviousPair(t *testing.T) {
	for _, cut := range []string{"mihomo:after:a_binary", "mihomo:after:b_receipt", "mihomo:after:c_lifecycle"} {
		t.Run(cut, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			m, info := mihomoReleaseFixture(t)
			oldInfo := info
			oldInfo.Version = "1.19.32"
			old := mihomoFixtureStage(t, m, []byte("original modeled replacement image\n"))
			if result, err := m.installMihomoImage(ctx, oldInfo, old, mihomoFixtureAdmission, mihomoFixtureAdmission); err != nil || !result.OK {
				t.Fatal(result, err)
			}
			_, _, _, paths, err := m.mihomoReleaseLayout()
			if err != nil {
				t.Fatal(err)
			}
			before := map[string][]byte{}
			for id, path := range paths {
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				before[id] = raw
			}
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMihomoReplacementCrashParticipant$", "-test.count=1")
			command.Env = append(os.Environ(), "RAZVILKA_MIHOMO_REPLACEMENT_CRASH_ROOT="+filepath.Dir(m.StateDir), "RAZVILKA_MIHOMO_REPLACEMENT_CRASH_CUT="+cut)
			output, err := command.CombinedOutput()
			if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 93 {
				t.Fatal("actual crash not observed", string(output), err)
			}
			if err := m.CheckMihomoReleaseIdle(ctx); err == nil {
				t.Fatal("abrupt replacement lost pending fence")
			}
			if outcome, err := m.RecoverMihomoRelease(ctx); err != nil || outcome != restorejournal.RolledBack {
				t.Fatal("exact original recovery failed", outcome, err)
			}
			for id, path := range paths {
				actual, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(actual, before[id]) {
					t.Fatal("old complete vector not restored", id, err)
				}
			}
			if outcome, err := m.RecoverMihomoRelease(ctx); err != nil || outcome != restorejournal.Clean {
				t.Fatal("recovery retry changed terminal result", outcome, err)
			}
		})
	}
}
