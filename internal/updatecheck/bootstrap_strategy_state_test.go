package updatecheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
)

// Model only: the actual original producer and old HTTP-authored nonempty
// state are exercised by the separate public paired native workflow.
func bootstrapOfflineStrategyFixture(t *testing.T) (*SelfUpdateFileAdapter, *Updater, fileReview, []byte) {
	t.Helper()
	a, u, review := bootstrapOwnerFixture(t)
	review.Bootstrap.Mode = "offline"
	for _, rel := range []string{"bin", "etc/razvilka", "razvilka/state"} {
		if err := os.MkdirAll(filepath.Join(a.installation, rel), 0700); err != nil {
			t.Fatal(err)
		}
	}
	old, err := os.ReadFile(u.Deployment.Executable)
	if err != nil {
		t.Fatal(err)
	}
	retainedFile(t, a.installation, "bin/razvilka", old)
	raw := []byte("{\"schema_version\":1,\"candidates\":{},\"evidence\":[],\"selections\":{}}\n")
	retainedFile(t, a.installation, "razvilka/state/strategy-lab.json", raw)
	review.Bootstrap.OfflineStrategy = &bootstrapOfflineStrategyProof{Schema: 1, StateSchema: 1, StateSHA256: digestBytes(raw), HelperSHA256: review.Bootstrap.HelperSHA256, StateReader: StrategyLabReadVersion}
	cfg := config.Config{Revision: 7, SafeMode: true}
	configBytes, _ := json.Marshal(cfg)
	review = sealFileExclusionFixture(t, a, u, review, configBytes, append(bytes.Clone(configBytes), '\n'))
	return a, u, review, raw
}

func TestBootstrapOfflineStrategyPreservesExcludedImageAndDeniesReplay(t *testing.T) {
	a, _, review, raw := bootstrapOfflineStrategyFixture(t)
	ctx := context.Background()
	if err := a.Authority(ctx, review.ID, review.Revision); err != nil {
		t.Fatal("unchanged offline data refused", err)
	}
	if err := a.preparePrivateSnapshot(ctx, review.ID); err != nil {
		t.Fatal(err)
	}
	snapshot, err := a.privateSnapshot(ctx, review.ID)
	if err != nil || snapshot.Schema != 2 || review.StrategyPair != nil {
		t.Fatal("excluded state became ordinary pair", err)
	}
	if _, present := snapshot.Images["strategy"]; present {
		t.Fatal("offline image gained mutable replay target")
	}
	for _, action := range []string{"start/live", "replace-to-rollback"} {
		if !errors.Is(a.AuthorityAction(ctx, review.ID, review.Revision, action), ErrStrategyStateAdmission) {
			t.Fatal("excluded state granted ordinary action", action)
		}
	}
	if !errors.Is(a.restorePrivateSnapshot(ctx, review.ID), ErrStrategyStateAdmission) {
		t.Fatal("direct private restore accepted excluded state")
	}
	if _, err := a.strategyRollbackImages(ctx, review.ID, snapshot); !errors.Is(err, ErrStrategyStateAdmission) {
		t.Fatal("direct rollback images accepted excluded state", err)
	}
	if _, err := a.sealStrategyPair(ctx, review); !errors.Is(err, ErrStrategyStateAdmission) {
		t.Fatal("bootstrap gained ordinary pair seal", err)
	}
	actual, err := os.ReadFile(filepath.Join(a.installation, "razvilka/state/strategy-lab.json"))
	if err != nil || !bytes.Equal(actual, raw) {
		t.Fatal("offline read/prepare/refusals rewrote original state", err)
	}
	for _, file := range review.Files {
		if file.Target == "bin/razvilka" {
			candidate, err := os.ReadFile(file.Candidate)
			if err != nil {
				t.Fatal(err)
			}
			retainedFile(t, a.installation, "bin/razvilka", candidate)
		}
	}
	if err := a.Authority(ctx, review.ID, review.Revision); err != nil {
		t.Fatal("actual reviewed file replacement lost offline state", err)
	}
	retainedFile(t, a.installation, "razvilka/state/strategy-lab.json", append(bytes.Clone(raw), '\n'))
	if err := a.Authority(ctx, review.ID, review.Revision); !errors.Is(err, ErrStrategyStateAdmission) {
		t.Fatal("changed post-Prepare bytes accepted", err)
	}
}

func TestBootstrapOfflineStrategyRefusesDriftAndMissingOriginal(t *testing.T) {
	for _, kind := range []string{"live", "ordinary-pair", "reader", "helper", "schema", "source-bytes", "source-missing", "source-symlink", "control", "candidate", "installed", "retention", "cancel", "finalizing", "unknown", "new-state-schema"} {
		t.Run(kind, func(t *testing.T) {
			a, u, review, raw := bootstrapOfflineStrategyFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			path := filepath.Join(a.installation, "razvilka/state/strategy-lab.json")
			switch kind {
			case "live":
				review.Bootstrap.Mode = "live"
			case "ordinary-pair":
				review.StrategyPair = &strategyPairProof{Schema: 1}
			case "reader":
				review.Bootstrap.OfflineStrategy.StateReader = 999
			case "helper":
				review.Bootstrap.OfflineStrategy.HelperSHA256 = review.OldExecutableSHA256
			case "schema":
				review.Bootstrap.OfflineStrategy.Schema++
			case "source-bytes":
				retainedFile(t, a.installation, "razvilka/state/strategy-lab.json", append(bytes.Clone(raw), '\n'))
			case "source-missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "source-symlink":
				target := filepath.Join(t.TempDir(), "same.json")
				if err := os.WriteFile(target, raw, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Skip("symlink unavailable", err)
				}
			case "control":
				retainedFile(t, filepath.Join(a.directory, review.ID), "control.bin", []byte("changed"))
			case "candidate":
				for _, file := range review.Files {
					if file.Target == "bin/razvilka" {
						if err := os.WriteFile(file.Candidate, []byte("changed"), 0700); err != nil {
							t.Fatal(err)
						}
					}
				}
			case "installed":
				retainedFile(t, a.installation, "bin/razvilka", []byte("changed"))
			case "retention":
				retainedFile(t, filepath.Join(a.directory, review.ID), strategyRollbackRetentionName, []byte("unknown"))
			case "cancel":
				cancel()
			case "finalizing", "unknown", "new-state-schema":
				var state map[string]any
				if err := json.Unmarshal(raw, &state); err != nil {
					t.Fatal(err)
				}
				if kind == "finalizing" {
					state["compatibility_finalizing"] = true
				} else if kind == "unknown" {
					state["managed_probe_unknown"] = true
				} else {
					state["schema_version"] = 4
				}
				changed, _ := json.Marshal(state)
				retainedFile(t, a.installation, "razvilka/state/strategy-lab.json", changed)
				// Even a matching digest cannot turn an unsafe schema/fence into
				// compatible settled legacy state.
				review.Bootstrap.OfflineStrategy.StateSHA256 = digestBytes(changed)
			}
			publishStrategyReview(t, a, u, review)
			if err := a.Authority(ctx, review.ID, review.Revision); err == nil {
				t.Fatal("drift or fence accepted")
			}
		})
	}
	a, u, review, _ := bootstrapOfflineStrategyFixture(t)
	review.Bootstrap.OfflineStrategy = nil
	if _, err := a.sealBootstrapOfflineStrategy(context.Background(), u.record, review, nil); !errors.Is(err, ErrStrategyStateAdmission) {
		t.Fatal("missing original preparation minted proof", err)
	}
}

func TestBootstrapOfflineStrategyNilWireAndOldReaderRefusal(t *testing.T) {
	_, _, review := bootstrapOwnerFixture(t)
	type priorBinding struct {
		Role          string `json:"role"`
		Mode          string `json:"mode"`
		HelperSHA256  string `json:"helper_sha256"`
		ArchivePath   string `json:"archive_path"`
		ArchiveSHA256 string `json:"archive_sha256"`
	}
	b := review.Bootstrap
	want, _ := json.Marshal(priorBinding{b.Role, b.Mode, b.HelperSHA256, b.ArchivePath, b.ArchiveSHA256})
	got, _ := json.Marshal(b)
	if !bytes.Equal(got, want) {
		t.Fatal("nil proof changed existing review bytes")
	}
	b.Mode = "offline"
	b.OfflineStrategy = &bootstrapOfflineStrategyProof{Schema: 1}
	got, _ = json.Marshal(b)
	var old priorBinding
	if decodeFileProtocol(got, &old) == nil {
		t.Fatal("old strict reader silently accepted new offline contract")
	}
}

func TestBootstrapOfflineStrategyEmptyAndKnownReaderCompatibility(t *testing.T) {
	a, u, review := bootstrapOwnerFixture(t)
	ctx := context.Background()
	if proof, err := a.sealBootstrapOfflineStrategy(ctx, u.record, review, nil); proof != nil || err != nil {
		t.Fatal("empty live bootstrap changed its existing no-pair path", err)
	}
	for _, reader := range []int{5, StrategyLabReadVersion} {
		a, u, review, _ := bootstrapOfflineStrategyFixture(t)
		review.Bootstrap.OfflineStrategy.StateReader = reader
		publishStrategyReview(t, a, u, review)
		if err := a.Authority(ctx, review.ID, review.Revision); err != nil {
			t.Fatal("known modern reader of excluded legacy data refused", reader, err)
		}
	}
}
