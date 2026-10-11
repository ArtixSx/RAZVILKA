package updatecheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

func offlineRestoreFixture(t *testing.T, large bool) (*priorArchiveFixture, selfupdatejournal.Receipt) {
	t.Helper()
	f := pairedArchiveFixture(t, large)
	retainedFile(t, f.installation, "etc/init.d/S99artem-flow", []byte("old legacy Start hook"))
	retainedFile(t, f.installation, "razvilka/log/old.log", []byte("prior log"))
	retainedFile(t, f.installation, "etc/razvilka/prior-only/unknown", []byte("opaque prior application data"))
	digest, err := f.capture(nil)
	if err != nil {
		t.Fatal(err)
	}
	r := f.receipt
	r.Schema, r.Phase = selfupdatejournal.PairedSchema, "paired-prepared"
	r.Paired = &selfupdatejournal.PairedBinding{ManifestSHA256: digest, PreparedSHA256: f.binding.ReceiptSHA256, ReviewSHA256: f.binding.ReviewSHA256, InstallationID: f.binding.InstallationID, Sequence: f.binding.Sequence, Revision: f.binding.Revision}
	for path, data := range map[string][]byte{
		"bin/razvilka":                                                []byte("new executable"),
		"etc/init.d/S99razvilka":                                      []byte("new active init"),
		"etc/init.d/S99artem-flow":                                    []byte("new active legacy init"),
		"etc/razvilka/nodes-private/known.private.json":               []byte("new mutable node data"),
		"etc/razvilka/candidate-only/file":                            []byte("candidate-only data"),
		"etc/razvilka/private-restore-native-v1/restore.private.json": []byte("new unknown native journal"),
		"etc/razvilka/private-restore-future-v9/unknown":              []byte("new future independent journal"),
		"razvilka/state/self-update-stop/current-v1.json":             []byte("current Stop is never rewound"),
		"razvilka/state/components/update-journal/future":             []byte("current unknown component evidence"),
		"razvilka/state/components/releases/runtime":                  []byte("new component bytes"),
		"razvilka/state/warp/native-enrollment/current.json":          []byte("new native enrollment bytes"),
		"razvilka/state/backups/lkg/frozen":                           []byte("new independent LKG"),
		"razvilka/cache/retained-cache":                               []byte("new cache"),
		"razvilka/log/old.log":                                        []byte("new log"),
	} {
		retainedFile(t, f.installation, filepath.FromSlash(path), data)
	}
	cfg := fileExclusionConfig(t)
	cfg.ServiceControl.Stopped = true
	data, _ := json.Marshal(cfg)
	retainedFile(t, f.installation, "etc/razvilka/config.json", data)
	return f, r
}

// This model performs real streaming/hash/staging/CAS reads on every platform.
// Its three-step exchange is not Linux renameat2 atomicity or native ownership.
func modelOfflinePriorCommit(ctx context.Context, item *offlinePriorReplacement, admission func(func() error) error) error {
	return admission(func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := filepath.Base(filepath.FromSlash(item.path))
		_, old := item.before[item.path]
		_, next := item.after[item.path]
		if old && next {
			if err := item.parent.Rename(name, item.stage+"-displaced"); err != nil {
				return err
			}
			return item.parent.Rename(item.stage, name)
		}
		if old {
			return item.parent.Rename(name, item.stage)
		}
		if next {
			return item.parent.Rename(item.stage, name)
		}
		return nil
	})
}

func runOfflineRestoreModel(f *priorArchiveFixture, receipt selfupdatejournal.Receipt, check func(context.Context) error, cut func(string) error, effects *[]string) error {
	return restorePairedOffline(f.ctx, f.installation, receipt, func(string) error { return nil }, check, func(effect string, begin func() error) error {
		*effects = append(*effects, effect)
		return begin()
	}, modelOfflinePriorCommit, cut)
}

func TestPairedOfflineRestoreStreamsFullPairAndRetainsCurrentIndependentState(t *testing.T) {
	f, receipt := offlineRestoreFixture(t, true)
	root, archive := f.open(t)
	before, _, err := readPairedPriorArchive(f.ctx, root, archive, f.binding)
	if err != nil {
		t.Fatal(err)
	}
	var effects []string
	check := func(ctx context.Context) error {
		if ctx != f.ctx {
			return ErrPairedOfflineRestore
		}
		return ctx.Err()
	}
	if err := runOfflineRestoreModel(f, receipt, check, nil, &effects); err != nil {
		t.Fatal(err)
	}
	if len(effects) < 7 {
		t.Fatal("complete pair was not restored", effects)
	}
	for path, expected := range map[string][]byte{
		"bin/razvilka":                                                bytes.Repeat([]byte("controller bytes\n"), (5<<20)/17+1),
		"etc/init.d/S99razvilka":                                      []byte(pairedOfflineInitGuard),
		"etc/init.d/S99artem-flow":                                    []byte(pairedOfflineInitGuard),
		"etc/init.d/S99artem-flow.razvilka-disabled":                  []byte(pairedOfflineInitGuard),
		"etc/razvilka/nodes-private/known.private.json":               []byte("private prior node bytes"),
		"etc/razvilka/prior-only/unknown":                             []byte("opaque prior application data"),
		"etc/razvilka/private-restore-native-v1/restore.private.json": []byte("new unknown native journal"),
		"etc/razvilka/private-restore-future-v9/unknown":              []byte("new future independent journal"),
		"razvilka/state/self-update-stop/current-v1.json":             []byte("current Stop is never rewound"),
		"razvilka/state/components/update-journal/future":             []byte("current unknown component evidence"),
		"razvilka/state/components/releases/runtime":                  bytes.Repeat([]byte("component bytes\n"), (5<<20)/16+1),
		"razvilka/state/warp/native-enrollment/current.json":          []byte("new native enrollment bytes"),
		"razvilka/state/backups/lkg/frozen":                           []byte("new independent LKG"),
		"razvilka/cache/retained-cache":                               []byte("prior cache"),
		"razvilka/log/old.log":                                        []byte("prior log"),
	} {
		actual, err := os.ReadFile(filepath.Join(f.installation, filepath.FromSlash(path)))
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatal("incorrect restored/preserved role", path, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(f.installation, "etc/razvilka/candidate-only")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("candidate-only tree survived in active namespace", err)
	}
	data, _ := os.ReadFile(filepath.Join(f.installation, "etc/razvilka/config.json"))
	cfg, _, err := config.InspectBytes(data)
	if err != nil || cfg.Revision != 8 || !cfg.SafeMode || !cfg.ServiceControl.Stopped || !fileConfigExclusionsPreserved(fileExclusionConfig(t), cfg) {
		t.Fatal("current Stop/exclusions were rewound", err)
	}
	after, _, err := readPairedPriorArchive(f.ctx, root, archive, f.binding)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("offline source evidence was mutated", err)
	}
}

func TestPairedOfflineRestoreCutsKeepOldExecutableOfflineAndRefuseOrphans(t *testing.T) {
	for _, point := range []string{"before:offline-effects", "after:offline-replace:etc/init.d/S99razvilka", "after:offline-replace:etc/razvilka/config.json", "before:offline-replace:bin/razvilka", "after:offline-replace:bin/razvilka"} {
		t.Run(point, func(t *testing.T) {
			f, receipt := offlineRestoreFixture(t, false)
			var effects []string
			failure := errors.New("simulated power cut")
			check := func(ctx context.Context) error { return ctx.Err() }
			err := runOfflineRestoreModel(f, receipt, check, func(stage string) error {
				if stage == point {
					return failure
				}
				return nil
			}, &effects)
			if err == nil {
				t.Fatal("cut ignored")
			}
			binary, _ := os.ReadFile(filepath.Join(f.installation, "bin/razvilka"))
			init, _ := os.ReadFile(filepath.Join(f.installation, "etc/init.d/S99razvilka"))
			if point == "before:offline-effects" {
				if len(effects) != 0 || string(binary) != "new executable" || string(init) != "new active init" {
					t.Fatal("effect before complete staging/readback", effects)
				}
			} else if string(init) != pairedOfflineInitGuard {
				t.Fatal("cut re-enabled prior autostart", point)
			}
			if point != "after:offline-replace:bin/razvilka" && string(binary) != "new executable" {
				t.Fatal("old executable was published before data restore")
			}
			var retryEffects []string
			if err := runOfflineRestoreModel(f, receipt, check, nil, &retryEffects); !errors.Is(err, ErrPairedOfflineOrphan) || len(retryEffects) != 0 {
				t.Fatal("retained partial stages were overwritten/adopted", err, retryEffects)
			}
		})
	}
}

func TestPairedOfflineRestoreRefusesCorruptionCurrentChangesAndOwnerLoss(t *testing.T) {
	for _, fault := range []string{"blob", "manifest", "foreign-manifest", "config", "owner", "cancel", "late-blob", "staged-tree", "archive-rebound"} {
		t.Run(fault, func(t *testing.T) {
			f, receipt := offlineRestoreFixture(t, false)
			archive := filepath.Join(f.installation, filepath.FromSlash(pairedPriorArchiveDirectory), receipt.ID)
			var effects []string
			lost := false
			check := func(ctx context.Context) error {
				if lost {
					return ErrPairedOfflineRestore
				}
				return ctx.Err()
			}
			if fault == "blob" {
				retainedFile(t, archive, "payload-00000000", []byte("corrupt"))
			}
			if fault == "manifest" {
				retainedFile(t, archive, "manifest.json", []byte("corrupt"))
			}
			if fault == "foreign-manifest" {
				receipt.Paired.ManifestSHA256 = strings.Repeat("f", 64)
			}
			cut := func(stage string) error {
				if stage == "before:offline-effects" {
					switch fault {
					case "staged-tree":
						parent := filepath.Join(f.installation, "razvilka")
						entries, err := os.ReadDir(parent)
						if err != nil {
							t.Fatal(err)
						}
						for _, entry := range entries {
							if strings.HasPrefix(entry.Name(), pairedOfflineStagePrefix) && entry.IsDir() {
								retainedFile(t, parent, filepath.Join(entry.Name(), "retained-cache"), []byte("corrupt staged cache"))
							}
						}
					case "archive-rebound":
						if err := os.Rename(archive, archive+".retained"); err != nil {
							return err
						}
						if err := os.Mkdir(archive, 0700); err != nil {
							t.Fatal(err)
						}
					}
				}
				if stage == "before:offline-stage:etc/init.d/S99razvilka" {
					switch fault {
					case "config":
						retainedFile(t, f.installation, "etc/razvilka/config.json", []byte("third config"))
					case "owner":
						lost = true
					case "cancel":
						return context.Canceled
					case "late-blob":
						retainedFile(t, archive, "payload-00000000", []byte("corrupt"))
					}
				}
				return nil
			}
			if err := runOfflineRestoreModel(f, receipt, check, cut, &effects); err == nil {
				t.Fatal("unsafe restore accepted", fault)
			}
			if len(effects) != 0 {
				t.Fatal("unsafe restore reached installation effect", fault, effects)
			}
			binary, _ := os.ReadFile(filepath.Join(f.installation, "bin/razvilka"))
			if string(binary) != "new executable" {
				t.Fatal("refusal replaced executable")
			}
		})
	}
}

func TestPairedOfflineConfigRetainsInactiveExclusionsAndRefusesUnknownFields(t *testing.T) {
	prior, _ := json.Marshal(config.Default())
	var raw map[string]json.RawMessage
	json.Unmarshal(prior, &raw)
	raw["future_application_data"] = json.RawMessage(`{"opaque":true}`)
	prior, _ = json.Marshal(raw)
	cfg := fileExclusionConfig(t)
	cfg.InactiveResourceExclusions = config.CloneResourceExclusions(cfg.NetworkPolicy.Exclusions)
	cfg.NetworkPolicy, cfg.AppliedNetworkPolicy = nil, nil
	current, _ := json.Marshal(cfg)
	if _, _, err := config.InspectBytes(current); err != nil {
		t.Fatal("current fixture", err)
	}
	if _, err := offlinePriorConfig(prior, current); !errors.Is(err, ErrPairedOfflineRestore) {
		t.Fatal("unknown prior config was rewritten/adopted", err)
	}
	delete(raw, "future_application_data")
	prior, _ = json.Marshal(raw)
	data, err := offlinePriorConfig(prior, current)
	if err != nil {
		t.Fatal(err)
	}
	restored, _, err := config.InspectBytes(data)
	if err != nil || !restored.SafeMode || !restored.ServiceControl.Stopped || !fileConfigExclusionsPreserved(cfg, restored) {
		t.Fatal("saved inactive exclusions lost", err)
	}
}
