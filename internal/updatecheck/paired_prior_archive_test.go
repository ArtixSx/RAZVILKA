package updatecheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

const pairedArchiveTestID = "0123456789abcdef0123456789abcdef"

type priorArchiveFixture struct {
	installation string
	journal      string
	control      string
	ctx          context.Context
	store        *selfupdatejournal.Store
	binding      pairedPriorBinding
	receipt      selfupdatejournal.Receipt
	configHash   string
	admissions   int
}

func pairedArchiveFixture(t *testing.T, large bool) *priorArchiveFixture {
	t.Helper()
	work := t.TempDir()
	f := &priorArchiveFixture{installation: filepath.Join(work, "installation"), journal: filepath.Join(work, "file-journal"), control: filepath.Join(work, "control")}
	var cancel context.CancelFunc
	f.ctx, cancel = context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	for _, path := range []string{f.journal, filepath.Join(f.installation, "bin"), filepath.Join(f.installation, "etc/init.d"), filepath.Join(f.installation, "etc/razvilka"), filepath.Join(f.installation, "razvilka/state/components/releases"), filepath.Join(f.installation, "razvilka/cache")} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.Default()
	cfg.Revision, cfg.SafeMode = 0, false
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.configHash = digestBytes(data)
	prior := map[string][]byte{"bin/razvilka": []byte("old controller with no read capability claim"), "etc/init.d/S99razvilka": []byte("old init"), "etc/razvilka/config.json": data, "etc/razvilka/service-catalog.json": []byte("old catalog"), "etc/razvilka/community-catalog.json": []byte("old community"), "etc/razvilka/sources.json": []byte("old sources")}
	if large {
		prior["bin/razvilka"] = bytes.Repeat([]byte("controller bytes\n"), (5<<20)/17+1)
	}
	var files []selfupdatejournal.File
	for _, target := range []string{"bin/razvilka", "etc/init.d/S99razvilka", "etc/razvilka/config.json", "etc/razvilka/service-catalog.json", "etc/razvilka/community-catalog.json", "etc/razvilka/sources.json"} {
		retainedFile(t, f.installation, filepath.FromSlash(target), prior[target])
		candidate := filepath.Join(work, "candidate-"+filepath.Base(target))
		if err := os.WriteFile(candidate, []byte("candidate file"), 0600); err != nil {
			t.Fatal(err)
		}
		files = append(files, selfupdatejournal.File{Target: target, Candidate: candidate, SHA256: digestBytes([]byte("candidate file"))})
	}
	for path, content := range map[string][]byte{
		"etc/init.d/S99artem-flow.razvilka-disabled":                  []byte("prior disabled legacy init, bytes only"),
		"etc/razvilka/nodes-private/known.private.json":               []byte("private prior node bytes"),
		"etc/razvilka/private-restore-native-v1/restore.private.json": []byte("unknown retained evidence, never a retirement grant"),
		"razvilka/state/warp/native-enrollment/current.json":          []byte("unknown native outcome, preserved unchanged"),
		"razvilka/state/backups/lkg/frozen":                           []byte("paired retained LKG"),
		"razvilka/state/components/releases/runtime":                  []byte("prior component bytes"),
		"razvilka/cache/retained-cache":                               []byte("prior cache"),
	} {
		if large && path == "razvilka/state/components/releases/runtime" {
			content = bytes.Repeat([]byte("component bytes\n"), (5<<20)/16+1)
		}
		retainedFile(t, f.installation, filepath.FromSlash(path), content)
	}
	ready, err := operationgate.InitializeSelfUpdateControl(f.ctx, f.control)
	if err != nil {
		t.Fatal(err)
	}
	f.binding = pairedPriorBinding{ID: pairedArchiveTestID, ReviewSHA256: digestBytes([]byte("model immutable file review")), InstallationID: ready.InstallationID, Sequence: ready.Sequence, Revision: 0}
	f.store, err = selfupdatejournal.Open(f.installation, f.journal)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.store.Close() })
	// These local callbacks model a closed process/runtime. They exercise the
	// actual file protocol and kernel writer lease, not native/App quiescence.
	check := func(context.Context) error { return nil }
	if err := f.store.Prepare(f.ctx, pairedArchiveTestID, files, check, check); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"stop-old-panel", "prepare-private-state", "quiesce-old-runtime"} {
		if err := f.store.Execute(f.ctx, pairedArchiveTestID, command, check, check); err != nil {
			t.Fatal(err)
		}
	}
	f.receipt, _, err = f.store.Current()
	if err != nil {
		t.Fatal(err)
	}
	receipt, _ := json.Marshal(f.receipt)
	f.binding.ReceiptSHA256 = digestBytes(receipt)
	return f
}

func (f *priorArchiveFixture) check(ctx context.Context) error {
	if ctx != f.ctx {
		return errors.New("original context changed")
	}
	control, present, err := operationgate.ReadSelfUpdateStop(ctx, f.control)
	if err != nil || !present || control.Stopped || control.InstallationID != f.binding.InstallationID || control.Sequence != f.binding.Sequence {
		return ErrPairedPriorArchive
	}
	data, err := os.ReadFile(filepath.Join(f.installation, "etc/razvilka/config.json"))
	if err != nil || digestBytes(data) != f.configHash {
		return ErrReviewChanged
	}
	return ctx.Err()
}

func (f *priorArchiveFixture) capture(cut func(string) error) (string, error) {
	var result string
	err := f.store.WithPreparedPriorState(f.ctx, pairedArchiveTestID, f.check, f.check, func(ctx context.Context, receipt selfupdatejournal.Receipt) error {
		var err error
		result, err = capturePairedPriorState(ctx, f.installation, f.binding, receipt, func(string) error { return nil }, f.check, func(begin func() error) error {
			f.admissions++
			return operationgate.WithSelfUpdateEffectAdmission(ctx, f.control, pairedArchiveTestID, f.binding.InstallationID, f.binding.Sequence, pairedPriorManifestEffect, begin)
		}, cut)
		return err
	})
	if err != nil {
		return "", err
	}
	return result, nil
}

func (f *priorArchiveFixture) open(t *testing.T) (*ownedfs.Root, *os.Root) {
	t.Helper()
	path := filepath.Join(f.installation, filepath.FromSlash(pairedPriorArchiveDirectory), pairedArchiveTestID)
	root, err := ownedfs.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close(); fs.Close() })
	return root, fs
}

func priorSourceDigest(t *testing.T, f *priorArchiveFixture) string {
	t.Helper()
	root, err := ownedfs.Open(f.installation)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fs, err := os.OpenRoot(f.installation)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	doc, _, err := scanPairedPriorState(f.ctx, root, fs, nil, f.binding, func(string) error { return nil }, func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(doc)
	return digestBytes(data)
}

func TestPairedPriorArchiveCopiesCompleteLargeSourceWithoutLifecycleChange(t *testing.T) {
	f := pairedArchiveFixture(t, true)
	before := priorSourceDigest(t, f)
	current, _ := os.ReadFile(filepath.Join(f.journal, pairedArchiveTestID, "receipt.json"))
	digest, err := f.capture(nil)
	if err != nil || !validDigest("sha256:"+digest) || f.admissions != 1 {
		t.Fatal("actual source capture failed", err)
	}
	root, fs := f.open(t)
	doc, data, err := readPairedPriorArchive(f.ctx, root, fs, f.binding)
	if err != nil || digestBytes(data) != digest || doc.Binding.Revision != 0 {
		t.Fatal("complete archive unavailable", err)
	}
	if before != priorSourceDigest(t, f) {
		t.Fatal("capture changed source application/state")
	}
	after, _ := os.ReadFile(filepath.Join(f.journal, pairedArchiveTestID, "receipt.json"))
	if !bytes.Equal(current, after) {
		t.Fatal("capture changed active lifecycle")
	}
	large := 0
	for _, payload := range doc.Payloads {
		if payload.Size > 4<<20 {
			large++
		}
	}
	if large != 2 {
		t.Fatal("binary or whole component tree was truncated")
	}
	if again, err := f.capture(nil); err != nil || again != digest || f.admissions != 1 {
		t.Fatal("matching verified copy not reusable", err)
	}
	var legacy privateFileSnapshot
	if decodeFileProtocol(data, &legacy) == nil || validatePrivateSnapshot(privateFileSnapshot{Schema: pairedPriorArchiveSchema, ID: pairedArchiveTestID}) == nil {
		t.Fatal("new archive was accepted as a legacy mutable snapshot")
	}
	if _, err := f.store.RetainedBinaryImages(f.ctx); !errors.Is(err, selfupdatejournal.ErrPending) {
		t.Fatal("capture removed the active pending fence", err)
	}
}

func TestPairedPriorArchiveCutBoundariesPreserveSourceAndNoGrant(t *testing.T) {
	for _, stage := range []string{"before:payload-00000000", "after:payload-00000000", "after:copy", "before:manifest", "before:publish", "after:publish", "after:verify"} {
		t.Run(stage, func(t *testing.T) {
			f := pairedArchiveFixture(t, false)
			before := priorSourceDigest(t, f)
			cut := errors.New("capture interrupted")
			seen := false
			digest, err := f.capture(func(point string) error {
				if point == stage {
					seen = true
					return cut
				}
				return nil
			})
			if !seen || err == nil || digest != "" || before != priorSourceDigest(t, f) {
				t.Fatal("cut manufactured a grant or changed source", err)
			}
			// Reopen the actual file owner after the cut; no native operation
			// was executed/replayed. Only fully published matching copies reuse.
			f.store.Close()
			f.store, err = selfupdatejournal.Open(f.installation, f.journal)
			if err != nil {
				t.Fatal(err)
			}
			digest, err = f.capture(nil)
			committed := stage == "after:publish" || stage == "after:verify"
			if committed && (err != nil || digest == "") || !committed && (err == nil || digest != "") {
				t.Fatal("partial copy promoted or committed copy lost", err)
			}
		})
	}
}

func TestPairedPriorArchiveRefusesThirdSourceAndStopBeforePublication(t *testing.T) {
	for _, change := range []string{"bytes", "same-bytes-inode", "root-appears", "stop"} {
		t.Run(change, func(t *testing.T) {
			f := pairedArchiveFixture(t, false)
			changed := false
			digest, err := f.capture(func(stage string) error {
				if stage != "after:copy" || changed {
					return nil
				}
				changed = true
				path := filepath.Join(f.installation, "etc/razvilka/nodes-private/known.private.json")
				switch change {
				case "bytes":
					return os.WriteFile(path, []byte("third private bytes"), 0600)
				case "same-bytes-inode":
					data, err := os.ReadFile(path)
					if err != nil {
						return err
					}
					file, err := os.Stat(path)
					if err != nil {
						return err
					}
					parent, err := os.Stat(filepath.Dir(path))
					if err != nil {
						return err
					}
					if err := os.Rename(path, filepath.Join(filepath.Dir(f.installation), "foreign-prior")); err != nil {
						return err
					}
					if err := os.WriteFile(path, data, file.Mode().Perm()); err != nil {
						return err
					}
					if err := os.Chtimes(path, file.ModTime(), file.ModTime()); err != nil {
						return err
					}
					return os.Chtimes(filepath.Dir(path), parent.ModTime(), parent.ModTime())
				case "root-appears":
					return os.MkdirAll(filepath.Join(f.installation, "razvilka/log"), 0700)
				case "stop":
					_, err := operationgate.RequestSelfUpdateStop(f.ctx, f.control, pairedArchiveTestID, 0)
					return err
				}
				return nil
			})
			if !changed || err == nil || digest != "" || f.admissions != 0 {
				t.Fatal("third source/Stop admitted publication", err)
			}
		})
	}
}

func TestPairedPriorArchiveRejectsMissingCorruptAndForgedExistingCopy(t *testing.T) {
	for _, change := range []string{"payload", "payload-missing", "forged-private-source", "root-missing", "binding", "future-schema", "duplicate-field", "foreign-entry"} {
		t.Run(change, func(t *testing.T) {
			f := pairedArchiveFixture(t, false)
			if _, err := f.capture(nil); err != nil {
				t.Fatal(err)
			}
			root, fs := f.open(t)
			doc, _, err := readPairedPriorArchive(f.ctx, root, fs, f.binding)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "payload":
				if err := root.WriteAtomic(doc.Payloads[0].Blob, []byte("changed archive bytes"), 0600); err != nil {
					t.Fatal(err)
				}
			case "payload-missing":
				if err := root.Remove(doc.Payloads[0].Blob); err != nil {
					t.Fatal(err)
				}
			case "forged-private-source":
				for i, payload := range doc.Payloads {
					if payload.Name == filepath.FromSlash("nodes-private/known.private.json") {
						data := []byte("forged private image with a valid manifest digest")
						if err := root.WriteAtomic(payload.Blob, data, 0600); err != nil {
							t.Fatal(err)
						}
						doc.Payloads[i].Size, doc.Payloads[i].SHA256 = int64(len(data)), digestBytes(data)
					}
				}
			case "root-missing":
				doc.Roots = doc.Roots[:len(doc.Roots)-1]
			case "binding":
				doc.Binding.Sequence++
			case "future-schema":
				doc.Schema++
			case "foreign-entry":
				if err := root.WriteAtomic("unclaimed-private-file", []byte("foreign evidence"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if change == "forged-private-source" || change == "root-missing" || change == "binding" || change == "future-schema" || change == "duplicate-field" {
				data, _ := json.Marshal(doc)
				if change == "duplicate-field" {
					data = append([]byte(`{"schema":3,`), data[1:]...)
				}
				if err := root.WriteAtomic("manifest.json", data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := priorSourceDigest(t, f)
			if digest, err := f.capture(nil); err == nil || digest != "" || before != priorSourceDigest(t, f) {
				t.Fatal("bad existing archive supplied a grant or changed source", err)
			}
		})
	}
}

func TestPairedPriorArchivePublicationIsOneRenameOutsidePayloadWork(t *testing.T) {
	for _, skipped := range []bool{false, true} {
		f := pairedArchiveFixture(t, false)
		leaf := false
		checks := 0
		check := func(ctx context.Context) error {
			if leaf {
				t.Fatal("source/authority check entered short admission")
			}
			checks++
			return f.check(ctx)
		}
		admitted := 0
		var digest string
		err := f.store.WithPreparedPriorState(f.ctx, pairedArchiveTestID, check, check, func(ctx context.Context, receipt selfupdatejournal.Receipt) error {
			var err error
			digest, err = capturePairedPriorState(ctx, f.installation, f.binding, receipt, func(string) error { return nil }, check, func(rename func() error) error {
				admitted++
				leaf = true
				defer func() { leaf = false }()
				if skipped {
					return nil
				}
				return rename()
			}, nil)
			return err
		})
		if admitted != 1 || checks < 4 || skipped && (err == nil || digest != "") || !skipped && (err != nil || digest == "") {
			t.Fatal("publication did not enforce synchronous one-use rename", err)
		}
	}
}
