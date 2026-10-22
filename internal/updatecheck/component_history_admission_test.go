package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

func componentAdmissionFixture(t *testing.T) *ComponentHistoryAdmission {
	t.Helper()
	a := NewComponentHistoryAdmission(3)
	a.stateRoot, a.installation = t.TempDir(), t.TempDir()
	a.executable = filepath.Join(a.installation, "bin", "razvilka")
	retainedFile(t, a.installation, "bin/razvilka", []byte("modeled installed component-reader3"))
	a.identity, a.owned = func(string) error { return nil }, func(string) error { return nil }
	a.layout = func(Deployment) error { return nil }
	a.probe = func(context.Context, selfupdatejournal.BinaryImage) (int, error) { return 3, nil }
	return a
}

// Actual typed on-disk metadata only. It issues no bundle/source/physical or
// operation authority and does not start a binary or construct a runtime.
func componentAdmissionState(t *testing.T, a *ComponentHistoryAdmission, version int, phase string) {
	t.Helper()
	state := components.ManagedUpdateState{SchemaVersion: version, TransactionID: strings.Repeat("a", 32), Component: "nfqws2", Phase: phase, BeforeVersion: "1.0", UpdatedAt: "2026-10-08T00:00:00Z"}
	var managed any
	packageName, packageFile, packageHash := "nfqws2-keenetic", "nfqws2-keenetic_1.0_arm64.ipk", strings.Repeat("c", 64)
	if version == 3 {
		manifest, err := components.ReviewedManagedNFQWSManifest("arm64")
		if err != nil {
			t.Fatal(err)
		}
		digest, err := manifest.Digest()
		if err != nil {
			t.Fatal(err)
		}
		receipt := components.ManagedNFQWSBundleReceipt{Schema: 1, ProviderID: components.ManagedNFQWSProvider, TransactionID: state.TransactionID, ManifestSHA256: digest, GenerationPath: filepath.Join(a.installation, "managed-releases", digest), Flavor: manifest.Flavor, State: "ready-idle"}
		managed = struct {
			InstallationID string                               `json:"installation_id"`
			Sequence       uint64                               `json:"sequence"`
			Revision       uint64                               `json:"revision"`
			Stage          string                               `json:"stage"`
			Manifest       components.ManagedNFQWSManifest      `json:"manifest"`
			After          components.ManagedNFQWSBundleReceipt `json:"after"`
		}{strings.Repeat("b", 32), 1, 7, ".stage-" + state.TransactionID, manifest, receipt}
		state.BeforeVersion, state.AfterVersion = "absent", manifest.Flavor
		packageName, packageFile, packageHash = "", "", ""
	}
	doc := struct {
		components.ManagedUpdateState
		Package       string `json:"package"`
		PackageFile   string `json:"package_file"`
		PackageSHA256 string `json:"package_sha256"`
		Configs       []any  `json:"configs"`
		Managed       any    `json:"managed_nfqws,omitempty"`
	}{state, packageName, packageFile, packageHash, nil, managed}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	retainedFile(t, a.stateRoot, "components/update-journal/current.json", data)
}

func componentAdmissionOldController(t *testing.T, a *ComponentHistoryAdmission) string {
	t.Helper()
	data := []byte("different modeled rollback controller")
	retainedFile(t, a.stateRoot, "update-backups/old/razvilka.bin", data)
	retainedFile(t, a.stateRoot, "update-backups/old/razvilka.sha256", []byte(digestBytes(data)))
	return filepath.Join(a.stateRoot, "update-backups", "old", "razvilka.bin")
}

func TestComponentHistoryAdmissionKeepsTypedCurrentAndRollbackReaderRequirements(t *testing.T) {
	for _, test := range []struct {
		current, retained, old, wanted int
		pass                           bool
	}{
		{2, 2, 2, 2, true}, {3, 2, 3, 3, true},
		{3, 2, 2, 3, false}, {2, 2, 3, 3, false},
		{3, 3, 2, 2, false}, {3, 3, 3, 2, true},
		{3, 3, 4, 3, true}, {4, 2, 3, 3, true}, {3, 2, 3, 4, false},
		{4, 2, 4, 4, true}, {4, 2, 3, 4, false}, {4, 3, 4, 4, true},
		{5, 2, 4, 4, false}, {4, 2, 5, 4, false},
	} {
		t.Run(fmt.Sprintf("%d/%d/%d/%d", test.current, test.retained, test.old, test.wanted), func(t *testing.T) {
			a := componentAdmissionFixture(t)
			a.currentReadVersion = test.current
			phase := components.UpdatePrepared
			if test.retained == 3 {
				phase = components.UpdateAwaitingLive
			}
			componentAdmissionState(t, a, test.retained, phase)
			componentAdmissionOldController(t, a)
			a.probe = func(context.Context, selfupdatejournal.BinaryImage) (int, error) { return test.old, nil }
			before, err := readDirectoryImage(context.Background(), a.stateRoot)
			if err != nil {
				t.Fatal(err)
			}
			err = a.CheckWrite(context.Background(), test.wanted)
			if (err == nil) != test.pass {
				t.Fatal("component format borrowed a different/current-only capability", err)
			}
			after, readErr := readDirectoryImage(context.Background(), a.stateRoot)
			if readErr != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("reader admission modified retained state", readErr)
			}
		})
	}
}

func TestComponentHistoryReadableDoesNotWaiveOldRollbackReader(t *testing.T) {
	a := componentAdmissionFixture(t)
	componentAdmissionState(t, a, 3, components.UpdateAwaitingLive)
	componentAdmissionOldController(t, a)
	a.probe = func(context.Context, selfupdatejournal.BinaryImage) (int, error) { return 2, nil }
	if err := a.CheckReadable(context.Background()); err != nil {
		t.Fatal("current reader3 could not read its typed metadata", err)
	}
	if err := a.CheckWrite(context.Background(), 3); err == nil {
		t.Fatal("readability waived actual retained oldreader2")
	}
	a.currentReadVersion = 2
	if err := a.CheckReadable(context.Background()); err == nil {
		t.Fatal("current reader2 accepted managed component3")
	}
}

func TestComponentHistoryAdmissionRejectsStateInventoryBinaryAndIdentityDrift(t *testing.T) {
	for _, change := range []string{"state-same-schema", "state-future", "new-controller", "old-binary", "current-binary", "identity", "unsealed", "helper-pending", "canceled"} {
		t.Run(change, func(t *testing.T) {
			a := componentAdmissionFixture(t)
			componentAdmissionState(t, a, 3, components.UpdateAwaitingLive)
			old := componentAdmissionOldController(t, a)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if change == "unsealed" {
				if err := os.Remove(filepath.Join(filepath.Dir(old), "razvilka.sha256")); err != nil {
					t.Fatal(err)
				}
			} else if change == "helper-pending" {
				data, _ := json.Marshal(updateRecord{Owner: updaterOwner, Job: Job{ID: strings.Repeat("a", 32), State: "ready"}})
				retainedFile(t, a.stateRoot, "self-update/current.json", data)
			}
			a.probe = func(context.Context, selfupdatejournal.BinaryImage) (int, error) {
				switch change {
				case "state-same-schema":
					componentAdmissionState(t, a, 3, components.UpdateStarted)
				case "state-future":
					retainedFile(t, a.stateRoot, "components/update-journal/current.json", []byte(`{"schema_version":5}`))
				case "new-controller":
					data := []byte("new retained controller")
					retainedFile(t, a.stateRoot, "update-backups/appeared/razvilka.bin", data)
					retainedFile(t, a.stateRoot, "update-backups/appeared/razvilka.sha256", []byte(digestBytes(data)))
				case "old-binary":
					if err := os.WriteFile(old, []byte("changed old controller"), 0600); err != nil {
						t.Fatal(err)
					}
				case "current-binary":
					if err := os.WriteFile(a.executable, []byte("changed current controller"), 0600); err != nil {
						t.Fatal(err)
					}
				case "identity":
					a.identity = func(string) error { return errors.New("current inode differs from running binary") }
				case "canceled":
					cancel()
				}
				return 3, nil
			}
			if err := a.CheckWrite(ctx, 3); err == nil {
				t.Fatal("drift/unknown admission succeeded")
			}
		})
	}
}

func TestComponentHistoryAdmissionPassesSameFiniteOriginalOperationContext(t *testing.T) {
	a := componentAdmissionFixture(t)
	componentAdmissionOldController(t, a)
	var gate operationgate.Gate
	parent, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx, release, err := gate.ExclusiveContext(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	observed := false
	a.probe = func(actual context.Context, image selfupdatejournal.BinaryImage) (int, error) {
		if actual != ctx {
			t.Fatal("component probe replaced original owned context")
		}
		if _, bounded := actual.Deadline(); !bounded || gate.WithExclusiveContext(actual, func() error { return nil }) != nil {
			t.Fatal("probe lost original finite operation owner")
		}
		observed = true
		return 3, nil
	}
	if err := gate.WithExclusiveContext(ctx, func() error { return a.CheckWrite(ctx, 3) }); err != nil || !observed {
		t.Fatal("original CORE admission did not reach typed component probe", err)
	}
	release()
	if err := gate.WithExclusiveContext(ctx, func() error { return a.CheckWrite(ctx, 3) }); err == nil {
		t.Fatal("released original operation revived reader admission")
	}
}

func TestComponentCapabilityProbeIsExactAndIndependentOfNodeAndSelfUpdate(t *testing.T) {
	for _, componentRequired := range []int{2, 3, 4} {
		for _, componentReader := range []int{1, 2, 3, 4, 5} {
			for _, nodeReader := range []int{2, 3} {
				probe := func(_ context.Context, _, flag string) (string, error) {
					switch flag {
					case "-component-update-schema":
						return strconv.Itoa(componentReader) + "\n", nil
					case "-node-history-read-version":
						return strconv.Itoa(nodeReader) + "\n", nil
					case "-self-update-schema":
						return "2\n", nil
					default:
						return "1\n", nil
					}
				}
				err := checkFileCapabilitiesForHistories(context.Background(), "sealed-controller", 3, componentRequired, probe)
				pass := componentReader >= componentRequired && componentReader <= 4 && nodeReader == 3
				if (err == nil) != pass {
					t.Fatal("independent reader requirements were conflated", componentReader, nodeReader, componentRequired, err)
				}
			}
		}
	}
	for _, output := range []string{"", "3", "03\n", "+3\n", " 3\n", "3\r\n", "3\nextra", "4", "04\n", "4\r\n", "4\nextra", "0\n", "5\n", "unknown\n"} {
		if _, err := parseComponentReadVersion(output); err == nil {
			t.Fatal("malformed/future component reader accepted", output)
		}
	}
}

func TestComponentHistoryAdmissionIncludesActualHelperControlCandidateAndJournalImages(t *testing.T) {
	adapter, updater, review := fileAdapterFixture(t)
	stateRoot := t.TempDir()
	helper := filepath.Join(stateRoot, "self-update")
	if err := os.Rename(adapter.directory, helper); err != nil {
		t.Fatal(err)
	}
	adapter.directory, updater.Directory = helper, helper
	adapter.fileJournal = filepath.Join(stateRoot, "self-update-files")
	for _, relative := range []string{"bin", "etc/init.d", "etc/razvilka"} {
		if err := os.MkdirAll(filepath.Join(adapter.installation, filepath.FromSlash(relative)), 0700); err != nil {
			t.Fatal(err)
		}
	}
	old, err := os.ReadFile(updater.record.Deployment.Executable)
	if err != nil {
		t.Fatal(err)
	}
	oldConfig, err := os.ReadFile(updater.record.Deployment.Paths["config"])
	if err != nil {
		t.Fatal(err)
	}
	updater.record.Deployment.Executable = filepath.Join(adapter.installation, "bin", "razvilka")
	updater.record.Deployment.Paths["config"] = filepath.Join(adapter.installation, "etc", "razvilka", "config.json")
	updater.Deployment = updater.record.Deployment
	for path, data := range map[string][]byte{
		updater.Deployment.Executable:                                       old,
		updater.Deployment.Paths["config"]:                                  oldConfig,
		filepath.Join(adapter.installation, "etc", "init.d", "S99razvilka"): []byte("trusted old init"),
		filepath.Join(helper, review.ID, "control.bin"):                     old,
	} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	review.Files = reviewedFileList(filepath.Join(helper, review.ID), *updater.record.Job.Release, updater.record.Files, review.MigratedConfigSHA256)
	saveStoppedReview(t, adapter, updater, review)
	if err := os.MkdirAll(adapter.fileJournal, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := selfupdatejournal.Open(adapter.installation, adapter.fileJournal)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	check := func(context.Context) error { return nil } // file-state model only
	if err := store.Prepare(ctx, review.ID, review.Files, check, check); err != nil {
		t.Fatal(err)
	}
	if err := store.Install(ctx, review.ID, check, check); err != nil {
		t.Fatal(err)
	}
	if err := store.Accept(ctx, review.ID, false, check, check); err != nil {
		t.Fatal(err)
	}
	updater.record.Job.State, updater.record.Job.CanApply, updater.record.Job.CanCancel = "completed", false, false
	if err := updater.persistLocked(); err != nil {
		t.Fatal(err)
	}
	if err := archiveHelperRecord(helper, updater.record); err != nil {
		t.Fatal(err)
	}
	a := componentAdmissionFixture(t)
	a.stateRoot, a.installation, a.executable = stateRoot, adapter.installation, updater.Deployment.Executable
	currentSHA, err := hashRegularFile(a.executable, MaximumBinaryBytes)
	if err != nil {
		t.Fatal(err)
	}
	images, err := a.controllerImages(ctx, currentSHA)
	if err != nil {
		t.Fatal("actual terminal upgrade/current new image refused", err)
	}
	wanted := []string{a.executable, filepath.Join(helper, review.ID, "control.bin"), review.Files[0].Candidate, filepath.Join(adapter.fileJournal, review.ID, "old-0"), filepath.Join(adapter.fileJournal, review.ID, "new-0")}
	for _, path := range wanted {
		found := false
		for _, image := range images {
			found = found || image.Path == path
		}
		if !found {
			t.Fatal("actual helper/candidate/retained controller missing", path)
		}
	}
	if err := a.CheckWrite(ctx, 3); err != nil {
		t.Fatal("actual sealed fleet of modeled reader3 refused", err)
	}
	for _, oldReader := range []string{filepath.Join(helper, review.ID, "control.bin"), filepath.Join(adapter.fileJournal, review.ID, "old-0")} {
		observed := false
		a.probe = func(_ context.Context, image selfupdatejournal.BinaryImage) (int, error) {
			if image.Path == oldReader {
				observed = true
				return 2, nil
			}
			return 3, nil
		}
		if err := a.CheckWrite(ctx, 3); err == nil || !observed {
			t.Fatal("actual retained/control oldreader2 was waived", err)
		}
	}
}
