package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

func selfUpdateReadRoots(base string) selfUpdateJournalRoots {
	return selfUpdateJournalRoots{installation: filepath.Join(base, "installation"), helper: filepath.Join(base, "helper"), files: filepath.Join(base, "files")}
}

func selfUpdateReadCLI(t *testing.T, base string, args ...string) (string, string, int) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, exe, append([]string{"-test.run=^TestSelfUpdateStartupSubprocess$", "--"}, args...)...)
	command.Env = append(os.Environ(), "RAZVILKA_SELF_UPDATE_BOOTSTRAP_TEST=1", "RAZVILKA_SELF_UPDATE_READER_FIXTURE_TEST="+base)
	var output, diagnostic bytes.Buffer
	command.Stdout, command.Stderr = &output, &diagnostic
	err = command.Run()
	if ctx.Err() != nil {
		t.Fatal("CLI exceeded its bounded lifetime", ctx.Err())
	}
	code := 0
	if err != nil {
		if exited, ok := err.(*exec.ExitError); ok {
			code = exited.ExitCode()
		} else {
			t.Fatal(err)
		}
	}
	return output.String(), diagnostic.String(), code
}

func selfUpdateReadTree(t *testing.T, root string) map[string][]byte {
	t.Helper()
	image := map[string][]byte{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			image[path] = nil
			return nil
		}
		image[path], err = os.ReadFile(path)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return image
}

func selfUpdateReadFixture(t *testing.T, stopped bool) (string, selfUpdateJournalRoots) {
	t.Helper()
	base := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	roots := selfUpdateReadRoots(base)
	candidates := filepath.Join(base, "candidates")
	for _, dir := range []string{roots.files, candidates} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	var files []selfupdatejournal.File
	for _, target := range []string{"bin/razvilka", "etc/init.d/S99razvilka", "etc/razvilka/config.json", "etc/razvilka/service-catalog.json", "etc/razvilka/community-catalog.json", "etc/razvilka/sources.json"} {
		installed := filepath.Join(roots.installation, filepath.FromSlash(target))
		if err := os.MkdirAll(filepath.Dir(installed), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(installed, []byte("old "+target), 0600); err != nil {
			t.Fatal(err)
		}
		data := []byte("new " + target)
		candidate := filepath.Join(candidates, filepath.Base(target))
		if err := os.WriteFile(candidate, data, 0600); err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(data)
		files = append(files, selfupdatejournal.File{Target: target, Candidate: candidate, SHA256: hex.EncodeToString(hash[:])})
	}
	store, err := selfupdatejournal.Open(roots.installation, roots.files)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx, id := context.Background(), strings.Repeat("a", 32)
	// Fixture-only evidence. No process or production settlement is invoked.
	check := func(context.Context) error { return nil }
	if err := store.Prepare(ctx, id, files, check, check); err != nil {
		t.Fatal(err)
	}
	if err := store.Install(ctx, id, check, check); err != nil {
		t.Fatal(err)
	}
	if err := store.Restore(ctx, id, check, check); err != nil {
		t.Fatal(err)
	}
	if stopped {
		binding := selfupdatejournal.StoppedBinding{InstallationID: strings.Repeat("b", 32), PreStopSequence: 1, StopSequence: 2, Revision: 7, RequiredReader: 3}
		if err := store.SettleStoppedRollback(ctx, id, binding, check, check, check); err != nil {
			t.Fatal(err)
		}
	}
	return base, roots
}

func TestSelfUpdateImmutableReaderCLIBypassesStopAndScanner(t *testing.T) {
	base := t.TempDir()
	roots := selfUpdateReadRoots(base)
	if err := os.Mkdir(roots.files, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(roots.files, "current.json"), []byte("private-invalid-retained"), 0600); err != nil {
		t.Fatal(err)
	}
	control := filepath.Join(base, "control")
	if _, err := operationgate.RequestSelfUpdateStop(context.Background(), control, strings.Repeat("a", 32), 7); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RAZVILKA_SELF_UPDATE_CONTROL_STATE", control)
	before := selfUpdateReadTree(t, base)
	for flag, expected := range map[string]string{"-self-update-read-version": "3\n", "-self-update-schema": "0\n"} {
		out, diagnostic, code := selfUpdateReadCLI(t, base, flag)
		if code != 0 || out != expected || diagnostic != "" {
			t.Fatal("immutable metadata acquired a startup/scanner dependency", flag, out, diagnostic, code)
		}
	}
	if !reflect.DeepEqual(before, selfUpdateReadTree(t, base)) {
		t.Fatal("metadata changed retained Stop or bootstrapped files")
	}
	for _, args := range [][]string{{"-self-update-read-version=true"}, {"--self-update-read-version"}, {"-self-update-read-version", "-config", filepath.Join(base, "new-config")}, {"-check-self-update-state=false"}, {"-check-self-update-state", "-self-update-installation", base}} {
		out, diagnostic, code := selfUpdateReadCLI(t, base, args...)
		if code != 2 || out != "" || !strings.Contains(diagnostic, "exact standalone flag") {
			t.Fatal("noncanonical metadata arguments reached startup", args, out, diagnostic, code)
		}
	}
	if !reflect.DeepEqual(before, selfUpdateReadTree(t, base)) {
		t.Fatal("invalid metadata arguments caused effects")
	}
}

func TestSelfUpdateFixedRetainedCLIEmptyAndPublicOverrides(t *testing.T) {
	base := filepath.Join(t.TempDir(), "absent")
	out, diagnostic, code := selfUpdateReadCLI(t, base, "-check-self-update-state")
	if code != 0 || out != "{\"ok\":true}\n" || diagnostic != "" {
		t.Fatal("empty read-only deployment refused", out, diagnostic, code)
	}
	if _, err := os.Stat(base); !os.IsNotExist(err) {
		t.Fatal("empty scan created roots", err)
	}
	base = t.TempDir()
	roots := selfUpdateReadRoots(base)
	if err := os.Mkdir(roots.helper, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(roots.helper, "current.json"), []byte("private-controller-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(base, "public-override")
	for _, variable := range []string{"RAZVILKA_SELF_UPDATE_INSTALLATION", "RAZVILKA_SELF_UPDATE_HELPER_STATE", "RAZVILKA_SELF_UPDATE_FILE_STATE", "RAZVILKA_SELF_UPDATE_CONTROL_STATE", "RAZVILKA_CONFIG"} {
		t.Setenv(variable, other)
	}
	before := selfUpdateReadTree(t, base)
	out, diagnostic, code = selfUpdateReadCLI(t, base, "-check-self-update-state")
	if code != 3 || out != "" || diagnostic != errSelfUpdateJournalState.Error()+"\n" || strings.Contains(diagnostic, "private-controller-secret") {
		t.Fatal("public override bypassed retained scanner or leaked data", out, diagnostic, code)
	}
	if !reflect.DeepEqual(before, selfUpdateReadTree(t, base)) {
		t.Fatal("refused scanner changed retained files or public roots")
	}
}

func TestSelfUpdateRetainedReaderVersionsAndFutureCLI(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("actual retained scanner requires Linux root-owned fixtures; Root runs this case")
	}
	for _, stopped := range []bool{false, true} {
		base, roots := selfUpdateReadFixture(t, stopped)
		before := selfUpdateReadTree(t, base)
		if err := checkSelfUpdateJournalState(context.Background(), roots, 3); err != nil {
			t.Fatal("current reader refused known retained formats", err)
		}
		if err := checkSelfUpdateJournalState(context.Background(), roots, 2); (err != nil) != stopped {
			t.Fatal("reader2/3 boundary changed", stopped, err)
		}
		out, diagnostic, code := selfUpdateReadCLI(t, base, "-check-self-update-state")
		if code != 0 || out != "{\"ok\":true}\n" || diagnostic != "" || !reflect.DeepEqual(before, selfUpdateReadTree(t, base)) {
			t.Fatal("actual CLI refused or changed known retained images", stopped, out, diagnostic, code)
		}
		// A future archived receipt must fence even with a readable current.
		data, err := os.ReadFile(filepath.Join(roots.files, strings.Repeat("a", 32), "receipt.json"))
		if err != nil {
			t.Fatal(err)
		}
		var receipt selfupdatejournal.Receipt
		if err := json.Unmarshal(data, &receipt); err != nil {
			t.Fatal(err)
		}
		receipt.ID, receipt.Schema = strings.Repeat("c", 32), 4
		data, err = json.Marshal(receipt)
		if err != nil {
			t.Fatal(err)
		}
		archive := filepath.Join(roots.files, receipt.ID)
		if err := os.Mkdir(archive, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(archive, "receipt.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
		before = selfUpdateReadTree(t, base)
		out, diagnostic, code = selfUpdateReadCLI(t, base, "-check-self-update-state")
		if code != 3 || out != "" || diagnostic != errSelfUpdateJournalState.Error()+"\n" || !reflect.DeepEqual(before, selfUpdateReadTree(t, base)) {
			t.Fatal("future retained archive bypassed current-only observation", out, diagnostic, code)
		}
	}
}

func TestSelfUpdateRetainedGatePrecedesStartupAndEarlyHelpers(t *testing.T) {
	base := t.TempDir()
	roots := selfUpdateReadRoots(base)
	if err := os.Mkdir(roots.files, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(roots.files, "current.json"), []byte(`{"schema":4,"private":"never-emit"}`), 0600); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 32)
	configPath, stage := filepath.Join(base, "config.json"), filepath.Join(base, "stage")
	other := filepath.Join(base, "override")
	for _, variable := range []string{"RAZVILKA_SELF_UPDATE_INSTALLATION", "RAZVILKA_SELF_UPDATE_HELPER_STATE", "RAZVILKA_SELF_UPDATE_FILE_STATE", "RAZVILKA_SELF_UPDATE_CONTROL_STATE", "RAZVILKA_DATAPLANE_STATE", "RAZVILKA_COMPONENT_STATE"} {
		t.Setenv(variable, filepath.Join(other, variable))
	}
	before := selfUpdateReadTree(t, base)
	for _, args := range [][]string{
		{"-config", configPath, "-stage", stage, "-migrate-config", "-self-update-installation", other, "-self-update-file-state", other + "-files", "-self-update-helper-state", other + "-helper"},
		{"self-update-helper", id}, {"self-update-command-helper", id, "restore-private-state"},
		{"self-update-runtime-quiesce", id, "7", "2"}, {"self-update-files", "restore", id, "7"},
		{"nfqws-managed-process-supervisor", id}, {"component-package-supervisor", id, "xray", "upgrade"},
		{"component-package-supervision-probe"}, {"components", "--refresh"}, {"component", "plan", "xray", "install", "--refresh"},
	} {
		out, diagnostic, code := selfUpdateReadCLI(t, base, args...)
		if code == 0 || out != "" || diagnostic != errSelfUpdateJournalState.Error()+"\n" {
			t.Fatal("early producer bypassed retained gate", args, out, diagnostic, code)
		}
		if !reflect.DeepEqual(before, selfUpdateReadTree(t, base)) {
			t.Fatal("refusal changed protocol/config/control/runtime paths", args)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if boundedSelfUpdateJournalState(ctx, selfUpdateReadRoots(filepath.Join(base, "absent"))) == nil {
		t.Fatal("canceled operation authorized empty scan")
	}
}
