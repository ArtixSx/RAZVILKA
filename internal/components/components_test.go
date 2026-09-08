package components

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	calls  [][]string
	output map[string]string
}

func TestNFQWSInstallCreatesOfficialRepositoryBeforeRefresh(t *testing.T) {
	r := &fakeRunner{output: map[string]string{"update": "ok", "install": "installed"}}
	repo := t.TempDir()
	m := &Manager{Opkg: "/opt/bin/opkg", RepoDir: repo, Runner: r}
	if _, err := m.Apply(context.Background(), "nfqws2"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(repo, "nfqws2.conf"))
	if err != nil {
		t.Fatal(err)
	}
	want := "src/gz nfqws2-keenetic https://nfqws.github.io/nfqws2-keenetic/all\n"
	if string(data) != want {
		t.Fatalf("repository=%q want=%q", data, want)
	}
	wantCalls := [][]string{{"/opt/bin/opkg", "list-installed"}, {"/opt/bin/opkg", "update"}, {"/opt/bin/opkg", "install", "nfqws2-keenetic"}, {"/opt/bin/opkg", "list-installed"}}
	if !reflect.DeepEqual(r.calls, wantCalls) {
		t.Fatalf("calls=%v want=%v", r.calls, wantCalls)
	}
}

func TestUsqueInstallUsesKeeneticPackageInsteadOfOverwritingManagedBinary(t *testing.T) {
	r := &fakeRunner{output: map[string]string{"update": "ok", "install": "installed"}}
	repo := t.TempDir()
	m := &Manager{Opkg: "/opt/bin/opkg", RepoDir: repo, Runner: r}
	if _, err := m.Apply(context.Background(), "usque"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(repo, "usque.conf"))
	if err != nil {
		t.Fatal(err)
	}
	wantRepo := "src/gz usque-keenetic https://side-effect-tm.github.io/usque-keenetic/all\n"
	if string(data) != wantRepo {
		t.Fatalf("repository=%q want=%q", data, wantRepo)
	}
	wantCalls := [][]string{
		{"/opt/bin/opkg", "list-installed"}, {"/opt/bin/opkg", "update"}, {"/opt/bin/opkg", "install", "usque-keenetic"}, {"/opt/bin/opkg", "list-installed"},
	}
	if !reflect.DeepEqual(r.calls, wantCalls) {
		t.Fatalf("calls=%v want=%v", r.calls, wantCalls)
	}
}

func TestUsqueDeclaresHTTP2AndNativeTunWithoutSingBoxDependency(t *testing.T) {
	var usque Spec
	for _, spec := range Specs() {
		if spec.ID == "usque" {
			usque = spec
			break
		}
	}
	if usque.ID == "" {
		t.Fatal("usque component is missing")
	}
	if len(usque.Dependencies) != 0 {
		t.Fatalf("USQUE nativetun must not require Sing-box: %v", usque.Dependencies)
	}
	hasHTTP2, hasNativeTun := false, false
	for _, capability := range usque.Capabilities {
		if capability == "http2" {
			hasHTTP2 = true
		}
		if capability == "nativetun" {
			hasNativeTun = true
		}
	}
	if !hasHTTP2 || !hasNativeTun {
		t.Fatalf("USQUE transport capabilities are incomplete: %v", usque.Capabilities)
	}
}

func TestOpkgInstallWritesVerifiedLifecycleReceipt(t *testing.T) {
	r := &fakeRunner{output: map[string]string{"update": "ok", "install": "installed"}}
	stateDir := t.TempDir()
	m := &Manager{Opkg: "/opt/bin/opkg", RepoDir: t.TempDir(), StateDir: stateDir, Runner: r}
	result, err := m.Apply(context.Background(), "nfqws2")
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.Action != "install" || !strings.Contains(result.Output, "verified installed version: 1.0.0") {
		t.Fatalf("unverified result: %+v", result)
	}
	data, err := os.ReadFile(filepath.Join(stateDir, "receipts", "nfqws2.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"after_version": "1.0.0"`) || !strings.Contains(string(data), `"action": "install"`) {
		t.Fatalf("invalid receipt: %s", data)
	}
}

func TestInstallReusesExistingOfficialRepositoryDeclaration(t *testing.T) {
	r := &fakeRunner{output: map[string]string{"update": "ok", "install": "installed"}}
	repo := t.TempDir()
	existing := filepath.Join(repo, "nfqws2-keenetic.conf")
	content := "src/gz nfqws2-keenetic https://nfqws.github.io/nfqws2-keenetic/all\n"
	if err := os.WriteFile(existing, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Opkg: "/opt/bin/opkg", RepoDir: repo, Runner: r}
	if _, err := m.Apply(context.Background(), "nfqws2"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(repo, "nfqws2.conf")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("duplicate repository file was created: %v", err)
	}
	wantCalls := [][]string{{"/opt/bin/opkg", "list-installed"}, {"/opt/bin/opkg", "update"}, {"/opt/bin/opkg", "install", "nfqws2-keenetic"}, {"/opt/bin/opkg", "list-installed"}}
	if !reflect.DeepEqual(r.calls, wantCalls) {
		t.Fatalf("calls=%v want=%v", r.calls, wantCalls)
	}
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	key := ""
	if len(args) > 0 {
		key = args[0]
	}
	if key == "list-installed" {
		return []byte(f.output[key]), nil
	}
	if value, ok := f.output[key]; ok {
		if len(args) > 1 && key == "install" {
			installed := parsePackageVersions(f.output["list-installed"])
			if installed[args[1]] == "" {
				f.output["list-installed"] += args[1] + " - 1.0.0 - installed by test\n"
			}
		}
		if len(args) > 1 && key == "remove" {
			lines := strings.Split(f.output["list-installed"], "\n")
			kept := make([]string, 0, len(lines))
			for _, line := range lines {
				if !strings.HasPrefix(line, args[1]+" - ") {
					kept = append(kept, line)
				}
			}
			f.output["list-installed"] = strings.Join(kept, "\n")
		}
		return []byte(value), nil
	}
	return nil, errors.New("unexpected command")
}

func TestListVersionsAndUpdate(t *testing.T) {
	r := &fakeRunner{output: map[string]string{
		"list-installed": "sing-box-go - 1.1.0 - proxy\nnfqws2-keenetic - 2.0 - dpi\n",
		"list":           "sing-box-go - 1.2.0 - proxy\nnfqws2-keenetic - 2.0 - dpi\n",
	}}
	m := &Manager{Opkg: "/opt/bin/opkg", Runner: r}
	views, err := m.List(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	var sing View
	for _, view := range views {
		if view.ID == "sing-box" {
			sing = view
		}
	}
	if !sing.UpdateAvailable || sing.InstalledVersion != "1.1.0" || sing.AvailableVersion != "1.2.0" {
		t.Fatalf("unexpected view: %+v", sing)
	}
}

func TestApplyUsesFixedPackageAllowlist(t *testing.T) {
	r := &fakeRunner{output: map[string]string{"install": "installed"}}
	m := &Manager{Opkg: "/opt/bin/opkg", Runner: r}
	if _, err := m.Apply(context.Background(), "../../evil"); err == nil {
		t.Fatal("unknown component accepted")
	}
	if _, err := m.Apply(context.Background(), "sing-box"); err != nil {
		t.Fatal(err)
	}
	want := []string{"/opt/bin/opkg", "install", "sing-box-go"}
	if !reflect.DeepEqual(r.calls[len(r.calls)-2], want) {
		t.Fatalf("call=%v want=%v", r.calls, want)
	}
}

func TestSuccessfulInstallIsVisibleAsVerified(t *testing.T) {
	r := &fakeRunner{output: map[string]string{
		"list-installed": "",
		"list":           "nfqws2-keenetic - 1.0.0 - dpi\n",
		"update":         "updated",
		"install":        "installed",
	}}
	m := &Manager{Opkg: "/opt/bin/opkg", RepoDir: t.TempDir(), Runner: r, StateDir: t.TempDir()}
	result, err := m.Apply(context.Background(), "nfqws2")
	if err != nil || !result.OK {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	views, err := m.List(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, view := range views {
		if view.ID != "nfqws2" {
			continue
		}
		if view.Verification != "verified" || view.LastAction != "install" || view.VerifiedVersion != "1.0.0" || view.LastActionAt == "" {
			t.Fatalf("verified lifecycle is not visible: %+v", view)
		}
		return
	}
	t.Fatal("nfqws2 view not found")
}

func TestFailedAndInterruptedOperationsRemainVisible(t *testing.T) {
	stateDir := t.TempDir()
	m := &Manager{StateDir: stateDir}
	if err := m.RecordOperation("nfqws2", "install", "failed", "download failed"); err != nil {
		t.Fatal(err)
	}
	views, err := m.List(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	foundFailed := false
	for _, view := range views {
		if view.ID == "nfqws2" && (view.OperationStatus != "failed" || view.OperationAction != "install" || view.OperationMessage != "download failed" || view.OperationAt == "") {
			t.Fatalf("failed operation is not visible: %+v", view)
		}
		if view.ID == "nfqws2" {
			foundFailed = true
		}
	}
	if !foundFailed {
		t.Fatal("nfqws2 failed operation view not found")
	}
	if err := m.writeOperationReceipt(operationReceipt{SchemaVersion: 1, Component: "nfqws2", Action: "update", Status: "running", UpdatedAt: time.Now().Add(-4 * time.Minute).UTC().Format(time.RFC3339Nano)}); err != nil {
		t.Fatal(err)
	}
	views, err = m.List(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, view := range views {
		if view.ID == "nfqws2" {
			if view.OperationStatus != "interrupted" || view.OperationAction != "update" {
				t.Fatalf("interrupted operation is not visible: %+v", view)
			}
			return
		}
	}
	t.Fatal("nfqws2 view not found")
}

func TestApplyRejectsComponentWithoutManagedProvider(t *testing.T) {
	r := &fakeRunner{output: map[string]string{"install": "installed"}}
	m := &Manager{Opkg: "/opt/bin/opkg", Runner: r}
	if _, err := m.Apply(context.Background(), "wgcf"); err == nil {
		t.Fatal("external component was incorrectly passed to opkg")
	}
	if len(r.calls) != 0 {
		t.Fatalf("unexpected opkg calls: %v", r.calls)
	}
}

func TestManifestIsVersionedAndInternallyConsistent(t *testing.T) {
	specs := Specs()
	if err := ValidateManifest(specs); err != nil {
		t.Fatal(err)
	}
	if len(specs) < 7 {
		t.Fatalf("manifest has only %d components", len(specs))
	}
	for _, spec := range specs {
		if spec.ID == "z2k" {
			t.Fatal("z2k must remain an import source and ownership detector, not an installable component")
		}
		if spec.SchemaVersion != ManifestSchemaVersion {
			t.Fatalf("component %s schema=%d", spec.ID, spec.SchemaVersion)
		}
		if spec.Budget.CPUClass == "" {
			t.Fatalf("component %s has no resource class", spec.ID)
		}
	}
}

func TestPlanExposesLifecycleAndResourceBudget(t *testing.T) {
	r := &fakeRunner{output: map[string]string{
		"list-installed": "",
		"list":           "nfqws2-keenetic - 1.2.4 - dpi\n",
	}}
	m := &Manager{Opkg: "/opt/bin/opkg", Runner: r}
	plan, err := m.Plan(context.Background(), "nfqws2", "install", false)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Ready || plan.SchemaVersion != ManifestSchemaVersion || plan.Budget.RAMMiB == 0 {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	if len(plan.Steps) != 7 || plan.Steps[0].Phase != "preflight" || plan.Steps[len(plan.Steps)-1].Phase != "commit" {
		t.Fatalf("unexpected lifecycle: %+v", plan.Steps)
	}
}

func TestRemoveUsesFixedPackageAllowlist(t *testing.T) {
	r := &fakeRunner{output: map[string]string{"list-installed": "nfqws2-keenetic - 2.0 - dpi\n", "remove": "removed"}}
	m := &Manager{Opkg: "/opt/bin/opkg", Runner: r}
	result, err := m.Remove(context.Background(), "nfqws2")
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.Action != "remove" {
		t.Fatalf("result=%+v", result)
	}
	want := []string{"/opt/bin/opkg", "remove", "nfqws2-keenetic"}
	if !reflect.DeepEqual(r.calls, [][]string{{"/opt/bin/opkg", "list-installed"}, want, {"/opt/bin/opkg", "list-installed"}}) {
		t.Fatalf("calls=%v want=%v", r.calls, want)
	}
	if _, err := m.Remove(context.Background(), "../../evil"); err == nil {
		t.Fatal("unknown component removal accepted")
	}
}

func TestExternalRemovalRequiresOwnershipReceiptAndCreatesSnapshot(t *testing.T) {
	binDir := t.TempDir()
	stateDir := t.TempDir()
	target := filepath.Join(binDir, "wgcf")
	binary := []byte("owned-test-binary")
	if err := installReleaseBinary(target, binary); err != nil {
		t.Fatal(err)
	}
	if err := writeExternalReceipt(target, "2.2.30", binary); err != nil {
		t.Fatal(err)
	}
	m := &Manager{BinDir: binDir, StateDir: stateDir, external: map[string]releaseInfo{}}
	result, err := m.Remove(context.Background(), "wgcf")
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.Action != "remove" {
		t.Fatalf("result=%+v", result)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned binary was not removed: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(stateDir, "removed"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("removal snapshot missing: entries=%v err=%v", entries, err)
	}

	if err := installReleaseBinary(target, []byte("user-binary")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Remove(context.Background(), "wgcf"); err == nil {
		t.Fatal("unowned external binary was removed")
	}
}
