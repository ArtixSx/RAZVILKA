package components

import (
	"context"
	"slices"
	"strings"
	"testing"
)

func TestInstallProgressReportsRealUSQUEOpkgStagesWithoutOutput(t *testing.T) {
	const secret = "PRIVATE-SYNTHETIC-TEST-VALUE"
	runner := &fakeRunner{output: map[string]string{"update": secret, "install": secret, "list-installed": "sing-box-go - 1.13.3-2 - existing shared core\n"}}
	m := &Manager{Opkg: "/opt/bin/opkg", RepoDir: t.TempDir(), Runner: runner}
	var got []InstallStage
	ctx := WithInstallProgress(context.Background(), func(s InstallStage) {
		if s.Message() == "" || strings.Contains(s.Message(), secret) {
			t.Fatal("untrusted progress event")
		}
		got = append(got, s)
	})
	if _, err := m.Apply(ctx, "usque"); err != nil {
		t.Fatal(err)
	}
	want := []InstallStage{installUSQUENetwork, installDependencies, installCatalog, installOpkg, installVerify}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}
