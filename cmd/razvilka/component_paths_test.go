package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/app"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/security"
)

func TestComponentExplicitDirectoriesPreserveProductionDefaults(t *testing.T) {
	want := components.New()
	got, err := configuredComponents("", "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.StateDir != want.StateDir || got.BinDir != want.BinDir || got.InitDir != want.InitDir || got.RepoDir != want.RepoDir || got.InfoDir != want.InfoDir {
		t.Fatal("retained production locations changed")
	}
	for i := range 5 {
		args := make([]string, 5)
		args[i] = "relative"
		if _, err := configuredComponents(args[0], args[1], args[2], args[3], args[4]); err == nil {
			t.Fatal("relative override accepted", i)
		}
	}
}

func TestComponentExplicitDirectoriesRealHTTPKeepsCorruptFence(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "components")
	bin, init, repo, info := filepath.Join(root, "bin"), filepath.Join(root, "init"), filepath.Join(root, "repo"), filepath.Join(root, "info")
	for name, value := range map[string]string{"STATE": state, "BIN": bin, "INIT": init, "REPO": repo, "INFO": info} {
		t.Setenv("RAZVILKA_COMPONENT_"+name, value)
	}
	m, err := componentsFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if m.StateDir != state || m.BinDir != bin || m.InitDir != init || m.RepoDir != repo || m.InfoDir != info {
		t.Fatal("explicit environment not wired")
	}
	const token = "component-startup-isolated-http-token-12345"
	gate, err := security.NewGate(token)
	if err != nil {
		t.Fatal(err)
	}
	a := &app.App{Components: m, Security: gate}
	if err := a.InitializeComponentRecoveryGate(); err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer s.Close()
	get := func() int {
		req, _ := http.NewRequest(http.MethodGet, s.URL+"/api/v1/components/recovery", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := s.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		return res.StatusCode
	}
	if code := get(); code != 200 {
		t.Fatal("isolated HTTP blocked by default /opt state", code)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatal("read-only construction/HTTP created journal", err)
	}
	if err := os.MkdirAll(filepath.Join(state, "update-journal"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "update-journal", "current.json"), []byte("truncated"), 0600); err != nil {
		t.Fatal(err)
	}
	if code := get(); code != 503 {
		t.Fatal("retained corrupt journal concealed", code)
	}
	if release, err := a.Operations.Enter(context.Background()); release != nil || err == nil || !strings.Contains(err.Error(), "recovery") {
		t.Fatal("write admission escaped corrupt journal", err)
	}
}
