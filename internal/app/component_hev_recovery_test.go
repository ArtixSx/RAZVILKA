package app

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/security"
)

func TestHEVRecoveryHTTPRequiresAuthAndExactReviewWithoutInitializingState(t *testing.T) {
	a := hevApplicationGuardFixture(t)
	root := t.TempDir()
	owner := components.New()
	owner.StateDir, owner.BinDir = filepath.Join(root, "components"), filepath.Join(root, "bin")
	a.Components = owner
	var err error
	a.Security, err = security.NewGate(componentRecoveryToken)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(a.Handler(nil))
	defer s.Close()
	if code, _ := componentHTTP(t, s, "GET", hevRecoveryPath, nil, "", s.URL); code != 401 {
		t.Fatal("unauthenticated", code)
	}
	code, data := componentHTTP(t, s, "GET", hevRecoveryPath, nil, componentRecoveryToken, s.URL)
	var view struct {
		Required  bool                                `json:"recovery_required"`
		Available bool                                `json:"repair_available"`
		Review    components.HEVReleaseRecoveryReview `json:"review"`
	}
	if code != 200 || json.Unmarshal(data, &view) != nil || view.Required || view.Available || view.Review.Identity != "" {
		t.Fatal(code, string(data))
	}
	body := map[string]any{"expected_identity": strings.Repeat("a", 64), "expected_revision": a.Store.Get().Revision}
	if code, _ := componentHTTP(t, s, "POST", hevRecoveryPath, body, componentRecoveryToken, "https://foreign.invalid"); code != 403 {
		t.Fatal("foreign origin", code)
	}
	body["expected_revision"] = a.Store.Get().Revision + 1
	if code, _ := componentHTTP(t, s, "POST", hevRecoveryPath, body, componentRecoveryToken, s.URL); code != 409 {
		t.Fatal("stale settings", code)
	}
	body["expected_revision"] = a.Store.Get().Revision
	if code, _ := componentHTTP(t, s, "POST", hevRecoveryPath, body, componentRecoveryToken, s.URL); code != 409 {
		t.Fatal("fabricated journal", code)
	}
	for _, path := range []string{owner.StateDir, owner.BinDir} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("recovery initialized missing state", path, err)
		}
	}
}
