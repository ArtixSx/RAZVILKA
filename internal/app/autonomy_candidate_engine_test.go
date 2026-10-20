package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

const autonomyXHTTPURI = "vless://123e4567-e89b-12d3-a456-426614174001@xhttp.example:443?security=tls&sni=xhttp.example&type=xhttp&path=%2Ftransport&mode=packet-up"

func autonomyXHTTPFixture(t *testing.T) (*App, *engineNodeFixture, *engineNodeFixture, string) {
	t.Helper()
	a, sing, xray, _ := engineNodeHTTPFixture(t)
	snapshot, err := a.Nodes.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, autonomyXHTTPURI, time.Now(), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	id := ""
	for _, node := range snapshot.Nodes {
		if node.Transport == "xhttp" {
			id = node.ID
		}
	}
	if id == "" {
		t.Fatal("canonical XHTTP fixture missing")
	}
	a.nodeReviews.options = func() []routecatalog.Option {
		return []routecatalog.Option{{ID: "sing-box", Installed: true}, {ID: "xray", Installed: true}}
	}
	return a, sing, xray, id
}

func TestAutonomyAUTOUsesCompatibleConsentedInstalledEngine(t *testing.T) {
	a, _, _, id := autonomyXHTTPFixture(t)
	p := autonomy.Default()
	s := autonomy.Service{ID: "discord", ExpectedRoute: "auto"}
	if got, err := a.autonomyCandidateEngine(context.Background(), p, s, "sing-box", id); err != nil || got != "xray" {
		t.Fatalf("AUTO skipped canonical XHTTP: %s %v", got, err)
	}
	for _, explicit := range []string{"sing-box", "sing-box:node-example", "xray", "xray:node-example"} {
		s.ExpectedRoute = explicit
		engine := autonomyNodeEngine(explicit)
		if got, err := a.autonomyCandidateEngine(context.Background(), p, s, engine, id); err != nil || got != engine {
			t.Fatalf("explicit executor changed: %s -> %s %v", explicit, got, err)
		}
	}
	s.ExpectedRoute = "auto"
	p.PreferredRoutes = []string{"sing-box"}
	if _, err := a.autonomyCandidateEngine(context.Background(), p, s, "sing-box", id); !errors.Is(err, dataplane.ErrExactNodeUnsupported) {
		t.Fatal("Xray used without method consent", err)
	}
	p = autonomy.Default()
	a.nodeReviews.options = func() []routecatalog.Option { return []routecatalog.Option{{ID: "sing-box", Installed: true}} }
	if _, err := a.autonomyCandidateEngine(context.Background(), p, s, "sing-box", id); !errors.Is(err, dataplane.ErrExactNodeUnsupported) {
		t.Fatal("uninstalled Xray used", err)
	}
	if _, err := compatibleAutonomyEngine([]byte(`{"type":"vless","transport":{"type":"xhttp","mode":"unsupported"}}`), "sing-box"); !errors.Is(err, dataplane.ErrExactNodeUnsupported) {
		t.Fatal("malformed contract dispatched to another engine", err)
	}
}

func TestNodeHTTPDefaultUsesXHTTPExecutorButExplicitChoiceDoesNotChange(t *testing.T) {
	a, sing, xray, id := autonomyXHTTPFixture(t)
	server := httptest.NewServer(a.Handler(http.NotFoundHandler()))
	defer server.Close()
	code, body := postEngineNode(t, server, id, "")
	if code != 200 || xray.calls != 1 || sing.calls != 0 || !strings.Contains(string(body), `"engine":"xray"`) || !strings.Contains(string(body), "xray:"+id) {
		t.Fatalf("omitted engine did not check canonical XHTTP: %d %s calls=%d/%d", code, body, sing.calls, xray.calls)
	}
	// Production Sing-box refuses XHTTP; that explicit refusal must survive.
	sing.err = dataplane.ErrExactNodeUnsupported
	code, _ = postEngineNode(t, server, id, "sing-box")
	if code != http.StatusConflict || sing.calls != 1 || xray.calls != 1 {
		t.Fatalf("explicit Sing-box choice silently fell back: %d calls=%d/%d", code, sing.calls, xray.calls)
	}
}
