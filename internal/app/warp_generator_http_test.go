package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/security"
	"github.com/ArtixSx/razvilka/internal/warp"
)

func TestWARPPanelRegistrationAndFileRoundTrip(t *testing.T) {
	// Isolate the synthetic TLS endpoint from all other tests and clients.
	if os.Getenv("RAZVILKA_TEST_WARP_TLS") != "loopback" {
		child := exec.Command(os.Args[0], "-test.run=^TestWARPPanelRegistrationAndFileRoundTrip$")
		child.Env = append(os.Environ(), "RAZVILKA_TEST_WARP_TLS=loopback")
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("loopback panel: %v\n%s", err, output)
		}
		return
	}
	var calls atomic.Int32
	var reject atomic.Bool
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v0a4471/reg" || r.Host != "api.cloudflareclient.com" {
			t.Error("unexpected enrollment request")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		calls.Add(1)
		if reject.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var request struct{ Key, TOS string }
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.TOS == "" || len(request.Key) != 44 {
			t.Error("invalid public registration request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		peer := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'p'}, 32))
		fmt.Fprintf(w, `{"id":"fixture-id","token":"fixture-token","key":%q,"key_type":"curve25519","tunnel_type":"wireguard","config":{"interface":{"addresses":{"v4":"172.16.0.2","v6":"2606:4700:110::2"}},"peers":[{"public_key":%q,"endpoint":{"v4":"162.159.192.1:0","ports":[2408,500]}}]}}`, request.Key, peer)
	}))
	defer issuer.Close()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	trust := issuer.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	trust.ServerName = "127.0.0.1"
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "api.cloudflareclient.com:443" {
			return nil, fmt.Errorf("unexpected test destination")
		}
		return (&tls.Dialer{Config: trust}).DialContext(ctx, network, issuer.Listener.Addr().String())
	}
	http.DefaultTransport = transport
	newPanel := func() *httptest.Server {
		dir := t.TempDir()
		store, err := config.Load(filepath.Join(dir, "config.json"))
		if err != nil {
			t.Fatal(err)
		}
		gate, err := security.NewGate(panelTestToken)
		if err != nil {
			t.Fatal(err)
		}
		configs := engineconfig.New(filepath.Join(dir, "stage"), filepath.Join(dir, "backup"))
		manager := warp.New(filepath.Join(dir, "warp"), filepath.Join(dir, "warp-backup"), configs)
		manager.ProfilePaths = []string{filepath.Join(dir, "live.conf")}
		a := &App{Store: store, Warp: manager, EngineConfigs: configs, Security: gate}
		panel := httptest.NewServer(a.Handler(http.NotFoundHandler()))
		t.Cleanup(panel.Close)
		return panel
	}
	request := func(panel *httptest.Server, method, path, body string, expected int, result any) {
		t.Helper()
		req, err := http.NewRequest(method, panel.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+panelTestToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := panel.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != expected {
			t.Fatalf("%s status %d, want %d", path, resp.StatusCode, expected)
		}
		if result != nil {
			if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(result); err != nil {
				t.Fatal(err)
			}
		}
	}
	const generate = "/api/v1/warp/generate"
	first, second := newPanel(), newPanel()
	request(first, "POST", generate, `{"accept_tos":false}`, 428, nil)
	if calls.Load() != 0 {
		t.Fatal("registration attempted without consent")
	}
	var created, reused, imported, checked warp.Result
	request(first, "POST", generate, `{"accept_tos":true}`, 200, &created)
	request(first, "POST", generate, `{"accept_tos":false}`, 200, &reused)
	var file engineconfig.Content
	request(first, "GET", "/api/v1/engine-configs/warp-wg/file?file=main&expert=true", "", 200, &file)
	if calls.Load() != 1 || !created.OK || !reused.OK || reused.SHA256 != created.SHA256 || warp.ValidateProfile([]byte(file.Content)) != nil || !strings.Contains(file.Content, "162.159.192.1:2408") {
		t.Fatal("registration did not yield a reusable WireGuard draft")
	}
	reject.Store(true)
	request(second, "POST", generate, `{"accept_tos":true}`, 409, nil)
	request(second, "POST", generate, `{"accept_tos":true,"fresh":true}`, 409, nil)
	upload, err := json.Marshal(map[string]string{"content": file.Content})
	if err != nil {
		t.Fatal(err)
	}
	request(second, "POST", "/api/v1/warp/import", string(upload), 200, &imported)
	request(second, "POST", "/api/v1/warp/check", "", 200, &checked)
	if calls.Load() != 2 || !imported.OK || !checked.OK || imported.SHA256 != created.SHA256 || checked.SHA256 != created.SHA256 {
		t.Fatal("offline file round trip or repeated enrollment fence failed")
	}
}
