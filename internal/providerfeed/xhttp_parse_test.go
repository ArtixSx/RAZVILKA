package providerfeed

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/providerprofile"
)

func TestXHTTPFeedCanonicalMaterialKeepsRequiredTransportAndDedupIdentity(t *testing.T) {
	raw := strings.Replace(goodURI, "type=tcp", "type=xhttp&mode=packet-up&host=front.example&path=%2Ftunnel&extra=%7B%22noSSEHeader%22%3Atrue%2C%22xPaddingBytes%22%3A%2264-128%22%7D", 1)
	for _, format := range []string{"uri", "keys-json", "profile"} {
		var data []byte
		switch format {
		case "uri":
			data = []byte(raw + "\n" + raw + "\n" + strings.Replace(raw, "%2Ftunnel", "%2Fother", 1))
		case "keys-json":
			data, _ = json.Marshal(map[string]any{"fixture": map[string]any{"top10": []any{map[string]any{"key": raw}, map[string]any{"key": raw}, map[string]any{"key": strings.Replace(raw, "%2Ftunnel", "%2Fother", 1)}}}})
		case "profile":
			parsed, err := providerprofile.ParseCanonicalURI(raw)
			if err != nil {
				t.Fatal(err)
			}
			data = parsed.Config
		}
		parsed, err := parse(context.Background(), data, format, 32)
		if err != nil || parsed.accepted < 1 || len(parsed.materials) != parsed.accepted {
			t.Fatalf("%s canonical parse: %v", format, err)
		}
		if format != "profile" && (parsed.accepted != 2 || parsed.duplicates != 1) {
			t.Fatal("path/extra lost from feed identity")
		}
		for _, material := range parsed.materials {
			p, err := providerprofile.VLESSProfileFromJSON(material)
			if err != nil || p.Transport != "xhttp" || p.XHTTP["mode"] != "packet-up" || p.XHTTP["host"] != "front.example" {
				t.Fatal("feed lost canonical transport")
			}
			config, _, err := providerprofile.CompileXrayConfig(p)
			if err != nil || !strings.Contains(string(config), `"noSSEHeader": true`) || !strings.Contains(string(config), `"network": "xhttp"`) {
				t.Fatal("feed did not preserve required extra")
			}
		}
	}
}

func TestXHTTPFeedUnsupportedIsRejectedBeforeAnyImportEvidence(t *testing.T) {
	for _, options := range []string{
		"type=xhttp&mode=unsupported", "type=xhttp&alpn=h3", "type=xhttp&flow=xtls-rprx-vision",
		"type=xhttp&extra=%7B%22downloadSettings%22%3A%7B%7D%7D",
	} {
		raw := strings.Replace(goodURI, "type=tcp", options, 1)
		if b, err := parse(context.Background(), []byte(raw), "uri", 32); err == nil || b.accepted != 0 || len(b.materials) != 0 {
			t.Fatal("unsupported feed entry became an accepted candidate")
		}
	}
}

func TestXHTTPFeedSyncPersistsQuarantinedCanonicalMaterialAndReaderFence(t *testing.T) {
	ctx := context.Background()
	m, store, path := testManager(t)
	raw := strings.Replace(goodURI, "type=tcp", "type=xhttp&mode=packet-up&host=front.example&path=%2Ftunnel&extra=%7B%22headers%22%3A%7B%22Authorization%22%3A%22private-extra-token%22%7D%2C%22xPaddingBytes%22%3A%2264-128%22%7D", 1)
	setResponse(m, 200, raw, nil)
	result, err := m.Sync(ctx, Request{URL: "https://feed.example.org/private-subscription"})
	if err != nil || result.Imported != 1 || len(result.NodeIDs) != 1 {
		t.Fatal("feed canonical material did not reach NodeStore", err)
	}
	id := result.NodeIDs[0]
	snap, err := store.Snapshot(ctx, testTime)
	if err != nil || len(snap.Nodes) != 1 || snap.Nodes[0].Transport != "xhttp" || snap.Nodes[0].State != "quarantined" || snap.Nodes[0].Trust != "untrusted" || snap.Nodes[0].Health.State != "not_checked" {
		t.Fatal("feed gained health/route authority or lost transport", err)
	}
	if version, err := store.RequiredHistoryReadVersion(ctx); err != nil || version != 3 {
		t.Fatal("unchecked feed material permits reader2", version, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = nodestore.Open(filepath.Dir(path))
	if err != nil {
		t.Fatal("XHTTP feed material cannot reopen", err)
	}
	defer store.Close()
	if err := store.WithSecret(ctx, id, func(material []byte) error {
		p, err := providerprofile.VLESSProfileFromJSON(material)
		if err != nil || p.Transport != "xhttp" || p.XHTTP["path"] != "/tunnel" || !strings.Contains(string(material), "private-extra-token") {
			t.Fatal("persisted feed lost required XHTTP settings", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	public, _ := json.Marshal(snap)
	if strings.Contains(string(public), "private-extra-token") || strings.Contains(string(public), "front.example") {
		t.Fatal("public feed snapshot leaked private transport fields")
	}
}
