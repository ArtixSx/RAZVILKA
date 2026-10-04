package providerfeed

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

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
