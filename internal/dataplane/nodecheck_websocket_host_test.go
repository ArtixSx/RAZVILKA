package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodestore"
)

func TestPinnedNodePreservesImportedWebSocketHost(t *testing.T) {
	for _, header := range []string{`"front.example"`, `["front.example"]`} {
		t.Run(header, func(t *testing.T) {
			// Native sing-box headers accept a string or a string list. Exercise
			// the actual importer before the runtime compiler, not a hand-built map.
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			store, err := nodestore.Open(root)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			snapshot, err := store.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, `{"outbounds":[{"type":"vless","server":"edge.example","server_port":443,"uuid":"123e4567-e89b-12d3-a456-426614174000","tls":{"enabled":true,"server_name":"tls.example"},"transport":{"type":"ws","path":"/tunnel","headers":{"Host":`+header+`,"X-Test":"unchanged"}}}]}`, time.Now(), time.Hour, false)
			if err != nil || len(snapshot.Nodes) != 1 {
				t.Fatal("valid WebSocket profile was rejected", err)
			}
			var material []byte
			if err := store.WithSecret(context.Background(), snapshot.Nodes[0].ID, func(raw []byte) error {
				material = bytes.Clone(raw)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			original := bytes.Clone(material)
			var canonical map[string]any
			if err := json.Unmarshal(material, &canonical); err != nil {
				t.Fatal(err)
			}
			endpoint, err := inspectExactNodeOutbound(material)
			if err != nil {
				t.Fatal(err)
			}
			endpoint.Pinned = netip.MustParseAddr("203.0.113.8")
			compiled, err := compilePinnedSingBoxNodeConfig(material, endpoint, 19181)
			if err != nil {
				t.Fatal(err)
			}
			var runtime struct {
				Outbounds []map[string]any `json:"outbounds"`
			}
			if err := json.Unmarshal(compiled, &runtime); err != nil || len(runtime.Outbounds) == 0 {
				t.Fatal(err)
			}
			outbound := runtime.Outbounds[0]
			if !reflect.DeepEqual(outbound["transport"], canonical["transport"]) {
				t.Fatalf("pinning changed the imported WebSocket request: got=%v want=%v", outbound["transport"], canonical["transport"])
			}
			if outbound["server"] != endpoint.Pinned.String() || !reflect.DeepEqual(outbound["tls"], canonical["tls"]) || !bytes.Equal(material, original) {
				t.Fatal("pinning lost the selected IP, SNI, or immutable canonical material")
			}
		})
	}
}
