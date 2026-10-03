package dataplane

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodestore"
)

// This opt-in test checks real Xray config syntax for NodeStore materialization.
// Its synthetic CheckRecord admits material to the compiler, and is NOT a
// native path proof. No runtime process, listener, route or TUN is started.
func TestNativeXrayStoreConfigSyntax(t *testing.T) {
	binary := os.Getenv("RAZVILKA_XRAY_NATIVE")
	if binary == "" {
		t.Skip("native Xray binary not requested")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("native Xray path must be absolute")
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	for _, security := range []string{"tls", "reality"} {
		t.Run(security, func(t *testing.T) {
			root := t.TempDir()
			nodesRoot := filepath.Join(root, "nodes")
			if err := os.Mkdir(nodesRoot, 0o700); err != nil {
				t.Fatal(err)
			}
			s, err := nodestore.Open(nodesRoot)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			query := "security=tls&sni=front.example&alpn=h2"
			if security == "reality" {
				query = "security=reality&sni=front.example&fp=chrome&pbk=" + public + "&sid=abcd&flow=xtls-rprx-vision"
			}
			raw := "vless://" + nativeXrayUUID + "@node.example:443?" + query + "\nvless://" + nativeXrayUUID + "@other.example:443?" + query
			now := time.Now().UTC()
			ctx := context.Background()
			snapshot, err := s.Import(ctx, nodestore.Source{ID: "manual", Kind: "manual"}, raw, now, time.Hour, false)
			if err != nil || len(snapshot.Nodes) != 2 {
				t.Fatal("fixture import failed", err)
			}
			var bindings []nodestore.RouteBinding
			for i, n := range snapshot.Nodes {
				service, domain := "telegram", "telegram.org"
				if i == 1 {
					service, domain = "discord", "discord.com"
				}
				_, err = s.RecordCheck(ctx, n.ID, nodestore.CheckRecord{ProbeID: "syntax-fixture-" + service, ServiceID: service, NetworkProfile: "wan-0123456789ab", RoutePathID: "xray:" + n.ID,
					TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: now, ExpiresAt: now.Add(time.Minute)}, now)
				if err != nil {
					t.Fatal(err)
				}
				bindings = append(bindings, nodestore.RouteBinding{NodeID: n.ID, ServiceID: service, NetworkProfile: "wan-0123456789ab", Domains: []string{domain}, Destinations: []string{"2001:db8::1/128"}})
			}
			// Keep destinations disjoint just as application policy must.
			bindings[1].Destinations = []string{"149.154.160.0/20"}
			material, err := s.MaterializeXray(ctx, bindings, now)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(material.Config)
			config := filepath.Join(root, "material.json")
			if err := os.WriteFile(config, material.Config, 0o600); err != nil {
				t.Fatal(err)
			}
			checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			output, err := exec.CommandContext(checkCtx, binary, "run", "-test", "-config", config).CombinedOutput()
			clear(output)
			if err != nil {
				t.Fatal("native Xray rejected NodeStore config syntax", err)
			}
			t.Log("native syntax only: two canonical exits, scoped domains/IPv4/IPv6, default blackhole; no TUN/path evidence")
		})
	}
}
