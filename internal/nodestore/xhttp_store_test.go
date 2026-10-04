package nodestore

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/providerprofile"
)

const xhttpStoreExtra = `{"headers":{"Authorization":"private-extra-token","X-Test":"fixture"},"xPaddingBytes":"100-200","xPaddingObfsMode":true,"xPaddingKey":"pad","xPaddingHeader":"X-Pad","xPaddingPlacement":"header","xPaddingMethod":"tokenish","uplinkHTTPMethod":"POST","sessionPlacement":"query","sessionKey":"session","seqPlacement":"query","seqKey":"seq","uplinkDataPlacement":"body","uplinkDataKey":"data","uplinkChunkSize":4096,"noGRPCHeader":true,"noSSEHeader":false,"scMaxEachPostBytes":8192,"scMinPostsIntervalMs":"10-20","scMaxBufferedPosts":16,"scStreamUpServerSecs":"20-30","serverMaxHeaderBytes":8192,"xmux":{"maxConnections":"1-2","cMaxReuseTimes":2,"hMaxRequestTimes":"10-20","hMaxReusableSecs":30,"hKeepAlivePeriod":-1}}`

func xhttpStoreURI(security, mode string) string {
	u, _ := url.Parse(good)
	q := u.Query()
	q.Set("security", security)
	q.Set("type", "xhttp")
	q.Set("host", "front.example")
	q.Set("path", "/tunnel?token=private-path")
	q.Set("mode", mode)
	q.Set("extra", xhttpStoreExtra)
	q.Set("fp", "chrome")
	if security == "reality" {
		q.Set("pbk", base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
		q.Set("sid", "0123456789abcdef")
	} else {
		q.Set("alpn", "h2,http/1.1")
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func xhttpStoredMaterial(t *testing.T, s *Store, id string) []byte {
	t.Helper()
	var material []byte
	if err := s.WithSecret(context.Background(), id, func(raw []byte) error {
		material = bytes.Clone(raw)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(material) })
	return material
}

func assertXHTTPStoreSettings(t *testing.T, settings map[string]any, mode string) {
	t.Helper()
	var extra map[string]any
	if json.Unmarshal([]byte(xhttpStoreExtra), &extra) != nil {
		t.Fatal("invalid fixture")
	}
	want := map[string]any{"host": "front.example", "path": "/tunnel?token=private-path", "mode": mode, "extra": extra}
	if !reflect.DeepEqual(settings, want) {
		t.Fatal("XHTTP settings changed across storage/materialization")
	}
}

func TestXHTTPStoreCanonicalImportReopenAndPrivateRestorePreserveIdentity(t *testing.T) {
	for _, security := range []string{"tls", "reality"} {
		t.Run(security, func(t *testing.T) {
			ctx := context.Background()
			s, path := setup(t)
			raw := xhttpStoreURI(security, "packet-up")
			first, err := s.Import(ctx, manual, raw, testTime, time.Hour, false)
			if err != nil || len(first.Nodes) != 1 || first.Nodes[0].Transport != "xhttp" || first.Nodes[0].State != "quarantined" || first.Nodes[0].Health.State != "not_checked" {
				t.Fatal("canonical XHTTP import failed or promoted health", err)
			}
			id := first.Nodes[0].ID
			material := xhttpStoredMaterial(t, s, id)
			var canonical map[string]any
			if json.Unmarshal(material, &canonical) != nil {
				t.Fatal("invalid stored material")
			}
			transport := canonical["transport"].(map[string]any)
			if transport["type"] != "xhttp" {
				t.Fatal("transport was mapped to RAW")
			}
			delete(transport, "type")
			assertXHTTPStoreSettings(t, transport, "packet-up")
			profile, err := providerprofile.VLESSProfileFromJSON(material)
			if err != nil || profile.Security != security || profile.ServerName != "private-sni.example" {
				t.Fatal("security or SNI lost", err)
			}
			canonicalBundle, err := providerprofile.ParseCanonicalProfile(raw)
			if err != nil {
				t.Fatal(err)
			}
			native, _, err := providerprofile.CompileXrayConfig(profile)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(native)
			for index, input := range []string{strings.Replace(raw, "SECRET_ALIAS", "Other", 1), string(canonicalBundle.Config), string(native)} {
				source := Source{ID: []string{"manual", "feed", "file"}[index], Kind: []string{"manual", "subscription", "file"}[index]}
				again, err := s.Import(ctx, source, input, testTime, time.Hour, false)
				if err != nil || len(again.Nodes) != 1 || again.Nodes[0].ID != id || !bytes.Equal(material, xhttpStoredMaterial(t, s, id)) {
					t.Fatal("URI/canonical feed/native JSON identity changed", err)
				}
			}
			before := readBytes(t, path)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = Open(path)
			if err != nil {
				t.Fatal("XHTTP persisted material cannot reopen", err)
			}
			defer s.Close()
			reopened, err := s.Snapshot(ctx, testTime)
			if err != nil || reopened.Nodes[0].ID != id || len(reopened.Nodes[0].Origins) != 3 || reopened.Nodes[0].Health.State != "not_checked" || !bytes.Equal(before, readBytes(t, path)) {
				t.Fatal("reopen changed passive material or origins", err)
			}
			public, _ := json.Marshal(reopened)
			for _, value := range []string{"123e4567", "private-host", "private-sni", "front.example", "private-extra-token", "private-path", "SECRET_ALIAS"} {
				if bytes.Contains(public, []byte(value)) {
					t.Fatal("public snapshot exposed private XHTTP field")
				}
			}
			backup, err := s.ExportPrivate(ctx)
			if err != nil || ValidatePrivateSnapshot(backup) != nil {
				t.Fatal("XHTTP backup rejected", err)
			}
			restoredStore, restoredPath := setup(t)
			session, err := restoredStore.BeginRestore(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, restoreErr := executeNodes(t, session, backup)
			closeErr := session.Close()
			if restoreErr != nil || closeErr != nil {
				t.Fatal("XHTTP private restore failed", restoreErr, closeErr)
			}
			restored, err := restoredStore.Snapshot(ctx, testTime)
			if err != nil || len(restored.Nodes) != 1 || restored.Nodes[0].ID != id || !bytes.Equal(material, xhttpStoredMaterial(t, restoredStore, id)) {
				t.Fatal("restore changed identity or secret", err)
			}
			if err := restoredStore.Close(); err != nil {
				t.Fatal(err)
			}
			restoredStore, err = Open(restoredPath)
			if err != nil {
				t.Fatal("restored XHTTP cannot reopen", err)
			}
			defer restoredStore.Close()
			if !bytes.Equal(material, xhttpStoredMaterial(t, restoredStore, id)) {
				t.Fatal("restored material changed on reopen")
			}
		})
	}
}

func TestXHTTPStoreMaterializationRequiresXrayProofAndRejectsSingBoxDespiteProof(t *testing.T) {
	for _, security := range []string{"tls", "reality"} {
		for _, mode := range []string{"auto", "packet-up", "stream-up", "stream-one"} {
			t.Run(security+"/"+mode, func(t *testing.T) {
				ctx := context.Background()
				s, path := setup(t)
				snap, err := s.Import(ctx, manual, xhttpStoreURI(security, mode), testTime, time.Hour, false)
				if err != nil {
					t.Fatal(err)
				}
				id := snap.Nodes[0].ID
				binding := RouteBinding{ServiceID: "telegram", NodeID: id, NetworkProfile: "wan-0123456789ab", Domains: []string{"telegram.org"}, Destinations: []string{"149.154.160.0/20"}}
				if _, err := s.MaterializeXray(ctx, []RouteBinding{binding}, testTime); !errors.Is(err, ErrRouteProof) {
					t.Fatal("unchecked XHTTP materialized", err)
				}
				// Stored/manual evidence alone cannot override the transport gate.
				for _, engine := range []string{"sing-box", "xray"} {
					if _, err := s.RecordCheck(ctx, id, enginePass(id, engine, engine+"-xhttp", testTime), testTime); err != nil {
						t.Fatal(err)
					}
				}
				before := readBytes(t, path)
				if material, err := s.MaterializeSingBox(ctx, []RouteBinding{binding}, testTime); !errors.Is(err, ErrRouteProof) || len(material.Config) != 0 || !bytes.Equal(before, readBytes(t, path)) {
					t.Fatal("impossible Sing-box proof bypassed transport gate or changed history", err)
				}
				material, err := s.MaterializeXray(ctx, []RouteBinding{binding}, testTime)
				if err != nil || material.EngineID != "xray" || !reflect.DeepEqual(material.EndpointHosts, []string{"private-host.example"}) {
					t.Fatal("exact Xray materialization failed", err)
				}
				defer clear(material.Config)
				var doc struct {
					Outbounds []struct {
						Tag            string
						Protocol       string
						StreamSettings struct {
							Network         string
							Security        string
							XHTTPSettings   map[string]any
							TLSSettings     struct{ ServerName string }
							RealitySettings struct{ ServerName, PublicKey, ShortID string }
						}
					}
					Routing struct{ Rules []map[string]any }
				}
				if json.Unmarshal(material.Config, &doc) != nil || len(doc.Outbounds) != 2 || doc.Outbounds[0].Protocol != "blackhole" || doc.Outbounds[1].Protocol != "vless" || doc.Outbounds[1].Tag != nodeTag(id) {
					t.Fatal("scope or default blackhole changed")
				}
				stream := doc.Outbounds[1].StreamSettings
				if stream.Network != "xhttp" || stream.Security != security {
					t.Fatal("transport/security was weakened")
				}
				assertXHTTPStoreSettings(t, stream.XHTTPSettings, mode)
				if security == "tls" && stream.TLSSettings.ServerName != "private-sni.example" || security == "reality" && (stream.RealitySettings.ServerName != "private-sni.example" || stream.RealitySettings.PublicKey == "" || stream.RealitySettings.ShortID != "0123456789abcdef") {
					t.Fatal("required security field lost")
				}
				if len(doc.Routing.Rules) != 3 || doc.Routing.Rules[0]["outboundTag"] != nodeTag(id) || doc.Routing.Rules[1]["outboundTag"] != nodeTag(id) || doc.Routing.Rules[2]["outboundTag"] != "rz-node-block" || doc.Routing.Rules[2]["network"] != "tcp,udp" {
					t.Fatal("destination scope or terminal blackhole changed")
				}
				if _, err := s.MaterializeXray(ctx, []RouteBinding{binding}, testTime.Add(30*time.Minute)); !errors.Is(err, ErrRouteProof) {
					t.Fatal("expired XHTTP proof materialized", err)
				}
			})
		}
	}
}

func TestXHTTPStoreUnsupportedAndPartialImportPreserveExistingBytes(t *testing.T) {
	ctx := context.Background()
	s, path := setup(t)
	id := importGood(t, s).Nodes[0].ID
	before := readBytes(t, path)
	valid := xhttpStoreURI("tls", "packet-up")
	for _, mutation := range []func(url.Values){
		func(q url.Values) { q.Set("alpn", "h3") },
		func(q url.Values) { q.Set("mode", "unknown") },
		func(q url.Values) { q.Set("flow", "xtls-rprx-vision") },
		func(q url.Values) { q.Set("extra", `{"downloadSettings":{}}`) },
		func(q url.Values) { q.Set("extra", `{"headers":null}`) },
	} {
		u, _ := url.Parse(valid)
		q := u.Query()
		mutation(q)
		u.RawQuery = q.Encode()
		if _, err := s.Import(ctx, manual, u.String(), testTime, time.Hour, false); !errors.Is(err, ErrImport) || !bytes.Equal(before, readBytes(t, path)) {
			t.Fatal("unsupported XHTTP changed existing material", err)
		}
	}
	bad := strings.Replace(valid, "mode=packet-up", "mode=unknown", 1)
	mixed := good + "\n" + valid + "\n" + bad
	if _, err := s.Import(ctx, manual, mixed, testTime, time.Hour, false); !errors.Is(err, ErrPartial) || !bytes.Equal(before, readBytes(t, path)) {
		t.Fatal("partial import lacked explicit acceptance", err)
	}
	accepted, err := s.Import(ctx, manual, mixed, testTime, time.Hour, true)
	if err != nil || len(accepted.Nodes) != 2 || accepted.Nodes[0].ID != id || accepted.Nodes[1].Transport != "xhttp" || len(accepted.Nodes[1].Health.History) != 0 {
		t.Fatal("explicit partial import lost existing node or accepted unsupported material", err)
	}
}

func TestXHTTPStoreReopenRejectsUnsupportedPersistedMaterialWithoutRepair(t *testing.T) {
	ctx := context.Background()
	s, path := setup(t)
	if _, err := s.Import(ctx, manual, xhttpStoreURI("tls", "packet-up"), testTime, time.Hour, false); err != nil {
		t.Fatal(err)
	}
	var doc document
	if decodeStrict(readBytes(t, path), &doc) != nil {
		t.Fatal("fixture document invalid")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	var outbound map[string]any
	_ = json.Unmarshal(doc.Secrets[0].Outbound, &outbound)
	outbound["transport"].(map[string]any)["extra"].(map[string]any)["downloadSettings"] = map[string]any{}
	material, _ := json.Marshal(outbound)
	// Keep the HMAC/reference consistent so this exercises canonical rejection.
	doc.Nodes[0].ID = identity(doc.IdentityKey, material)
	doc.Nodes[0].SecretRef = "secret-" + doc.Nodes[0].ID
	doc.Secrets[0] = secret{Ref: doc.Nodes[0].SecretRef, Outbound: material}
	data, _ := json.Marshal(doc)
	if err := os.WriteFile(filepath.Join(path, fileName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(path); !errors.Is(err, ErrStore) {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatal("unsupported persisted XHTTP was accepted", err)
	}
	if !bytes.Equal(data, readBytes(t, path)) {
		t.Fatal("reopen silently repaired/dropped unsupported secret")
	}
}

func TestXHTTPStorePrivateHeadersNeverBecomeEndpointHosts(t *testing.T) {
	ctx := context.Background()
	s, _ := setup(t)
	headers := map[string]any{"Address": "private-address-token", "SERVER": "private-server-token", "Endpoint": "private-endpoint-token"}
	extra, _ := json.Marshal(map[string]any{"headers": headers})
	u, _ := url.Parse(xhttpStoreURI("tls", "packet-up"))
	q := u.Query()
	q.Set("extra", string(extra))
	u.RawQuery = q.Encode()
	snap, err := s.Import(ctx, manual, u.String(), testTime, time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	id := snap.Nodes[0].ID
	pass := enginePass(id, "xray", "header-authority", testTime)
	if _, err := s.RecordCheck(ctx, id, pass, testTime); err != nil {
		t.Fatal(err)
	}
	binding := RouteBinding{ServiceID: pass.ServiceID, NodeID: id, NetworkProfile: pass.NetworkProfile, Domains: []string{"telegram.org"}}
	material, err := s.MaterializeXray(ctx, []RouteBinding{binding}, testTime)
	if err != nil || !reflect.DeepEqual(material.EndpointHosts, []string{"private-host.example"}) {
		t.Fatal("private header value or SNI/HTTP host became endpoint authority", err)
	}
	defer clear(material.Config)
	var doc struct {
		Outbounds []struct {
			StreamSettings struct {
				XHTTPSettings struct {
					Extra struct{ Headers map[string]any }
				}
			}
		}
	}
	if json.Unmarshal(material.Config, &doc) != nil || len(doc.Outbounds) != 2 || !reflect.DeepEqual(doc.Outbounds[1].StreamSettings.XHTTPSettings.Extra.Headers, headers) {
		t.Fatal("endpoint scoping dropped or changed accepted private headers")
	}
}
