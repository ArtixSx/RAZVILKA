package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodestore"
)

const nodeDefaultSourceFixtureURI = "vless://123e4567-e89b-12d3-a456-426614174000@source-node.example:443?security=tls&sni=source-front.example"

type nodeDefaultSourceFixture struct {
	store *nodestore.Store
	root  string
	id    string
	now   time.Time
	ctx   context.Context
}

func newNodeDefaultSourceFixture(t *testing.T, raw string) *nodeDefaultSourceFixture {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := nodestore.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	f := &nodeDefaultSourceFixture{store: store, root: root, ctx: ctx, now: time.Now().UTC()}
	snapshot, err := store.Import(ctx, nodestore.Source{ID: "manual", Kind: "manual"}, raw, f.now, time.Hour, false)
	if err != nil || len(snapshot.Nodes) != 1 {
		t.Fatal("actual private source fixture import failed", err)
	}
	f.id = snapshot.Nodes[0].ID
	return f
}

func (f *nodeDefaultSourceFixture) review(t *testing.T, engine string) *NodeDefaultSourceReview {
	t.Helper()
	r, err := reviewNodeDefaultSource(f.ctx, f.store, engine+":"+f.id, func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func nodeDefaultSourceRequireCleared(t *testing.T, material []byte) {
	t.Helper()
	if len(material) == 0 || !bytes.Equal(material, make([]byte, len(material))) {
		t.Fatal("callback material was not cleared")
	}
}

func TestNodeDefaultSourceReviewIsReadOnlyAndDoesNotGrantServiceRoute(t *testing.T) {
	for _, engine := range []string{"xray", "sing-box"} {
		t.Run(engine, func(t *testing.T) {
			f := newNodeDefaultSourceFixture(t, nodeDefaultSourceFixtureURI)
			path := filepath.Join(f.root, "nodes.private.json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(before)
			r := f.review(t, engine)
			ref := r.Reference()
			if ref.Schema != 1 || ref.EngineID != engine || ref.NodeID != f.id || ref.Resolved != engine+":"+f.id || ref.NodeGeneration != 1 || !validNetworkPolicyGeneration(ref.MaterialSHA256) {
				t.Fatal("source reference is incomplete")
			}
			ref.NodeID, ref.MaterialSHA256, ref.NodeGeneration = "changed", "changed", 999
			var retained []byte
			if err := r.WithMaterial(f.ctx, func(material []byte) error {
				retained = material
				if !bytes.Contains(material, []byte("123e4567")) {
					t.Fatal("source copy is not actual material")
				}
				// A compiler may edit its copy; it cannot alter the held source.
				clear(material)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			nodeDefaultSourceRequireCleared(t, retained)
			if r.Reference().NodeID != f.id || r.Current(f.ctx) != nil {
				t.Fatal("detached reference or callback copy changed the review")
			}
			bindings := []nodestore.RouteBinding{{ServiceID: "telegram", NodeID: f.id, NetworkProfile: "wan-0123456789ab", Destinations: []string{"149.154.160.0/20"}}}
			if engine == "xray" {
				_, err = f.store.MaterializeXray(f.ctx, bindings, f.now)
			} else {
				_, err = f.store.MaterializeSingBox(f.ctx, bindings, f.now)
			}
			if !errors.Is(err, nodestore.ErrRouteProof) {
				t.Fatal("source-only review promoted unchecked node to service route")
			}
			after, err := os.ReadFile(path)
			defer clear(after)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("source review wrote private store or history")
			}
			public, _ := json.Marshal(r.Reference())
			private, _ := json.Marshal(r)
			for _, secret := range []string{"123e4567", "source-node", "source-front", "outbound", f.root} {
				if bytes.Contains(public, []byte(secret)) || bytes.Contains(private, []byte(secret)) || strings.Contains(fmt.Sprintf("%+v %#v", r, r), secret) {
					t.Fatal("review/reference leaked private source material")
				}
			}
		})
	}
}

func TestNodeDefaultSourceCurrentRevokesChangedOwnerAndFreshness(t *testing.T) {
	for _, change := range []string{"generation", "disabled", "deleted", "expired", "clock-before-origin", "closed-owner", "same-generation-provenance", "same-generation-material"} {
		t.Run(change, func(t *testing.T) {
			f := newNodeDefaultSourceFixture(t, nodeDefaultSourceFixtureURI)
			r := f.review(t, "xray")
			var err error
			switch change {
			case "generation":
				_, err = f.store.SetAlias(f.ctx, f.id, "changed", f.now)
			case "disabled":
				_, err = f.store.SetDisabled(f.ctx, f.id, true, f.now)
			case "deleted":
				_, err = f.store.Delete(f.ctx, f.id, f.now)
			case "expired":
				f.now = f.now.Add(time.Hour)
			case "clock-before-origin":
				f.now = f.now.Add(-time.Second)
			case "closed-owner":
				err = f.store.Close()
			case "same-generation-provenance", "same-generation-material":
				// Controlled external replacement tests actual rereads; it never
				// fabricates a service PASS or changes generation to trigger them.
				backup, e := f.store.ExportPrivate(f.ctx)
				if e != nil {
					t.Fatal(e)
				}
				defer clear(backup.Content)
				var doc map[string]any
				if json.Unmarshal(backup.Content, &doc) != nil {
					t.Fatal("fixture decode failed")
				}
				if change == "same-generation-provenance" {
					node := doc["nodes"].([]any)[0].(map[string]any)
					origin := node["origins"].([]any)[0].(map[string]any)
					origin["received_at"] = f.now.Add(-time.Minute).Format(time.RFC3339Nano)
				} else {
					secret := doc["secrets"].([]any)[0].(map[string]any)
					secret["outbound"].(map[string]any)["uuid"] = "223e4567-e89b-12d3-a456-426614174000"
				}
				data, e := json.Marshal(doc)
				defer clear(data)
				if e != nil {
					t.Fatal(e)
				}
				err = os.WriteFile(filepath.Join(f.root, "nodes.private.json"), data, 0o600)
			}
			if err != nil {
				t.Fatal("fixture mutation failed", err)
			}
			if err := r.Current(f.ctx); !errors.Is(err, ErrNodeDefaultSource) {
				t.Fatal("stale source review accepted", err)
			}
			called := false
			if err := r.WithMaterial(f.ctx, func([]byte) error { called = true; return nil }); !errors.Is(err, ErrNodeDefaultSource) || called {
				t.Fatal("stale source exposed material")
			}
		})
	}
}

func TestNodeDefaultSourceClosesAfterCallbackAndClearsOnAllReturns(t *testing.T) {
	for _, change := range []string{"generation", "expiry", "cancel", "callback-error", "panic"} {
		t.Run(change, func(t *testing.T) {
			f := newNodeDefaultSourceFixture(t, nodeDefaultSourceFixtureURI)
			r := f.review(t, "xray")
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			callbackErr := errors.New("private compiler refused")
			var retained []byte
			calls := 0
			invoke := func() error {
				return r.WithMaterial(ctx, func(material []byte) error {
					retained, calls = material, calls+1
					switch change {
					case "generation":
						_, err := f.store.SetAlias(f.ctx, f.id, "during-copy", f.now)
						return err
					case "expiry":
						f.now = f.now.Add(time.Hour)
					case "cancel":
						cancel()
					case "callback-error":
						return callbackErr
					case "panic":
						panic(callbackErr)
					}
					return nil
				})
			}
			if change == "panic" {
				func() {
					defer func() {
						if recover() != callbackErr {
							t.Fatal("private compiler panic was changed")
						}
					}()
					_ = invoke()
				}()
			} else {
				err := invoke()
				if change == "callback-error" {
					if !errors.Is(err, callbackErr) {
						t.Fatal("compiler error was hidden", err)
					}
				} else if !errors.Is(err, ErrNodeDefaultSource) {
					t.Fatal("closing owner refusal was hidden", err)
				}
			}
			if calls != 1 {
				t.Fatal("private material callback retried")
			}
			nodeDefaultSourceRequireCleared(t, retained)
		})
	}
}

func TestNodeDefaultSourceOpeningClosingGenerationRace(t *testing.T) {
	f := newNodeDefaultSourceFixture(t, nodeDefaultSourceFixtureURI)
	reads := 0
	r, err := reviewNodeDefaultSource(f.ctx, f.store, "xray:"+f.id, func() time.Time {
		reads++
		if reads == 2 {
			if _, err := f.store.SetAlias(f.ctx, f.id, "changed-between-owner-reads", f.now); err != nil {
				t.Fatal(err)
			}
		}
		return f.now
	})
	if r != nil || !errors.Is(err, ErrNodeDefaultSource) {
		t.Fatal("source constructor accepted mixed generations")
	}
}

func TestNodeDefaultSourceRequiresFiniteLiveContextAndConcreteOwner(t *testing.T) {
	f := newNodeDefaultSourceFixture(t, nodeDefaultSourceFixtureURI)
	r := f.review(t, "xray")
	canceled, cancel := context.WithCancel(f.ctx)
	cancel()
	for _, ctx := range []context.Context{nil, context.Background(), canceled} {
		if review, err := ReviewNodeDefaultSource(ctx, f.store, "xray:"+f.id); review != nil || !errors.Is(err, ErrNodeDefaultSource) {
			t.Fatal("unbounded/canceled review context accepted")
		}
		if err := r.Current(ctx); !errors.Is(err, ErrNodeDefaultSource) {
			t.Fatal("unbounded/canceled current context accepted")
		}
		called := false
		if err := r.WithMaterial(ctx, func([]byte) error { called = true; return nil }); !errors.Is(err, ErrNodeDefaultSource) || called {
			t.Fatal("invalid context exposed material")
		}
	}
	var empty *NodeDefaultSourceReview
	if empty.Reference() != (NodeDefaultSourceReference{}) || empty.Current(f.ctx) == nil || new(NodeDefaultSourceReview).Current(f.ctx) == nil || r.WithMaterial(f.ctx, nil) == nil {
		t.Fatal("unissued source review or nil callback accepted")
	}
	for _, route := range []string{"xray", "xray:group-" + strings.Repeat("a", 64), "auto", "direct", "xray:" + f.id + ":extra", "usque:" + f.id, "sing-box:" + strings.ToUpper(f.id)} {
		if review, err := ReviewNodeDefaultSource(f.ctx, f.store, route); review != nil || !errors.Is(err, ErrNodeDefaultSource) {
			t.Fatal("non-exact resolved source accepted")
		}
	}
	if review, err := ReviewNodeDefaultSource(f.ctx, nil, "xray:"+f.id); review != nil || err == nil {
		t.Fatal("nil source owner accepted")
	}
}

func TestNodeDefaultSourceKeepsXHTTPEngineBoundary(t *testing.T) {
	raw := nodeDefaultSourceFixtureURI + "&type=xhttp&mode=packet-up&host=source-front.example&path=%2Ftunnel"
	f := newNodeDefaultSourceFixture(t, raw)
	if _, err := ReviewNodeDefaultSource(f.ctx, f.store, "xray:"+f.id); err != nil {
		t.Fatal("compiler-supported XHTTP source refused", err)
	}
	if r, err := ReviewNodeDefaultSource(f.ctx, f.store, "sing-box:"+f.id); r != nil || !errors.Is(err, ErrNodeDefaultSource) {
		t.Fatal("XHTTP source was silently transferred to Sing-box")
	}
}
