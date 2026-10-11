package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/customservices"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Actual public custom-service handler, applied registry, Store and source
// owners are used here. Physical/WAN and recorded node health remain the
// explicit unit fixture models; this is no native/check/router evidence.
func newListXrayInlineFixture(t *testing.T) (*listXraySourceFixture, catalog.Service, string) {
	t.Helper()
	f := newListXraySourceFixture(t, "xray")
	private := filepath.Join(f.root, "custom-registry")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(private, "custom-services.json")
	var err error
	f.a.CustomServices, err = customservices.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/custom-services", strings.NewReader(`{"id":"inline","name":"Inline fixture","cidrs":["149.154.167.51/32","1.1.1.1/32"],"strategy":["xray"],"probe_url":"https://1.1.1.1/"}`))
	response := httptest.NewRecorder()
	f.a.customServiceList(response, request)
	var service catalog.Service
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &service) != nil {
		t.Fatal("ordinary custom POST failed", response.Code)
	}
	if len(service.SourceRefs) != 0 {
		t.Fatal("POST fabricated source references")
	}
	if err := f.a.Store.UpdateService(service.ID, config.ServiceState{Enabled: true, Route: "xray:" + f.nodeID}); err != nil {
		t.Fatal(err)
	}
	check := nodestore.CheckRecord{ProbeID: "fixture-inline-health", ServiceID: service.ID, NetworkProfile: f.physical.network, RoutePathID: "xray:" + f.nodeID,
		TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: f.now, ExpiresAt: f.now.Add(time.Hour)}
	if _, err := f.a.Nodes.RecordCheck(context.Background(), f.nodeID, check, f.now); err != nil {
		t.Fatal(err)
	}
	if err := f.scope.Close(); err != nil {
		t.Fatal(err)
	}
	listScopeOperation(t, f.a, func(ctx context.Context) {
		f.scope, err = newListScopeBinding(ctx, f.a, f.physical.acquire)
		if err != nil {
			t.Fatal(err)
		}
	})
	return f, service, path
}

func TestListXrayInlineSourceOrdinaryAppliedDefinitionAndCommit(t *testing.T) {
	f, service, path := newListXrayInlineFixture(t)
	listScopeOperation(t, f.a, func(ctx context.Context) {
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		r, err := f.a.ReviewXrayListRuntimeSource(ctx, f.scope, service.ID, f.adapter)
		if err != nil {
			t.Fatal("ordinary inline source refused", err)
		}
		defer r.Close()
		o, err := r.Observation(ctx)
		if err != nil || r.cidrs != nil || r.inline == nil || o.Inline == nil || o.Inline.ServiceID != service.ID ||
			!reflect.DeepEqual(o.Inline.CIDRs, service.CIDRs) || len(o.Sources.SourceIDs) != 0 || len(o.Sources.Revisions) != 0 || len(o.Service.SourceRefs) != 0 {
			t.Fatal("inline definition borrowed external provenance", err)
		}
		o.Inline.CIDRs[0] = "0.0.0.0/0"
		if err := r.Current(ctx); err != nil {
			t.Fatal("detached observation changed original", err)
		}
		_, started, finished := xrayAssemblySourceCAS(t, r)
		if err := r.acceptCommitted(ctx, started, finished); err != nil {
			t.Fatal("actual inline CAS failed", err)
		}
		after, err := os.ReadFile(path)
		if err != nil || string(before) != string(after) {
			t.Fatal("source/commit wrote custom definition", err)
		}
		if err := r.Close(); err != nil || r.Current(ctx) == nil {
			t.Fatal("closed inline source remained usable", err)
		}
		if !f.a.CustomServices.Has(service.ID) {
			t.Fatal("source closed shared custom owner")
		}
	})
}

func TestListXrayInlineSourceRefusesReplacementForeignManagerAndFabricatedRefs(t *testing.T) {
	for _, change := range []string{"same-bytes-replacement", "foreign-manager", "fabricated-source-refs", "catalog-only-inline"} {
		t.Run(change, func(t *testing.T) {
			f, service, path := newListXrayInlineFixture(t)
			listScopeOperation(t, f.a, func(ctx context.Context) {
				if change == "fabricated-source-refs" {
					service.SourceRefs = []string{"reviewed-networks"}
					if _, err := f.a.CustomServices.Update(service.ID, service); err != nil {
						t.Fatal(err)
					}
					if _, err := f.a.ReviewXrayListRuntimeSource(ctx, f.scope, service.ID, f.adapter); err == nil {
						t.Fatal("unapplied references became source issuer")
					}
					return
				}
				if change == "catalog-only-inline" {
					if err := f.a.CustomServices.Delete(service.ID); err != nil {
						t.Fatal(err)
					}
					f.a.Catalog.Services = append(f.a.Catalog.Services, service)
					if _, err := f.a.ReviewXrayListRuntimeSource(ctx, f.scope, service.ID, f.adapter); err == nil {
						t.Fatal("catalog DTO became applied custom issuer")
					}
					return
				}
				r, err := f.a.ReviewXrayListRuntimeSource(ctx, f.scope, service.ID, f.adapter)
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				original := f.a.CustomServices
				if change == "foreign-manager" {
					f.a.CustomServices, err = customservices.Load(path)
					if err != nil {
						t.Fatal(err)
					}
				} else {
					image, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					root, err := ownedfs.Open(filepath.Dir(path))
					if err != nil {
						t.Fatal(err)
					}
					defer root.Close()
					if err := root.WriteAtomic(filepath.Base(path), image, 0600); err != nil {
						t.Fatal(err)
					}
				}
				if err := r.Current(ctx); err == nil {
					t.Fatal("changed original inline owner accepted")
				}
				f.a.CustomServices = original
				if err := r.Current(ctx); err == nil {
					t.Fatal("restoring pointer revived refused source")
				}
			})
		})
	}
}
