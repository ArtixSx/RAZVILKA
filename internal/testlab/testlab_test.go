package testlab

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
)

func TestProbeCurrent(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer ts.Close()
	r := NewRunner()
	r.Client = ts.Client()
	r.Client.Timeout = 2 * time.Second
	cat := catalog.Catalog{Services: []catalog.Service{{ID: "test", Name: "Test", ProbeURL: ts.URL}}}
	got := r.ProbeCurrent(context.Background(), cat, nil)
	if len(got) != 1 || got[0].Status != "pass" || got[0].HTTPStatus != 204 {
		t.Fatalf("unexpected result: %+v", got)
	}
	snap := r.Snapshot(cat)
	if len(snap.Current) != 1 {
		t.Fatalf("snapshot missing result: %+v", snap)
	}
}

func TestDecodeRunRequest(t *testing.T) {
	ids, err := DecodeRunRequest(strings.NewReader(`{"services":["youtube","chatgpt"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != "youtube" {
		t.Fatalf("ids=%v", ids)
	}
}
