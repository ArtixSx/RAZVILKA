// Package panelhealth reports panel liveness without reading runtime Stores.
// The caller MUST place this handler behind the existing authentication
// middleware. HTTP 200 certifies an answering panel, not a working bypass.
package panelhealth

import (
	"encoding/json"
	"net/http"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

const Path = "/api/v1/panel/availability"

type response struct {
	Schema    int                    `json:"schema"`
	Name      string                 `json:"name"`
	Panel     string                 `json:"panel"`
	Dataplane string                 `json:"dataplane"`
	Admission operationgate.Snapshot `json:"admission"`
}

// Handler intentionally has no dependency on App, network inventory, runtime
// health, private restore files, or an external command. Do not expand it into
// a second /status handler: its job is to stay available while those are busy.
func Handler(gate *operationgate.Gate) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if gate == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		value := response{Schema: 1, Name: "RAZVILKA", Panel: "responding", Dataplane: "not-checked", Admission: gate.Snapshot()}
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodHead {
			return
		}
		// No private error or configuration material is included in this payload.
		_ = json.NewEncoder(w).Encode(value)
	})
}
