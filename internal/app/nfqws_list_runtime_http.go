package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/physicalscope"
)

const managedNFQListRuntimePath = "/api/v1/strategy-lab/runtime"

// This bounded laboratory caller reaches the SAME startup/App runtime. It
// accepts only a saved selection target, never paths, commands or evidence.
// The normal project controls must use this owner too, not another executor.
func (a *App) managedNFQListRuntimeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var input struct {
		Action    string `json:"action"`
		ServiceID string `json:"service_id,omitempty"`
		Protocol  string `json:"protocol,omitempty"`
		Family    string `json:"ip_family,omitempty"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		http.Error(w, "invalid managed runtime request", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		http.Error(w, "one managed runtime request is required", http.StatusBadRequest)
		return
	}
	if input.Action != "start" && input.Action != "check" && input.Action != "stop" ||
		input.Action == "start" && (input.ServiceID == "" || input.Protocol != "tcp" && input.Protocol != "quic" || input.Family != "ipv4" && input.Family != "ipv6") ||
		input.Action != "start" && (input.ServiceID != "" || input.Protocol != "" || input.Family != "") {
		http.Error(w, "invalid managed runtime target", http.StatusBadRequest)
		return
	}
	a.managedNFQListMu.Lock()
	runtime := a.managedNFQList
	a.managedNFQListMu.Unlock()
	if runtime == nil {
		writeManagedNFQRuntimeError(w, http.StatusServiceUnavailable, "MANAGED_NFQWS_RUNTIME_UNAVAILABLE")
		return
	}
	// All methods own their actual admission. In particular an unknown Stop
	// joins its still-held original cleanup owner, without entering a new gate.
	ctx, cancel := context.WithTimeout(operationgate.WithLabel(r.Context(), "управление удерживаемым маршрутом NFQWS"), 15*time.Second)
	defer cancel()
	var err error
	response := map[string]any{"ok": true, "service_health": "unverified"}
	switch input.Action {
	case "start":
		execution, startErr := runtime.Start(ctx, input.ServiceID, input.Protocol, input.Family)
		err = startErr
		response["execution"] = execution
		response["runtime_state"] = "native-active"
		response["live_applied"] = true
	case "check":
		err = runtime.Current(ctx)
		response["runtime_state"] = "native-active"
	case "stop":
		err = runtime.Stop(ctx)
		response["runtime_state"] = "stopped"
	}
	if err != nil {
		stage, reason := managedNFQFailureDiagnostic(err)
		log.Printf("Managed NFQ runtime %s refused at %s (%s)", input.Action, stage, reason)
		if physical := physicalscope.DiagnosticStages(err); len(physical) > 0 {
			log.Printf("Managed NFQ original physical refusal: %s", strings.Join(physical, " > "))
		}
		status, code := http.StatusConflict, "MANAGED_NFQWS_RUNTIME_REFUSED"
		if errors.Is(err, operationgate.ErrBusy) {
			code = "MANAGED_NFQWS_RUNTIME_BUSY"
		} else if errors.Is(err, operationgate.ErrRecovery) || errors.Is(err, errComponentRecovery) || errors.Is(err, errSelfUpdateRecovery) {
			status, code = http.StatusServiceUnavailable, "MANAGED_NFQWS_RUNTIME_RECOVERY_REQUIRED"
		} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			status, code = http.StatusRequestTimeout, "MANAGED_NFQWS_RUNTIME_UNCONFIRMED"
		}
		// An error may follow actual effects or an uncertain cleanup. Do not
		// claim unchanged settings, stopped native lifetime or successful Apply.
		writeManagedNFQRuntimeError(w, status, code)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func writeManagedNFQRuntimeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]any{"ok": false, "code": code, "error": "Состояние удерживаемого маршрута NFQWS не подтверждено. Проверьте журнал и исходную область маршрута.", "service_health": "unverified"})
}
