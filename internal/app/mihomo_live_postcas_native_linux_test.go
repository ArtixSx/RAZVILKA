//go:build linux && razvilka_native_fixture

package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// A separate test PROCESS/private namespace is required: DefaultRootCAs and
// the actual physical namespaces must not be reused after the positive case.
func TestMihomoLiveOriginalPostCASServiceFailure(t *testing.T) {
	runMihomoLiveOriginalNativeWorkflow(t, true)
}

func mihomoLiveNativeDegradeAfterCAS(peers *domainOriginalNativePeers, binding *mihomoNodeBinding) error {
	committed := binding.after.Load()
	if committed == nil || !reflect.DeepEqual(binding.store.Get(), *committed) || committed.Revision != binding.before.Revision+1 || binding.before.Services[binding.service.ID].Route != "direct" || len(binding.plan.Routes) != 1 || committed.Services[binding.service.ID].Route != binding.plan.Routes[0].Selected || committed.AppliedServices[binding.service.ID].Route != binding.plan.Routes[0].Selected {
		return errors.New("actual original captured configuration CAS is required before physical failure")
	}
	file, err := os.OpenFile(filepath.Join(peers.root, "mihomo-service-degraded"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.WriteString("physical-error-after-original-cas-v1\n")
	return errors.Join(writeErr, file.Sync(), file.Close())
}

func assertMihomoLivePostCASFailure(t *testing.T, ctx context.Context, a *App, peers *domainOriginalNativePeers, configPath string, before config.Config, binding *mihomoNodeBinding, actualCAS bool, execution dataplane.Execution, detail string, status int, decodeErr error) {
	t.Helper()
	if decodeErr != nil || !actualCAS || status != http.StatusConflict || !strings.Contains(detail, "(http-503)") || execution.State != "rolled-back" && execution.State != "rollback-failed" {
		t.Fatal("actual after-CAS required service rejection was not observed", actualCAS, status, execution.State, detail, decodeErr)
	}
	// Compare the exact before image, not just revision arithmetic. Undo must
	// restore both desired/applied selection and all unrelated configuration.
	if !reflect.DeepEqual(a.Store.Get(), before) || binding.after.Load() != nil {
		t.Fatal("actual failed final health did not undo its exact captured CAS")
	}
	reloaded, err := config.LoadExisting(configPath)
	if err != nil || !reflect.DeepEqual(reloaded.Get(), before) {
		t.Fatal("strict reload lost original desired configuration", err)
	}
	committed, found, err := a.Dataplane.Committed()
	if err != nil || found && committed.State == "committed" {
		t.Fatal("failed final service was published as committed", found, committed.State, err)
	}
	observed := filepath.Join(peers.root, "mihomo-service-degraded-observed")
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var data []byte
	for {
		file, openErr := os.Open(observed)
		if openErr == nil {
			data, err = io.ReadAll(io.LimitReader(file, 8193))
			err = errors.Join(err, file.Close())
			if err != nil || len(data) > 8192 {
				t.Fatal("bounded actual physical response evidence", err)
			}
			if len(data) > 0 && data[len(data)-1] == '\n' {
				break
			}
		} else if !errors.Is(openErr, os.ErrNotExist) {
			t.Fatal(openErr)
		}
		select {
		case <-bounded.Done():
			t.Fatal("actual physical 503 delivery was not confirmed", bounded.Err())
		case <-ticker.C:
		}
	}
	var event struct {
		Host, Source, Marker string
		Status               int
	}
	line := strings.SplitN(string(data), "\n", 2)[0]
	decoder := json.NewDecoder(strings.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&event); err != nil || event.Host != "service.example.com" || event.Status != 503 || event.Source != domainOriginalServer || event.Marker != "physical-error-after-cas" {
		t.Fatal("failed required TLS did not traverse actual selected physical peer", event, err)
	}
	pending := a.Dataplane.HasPendingMihomoLive()
	unknown := execution.State == "rollback-failed" || pending
	for _, row := range execution.Resources {
		unknown = unknown || row.State != "removed" && row.State != "unused"
	}
	if unknown && !a.Dataplane.HasPendingMihomoLive() {
		t.Fatal("original unknown rollback lost its pending owner")
	}
	if !unknown && !execution.RollbackVerified {
		t.Fatal("successful original rollback lacks independent native readback")
	}
	if unknown {
		check, finish := context.WithTimeout(ctx, time.Second)
		_, release, err := a.Operations.ExclusiveContext(check)
		finish()
		if err == nil {
			release()
			t.Fatal("original unknown rollback released forward admission")
		}
		if !errors.Is(err, operationgate.ErrBusy) && !errors.Is(err, operationgate.ErrRecovery) {
			t.Fatal("unknown rollback lacks original admission fence", err)
		}
	}
	if err := os.Remove(filepath.Join(peers.root, "mihomo-service-degraded")); err != nil {
		t.Fatal(err)
	}
	if !unknown {
		baseline := mihomoLiveNativeLANRequest(t, ctx, peers)
		if baseline.Source != domainOriginalClient {
			t.Fatal("known rollback did not restore actual physical baseline", baseline)
		}
	}
	t.Logf("actual_postcas_service_rejection status=503 desired_exact_restored=true state=%s rollback_verified=%t original_pending=%t", execution.State, execution.RollbackVerified, a.Dataplane.HasPendingMihomoLive())
	if unknown || execution.State != "rolled-back" || !execution.RollbackVerified {
		t.Fatal("real service rejection stayed fenced but original rollback is not complete")
	}
}
