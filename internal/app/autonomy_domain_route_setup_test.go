package app

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
)

// A newly imported domain-only service cannot be repaired by downloading
// proxy nodes or changing DNS settings. Explain the actual missing prerequisite
// while retaining the no-probe/no-apply boundary for IP policy executors.
func TestAutopilotDomainServiceNamesActionableSetupWithoutApplying(t *testing.T) {
	for _, test := range []struct {
		name       string
		ready      bool
		allowed    bool
		want       string
		wantProbes []string
	}{
		{"route-disabled", true, false, "Разрешите NFQWS2 в маршрутах автопилота", nil},
		{"runtime-not-ready", false, true, "Откройте «Обходы», настройте NFQWS2", nil},
		{"service-unconfirmed", true, true, "NFQWS2 готов, но доступ к сервису не подтверждён", []string{"nfqws2"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := catalog.Service{ID: "domain-import", Name: "Imported domain list", Domains: []string{"site.example"}, ProbeURL: "https://site.example/"}
			a, adapter, recorder := domainAutopilotFixture(t, service, test.ready)
			if !test.allowed {
				a.autonomy.mu.Lock()
				a.autonomy.doc.Policy.PreferredRoutes = []string{"sing-box", "xray"}
				err := a.persistAutonomyLocked(context.Background())
				a.autonomy.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
			}
			before := a.Store.Get()
			committed, _, _ := a.Dataplane.Committed()
			domainAutopilotDue(a, service.ID)
			a.autonomyRound(context.Background(), time.Now())
			state, message := domainAutopilotState(a, service.ID)
			if state != autonomyStateDomainRouteUnavailable || !strings.Contains(message, test.want) || !strings.Contains(message, "«Проверка NFQWS2»") {
				t.Fatalf("missing actionable setup: %s %q", state, message)
			}
			if !strings.Contains(message, "импорт подключений и смена DNS не помогут") || !strings.Contains(message, "проверенными IP-сетями") {
				t.Fatal("setup advice implied a proxy/DNS shortcut", message)
			}
			if !slices.Equal(recorder.routes(), test.wantProbes) || recorder.nodeChecks != 0 || len(adapter.calls) != 0 {
				t.Fatal("setup status crossed the domain route guard", recorder.routes(), recorder.nodeChecks, adapter.calls)
			}
			current, _, _ := a.Dataplane.Committed()
			if !reflect.DeepEqual(before, a.Store.Get()) || !reflect.DeepEqual(committed, current) {
				t.Fatal("setup status changed settings or committed routes")
			}
		})
	}
}
