package app

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/catalog"
	routecatalog "github.com/ArtixSx/razvilka/internal/routes"
)

// This is the finishing diagnostic after existing route admission/probes. It
// must not turn component readiness into proof of selector/device coverage.
func TestAutonomyDomainFinishingDiagnosticSeparatesProfileScopeAndRuntime(t *testing.T) {
	for _, test := range []struct {
		name, current                          string
		mixed, scoped, stopped, ready, healthy bool
		want, absent                           []string
	}{
		{name: "mixed unknown profile", mixed: true, ready: true,
			want:   []string{"Домены и IP-сети", "Для закрытого профиля NFQWS2", "работа полного списка не подтверждена", "Список и область сохранены"},
			absent: []string{"NFQWS2 готов", "подберите стратегию", "отдельный сервис с проверенными IP-сетями", "Этот профиль NFQWS2"}},
		{name: "mixed selected devices", mixed: true, scoped: true, ready: true,
			want: []string{"Домены и IP-сети", "доступны только домены/TCP 443", "для выбранных устройств не подтверждена"}},
		{name: "domain selected devices", scoped: true, ready: true,
			want: []string{"поддерживается вся домашняя сеть", "для выбранных устройств не подтверждена"}, absent: []string{"Домены и IP-сети", "подберите стратегию"}},
		{name: "installed stopped ready", stopped: true, ready: true,
			want: []string{"NFQWS2 установлен, но не запущен", "Без работающего процесса"}, absent: []string{"готов, но", "подберите стратегию"}},
		{name: "installed stopped not ready", stopped: true,
			want: []string{"NFQWS2 установлен, но не запущен"}, absent: []string{"NFQWS2 не готов", "подберите стратегию"}},
		{name: "mixed stopped retains both limits", mixed: true, scoped: true, stopped: true,
			want: []string{"NFQWS2 установлен, но не запущен", "Домены и IP-сети", "для выбранных устройств не подтверждена"}, absent: []string{"подберите стратегию"}},
		{name: "running unconfirmed", ready: true,
			want: []string{"не подтвердил доступ к сервису"}, absent: []string{"не запущен", "подберите стратегию"}},
		{name: "confirmed current failure", ready: true, current: "nfqws2",
			want: []string{"Действующий путь не подтвердил работу сервиса", "Маршрут сохранён; проверка повторится"}, absent: []string{"подберите стратегию", "не запущен"}},
		{name: "healthy external mixed preserved", mixed: true, scoped: true, ready: true, current: "nfqws2", healthy: true,
			want: []string{"Работающий путь сохранён"}, absent: []string{"не поддерживает", "Поддержка полного списка"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := catalog.Service{ID: "diagnostic-domain", Domains: []string{"selected.example"}}
			if test.mixed {
				service.CIDRs = []string{"192.0.2.0/24"}
			}
			a, adapter, recorder := domainAutopilotFixture(t, service, test.ready)
			a.nodeReviews.options = func() []routecatalog.Option {
				return []routecatalog.Option{{ID: "nfqws2", Installed: true, Configured: true, Ready: test.ready, Running: !test.stopped}}
			}
			cfg := a.Store.Get()
			spec := autonomy.Service{ID: service.ID, AllLAN: !test.scoped}
			if test.scoped {
				spec.Sources = []string{"192.168.1.50/32"}
			}
			applied := cfg.AppliedServices[service.ID]
			applied.Sources = append([]string(nil), spec.Sources...)
			cfg.AppliedServices[service.ID] = applied
			before := a.Store.Get()
			committed, _, _ := a.Dataplane.Committed()
			runtime := autonomy.Runtime{Failures: 2, FailureNode: "nfqws2", Switches: []time.Time{time.Now()}, Cursor: 3}
			next := a.finishAutonomyDomainService(context.Background(), autonomy.Policy{PreferredRoutes: []string{"nfqws2"}}, spec, runtime, cfg, "", test.current, test.healthy)
			wantState := autonomyStateDomainRouteUnavailable
			if test.healthy {
				wantState = "healthy"
			}
			if next.State != wantState {
				t.Fatal("wrong diagnostic state", next.State, next.Message)
			}
			if boundedAutonomyMessage(next.Message) != next.Message {
				t.Fatal("diagnostic would lose its qualifiers in the runtime journal", len(next.Message))
			}
			for _, want := range test.want {
				if !strings.Contains(next.Message, want) {
					t.Fatal("missing diagnostic", want, next.Message)
				}
			}
			for _, absent := range test.absent {
				if strings.Contains(next.Message, absent) {
					t.Fatal("misleading diagnostic", absent, next.Message)
				}
			}
			runtime.State, runtime.Message = next.State, next.Message
			if !reflect.DeepEqual(runtime, next) {
				t.Fatal("diagnostic changed traversal or failure/switch budget", next)
			}
			after, _, _ := a.Dataplane.Committed()
			if len(recorder.routes()) != 0 || recorder.nodeChecks != 0 || len(adapter.calls) != 0 || !reflect.DeepEqual(before, a.Store.Get()) || !reflect.DeepEqual(committed, after) {
				t.Fatal("finishing diagnostic gained probe/apply authority")
			}
		})
	}
}

func TestAutonomyMixedUnknownProfileRoundDoesNotSuggestStrategyRepair(t *testing.T) {
	service := catalog.Service{ID: "mixed-diagnostic", Domains: []string{"selected.example"}, CIDRs: []string{"192.0.2.0/24"}, ProbeURL: "https://selected.example/"}
	a, adapter, recorder := domainAutopilotFixture(t, service, true)
	before := a.Store.Get()
	committed, _, _ := a.Dataplane.Committed()
	domainAutopilotDue(a, service.ID)
	a.autonomyRound(context.Background(), time.Now())
	state, message := domainAutopilotState(a, service.ID)
	if state != autonomyStateDomainRouteUnavailable || !strings.Contains(message, "работа полного списка не подтверждена") || strings.Contains(message, "подберите стратегию") {
		t.Fatal("mixed round hid the selector limit", state, message)
	}
	after, _, _ := a.Dataplane.Committed()
	// Unknown/external profiles retain the existing single NFQ probe; this
	// diagnostic must not add an admission denial or any VPN/node fallback.
	if !reflect.DeepEqual(recorder.routes(), []string{"nfqws2"}) || recorder.nodeChecks != 0 || len(adapter.calls) != 0 || !reflect.DeepEqual(before, a.Store.Get()) || !reflect.DeepEqual(committed, after) {
		t.Fatal("diagnostic changed existing route authority", recorder.routes(), adapter.calls)
	}
}
