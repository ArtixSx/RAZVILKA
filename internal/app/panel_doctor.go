package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/engine"
)

// panelDoctorPath answers "why does it not open?" in five plain groups, as the
// owner sees them. It reads memory snapshots only (like the other panel
// paths) and runs two bounded direct probes, so it answers while the autopilot
// holds the operation gate. It changes nothing.
const panelDoctorPath = "/api/v1/panel/doctor"

type doctorCheck struct {
	ID     string        `json:"id"`
	Title  string        `json:"title"`
	Status string        `json:"status"` // ok, warn, fail
	Detail string        `json:"detail"`
	Items  []doctorItem  `json:"items,omitempty"`
	Action *doctorAction `json:"action,omitempty"`
}

type doctorItem struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type doctorAction struct {
	View  string `json:"view"`
	Label string `json:"label"`
}

type doctorReport struct {
	Schema    int           `json:"schema"`
	CheckedAt time.Time     `json:"checked_at"`
	Status    string        `json:"status"`
	Summary   string        `json:"summary"`
	Checks    []doctorCheck `json:"checks"`
}

// doctorProbes are replaced in tests; production dials public endpoints
// directly from the router.
type doctorProbes struct {
	dial    func(ctx context.Context, address string) error
	resolve func(ctx context.Context, host string) error
	engines func() []engine.Status
}

func defaultDoctorProbes() doctorProbes {
	return doctorProbes{
		dial: func(ctx context.Context, address string) error {
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
			if err == nil {
				_ = conn.Close()
			}
			return err
		},
		resolve: func(ctx context.Context, host string) error {
			_, err := net.DefaultResolver.LookupHost(ctx, host)
			return err
		},
		engines: func() []engine.Status { return (engine.Detector{}).Inventory() },
	}
}

func (a *App) panelDoctor(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	probes := a.doctorProbes
	if probes.dial == nil {
		probes = defaultDoctorProbes()
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, a.doctorAt(ctx, probes, time.Now()))
}

func (a *App) doctorAt(ctx context.Context, probes doctorProbes, now time.Time) doctorReport {
	internet, dns := doctorNetwork(ctx, probes)
	checks := []doctorCheck{internet, dns, a.doctorRazvilka(), a.doctorEngines(probes), a.doctorServices()}
	report := doctorReport{Schema: 1, CheckedAt: now.UTC(), Status: "ok", Checks: checks}
	for _, c := range checks {
		report.Status = worseDoctorStatus(report.Status, c.Status)
	}
	switch report.Status {
	case "ok":
		report.Summary = "Всё в порядке: интернет есть, обход работает, сервисы подтверждены."
	case "warn":
		report.Summary = "В целом работает. Ниже то, что ещё проверяется или требует времени."
	default:
		report.Summary = "Есть проблема. Начните с первой красной строки."
	}
	return report
}

func worseDoctorStatus(a, b string) string {
	rank := map[string]int{"ok": 0, "warn": 1, "fail": 2}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// doctorNetwork checks that the router itself reaches the internet (two
// public addresses on 443) and resolves names (two well-known hosts). Either
// answer of a pair is enough.
func doctorNetwork(ctx context.Context, probes doctorProbes) (doctorCheck, doctorCheck) {
	race := func(timeout time.Duration, run func(context.Context, string) error, targets ...string) error {
		c, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		var mu sync.Mutex
		var wg sync.WaitGroup
		var first error = errors.New("no answer")
		ok := false
		for _, target := range targets {
			wg.Add(1)
			go func(target string) {
				defer wg.Done()
				err := run(c, target)
				mu.Lock()
				defer mu.Unlock()
				if err == nil {
					ok = true
				} else {
					first = err
				}
			}(target)
		}
		wg.Wait()
		if ok {
			return nil
		}
		return first
	}
	internet := doctorCheck{ID: "internet", Title: "Интернет роутера", Status: "ok", Detail: "Роутер выходит в интернет напрямую."}
	if race(4*time.Second, probes.dial, "1.1.1.1:443", "77.88.8.8:443") != nil {
		internet.Status, internet.Detail = "fail", "Роутер не достучался до интернета. Проверьте подключение к провайдеру: без него обход не поможет."
	}
	dns := doctorCheck{ID: "dns", Title: "Адреса сайтов (DNS)", Status: "ok", Detail: "Имена сайтов определяются."}
	if race(4*time.Second, probes.resolve, "ya.ru", "www.google.com") != nil {
		dns.Status, dns.Detail = "fail", "Роутер не определяет адреса сайтов. Проверьте DNS в настройках роутера или провайдера."
		dns.Action = &doctorAction{View: "dns", Label: "Открыть DNS"}
	}
	return internet, dns
}

func (a *App) doctorRazvilka() doctorCheck {
	c := doctorCheck{ID: "razvilka", Title: "RAZVILKA", Status: "ok", Detail: "Работает, автопилот включён."}
	if a.Operations.Snapshot().Fenced {
		c.Status, c.Detail = "fail", "Изменения приостановлены до проверки журнала сетевых транзакций. Обход, который уже работал, сохранён."
		c.Action = &doctorAction{View: "activity", Label: "Открыть события"}
		return c
	}
	if a.Store == nil {
		c.Status, c.Detail = "warn", "Настройки ещё загружаются."
		return c
	}
	cfg := a.Store.Get()
	if cfg.ServiceControl.Stopped {
		c.Status, c.Detail = "warn", "Обход выключен кнопкой «Выключить всё». Включите его, чтобы сервисы снова открывались."
		return c
	}
	p := a.autonomyPolicy()
	switch {
	case !p.SetupComplete:
		c.Status, c.Detail = "warn", "Первоначальная настройка не завершена."
		c.Action = &doctorAction{View: "autopilot", Label: "Начать настройку"}
	case !p.Enabled:
		c.Status, c.Detail = "warn", "Автопилот на паузе: сервисы не проверяются и не переключаются."
		c.Action = &doctorAction{View: "autopilot", Label: "Открыть автопилот"}
	}
	return c
}

// doctorEngines reports the engines that carry applied services.
func (a *App) doctorEngines(probes doctorProbes) doctorCheck {
	c := doctorCheck{ID: "engines", Title: "Способы обхода", Status: "ok"}
	used := map[string]int{}
	if a.Store != nil {
		for _, state := range a.Store.Get().AppliedServices {
			if state.Enabled {
				if route := selectedRoute(state); route != "" && route != "auto" && route != "direct" {
					used[strings.SplitN(route, ":", 2)[0]]++
				}
			}
		}
	}
	if len(used) == 0 {
		c.Detail = "Пока ни один способ не назначен."
		return c
	}
	running := map[string]bool{}
	names := map[string]string{}
	for _, s := range probes.engines() {
		running[s.ID] = s.Running
		names[s.ID] = s.Name
	}
	ids := make([]string, 0, len(used))
	for id := range used {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	working := []string{}
	for _, id := range ids {
		name := names[id]
		if name == "" {
			name = id
		}
		item := doctorItem{ID: id, Name: name, Status: "ok", Detail: fmt.Sprintf("работает, сервисов: %d", used[id])}
		if known, ok := running[id]; ok && !known {
			item.Status, item.Detail = "fail", fmt.Sprintf("не запущен, сервисов: %d", used[id])
			c.Status = "fail"
		} else {
			working = append(working, name)
		}
		c.Items = append(c.Items, item)
	}
	if c.Status == "ok" {
		c.Detail = "Работают: " + strings.Join(working, ", ") + "."
	} else {
		c.Detail = "Нужный способ обхода не запущен; сервисы через него не откроются."
		c.Action = &doctorAction{View: "engines", Label: "Открыть обходы"}
	}
	return c
}

// doctorServices summarizes the autopilot's own latest results.
func (a *App) doctorServices() doctorCheck {
	c := doctorCheck{ID: "services", Title: "Ваши сервисы", Status: "ok"}
	names := map[string]string{}
	for _, s := range a.catalogSnapshot().Services {
		names[s.ID] = s.Name
	}
	a.autonomy.mu.Lock()
	type row struct{ id, state, message string }
	rows := []row{}
	for id, s := range a.autonomy.doc.Services {
		if s.Removing {
			continue
		}
		r := a.autonomy.doc.Runtime[id]
		rows = append(rows, row{id, r.State, r.Message})
	}
	a.autonomy.mu.Unlock()
	if len(rows) == 0 {
		c.Status, c.Detail = "warn", "Сервисы ещё не добавлены."
		return c
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].id < rows[j].id })
	good, waiting, bad := 0, 0, 0
	for _, r := range rows {
		name := names[r.id]
		if name == "" {
			name = r.id
		}
		item := doctorItem{ID: r.id, Name: name, Detail: r.message}
		switch r.state {
		case "healthy", "applied":
			item.Status = "ok"
			good++
		case "", "pending", "checking", "applying", "searching", "scope-pending", "rate-limited":
			item.Status = "warn"
			waiting++
		default:
			item.Status = "fail"
			bad++
		}
		c.Items = append(c.Items, item)
	}
	switch {
	case bad > 0:
		c.Status, c.Detail = "fail", fmt.Sprintf("Не работают: %d из %d. Причина указана у сервиса; автопилот продолжает попытки.", bad, len(rows))
	case waiting > 0:
		c.Status, c.Detail = "warn", fmt.Sprintf("Подтверждены %d из %d, остальные проверяются.", good, len(rows))
	default:
		c.Detail = fmt.Sprintf("Все %d подтверждены автопилотом.", len(rows))
	}
	return c
}
