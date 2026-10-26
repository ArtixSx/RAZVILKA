package app

import (
	"errors"
	"time"
)

// A service that refuses through this many nodes in a row more likely refuses
// the path or is down itself. The search then pauses instead of consuming the
// rest of the list.
const autonomyServiceRefusalLimit = 3

const autonomyServiceUnconfirmedMessage = "Сервис отказал через три узла подряд. Возможно, причина на стороне сервиса. Подбор продолжится позже."

var errAutonomyServiceRefusals = errors.New("autonomy search paused after consecutive service refusals")

// autonomyServiceRefusals counts consecutive consumed service refusals in one
// traversal of one service and holds the pause the guard started. It lives in
// memory only: a restart may consume up to the limit again, but never grants
// Apply, a candidate failure or a penalty.
type autonomyServiceRefusals struct {
	version string
	count   int
	until   time.Time
}

// observe counts one consumed check. Any other observed outcome, a PASS or a
// node failure, ends the run; skipped candidates are not observations.
func (g autonomyServiceRefusals) observe(refusal bool) autonomyServiceRefusals {
	if refusal {
		g.count++
	} else {
		g.count = 0
	}
	return g
}

func (a *App) autonomyServiceRefusals(id, version string) autonomyServiceRefusals {
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	if g, ok := a.autonomy.serviceRefusals[id]; ok && g.version == version {
		return g
	}
	return autonomyServiceRefusals{version: version}
}

func (a *App) setAutonomyServiceRefusals(id string, g autonomyServiceRefusals) {
	a.autonomy.mu.Lock()
	defer a.autonomy.mu.Unlock()
	if a.autonomy.serviceRefusals == nil {
		a.autonomy.serviceRefusals = map[string]autonomyServiceRefusals{}
	}
	a.autonomy.serviceRefusals[id] = g
}
