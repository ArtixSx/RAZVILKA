package nodestore

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

// searchServiceRecord is a definite refusal after proven exact egress: the
// service answered HTTP 404 through the node's measured exit.
func searchServiceRecord(id, engine, probe string, at time.Time) CheckRecord {
	return CheckRecord{ProbeID: probe, ServiceID: "telegram", NetworkProfile: "wan-0123456789ab", RoutePathID: engine + ":" + id,
		TestLevel: "service", Stage: "service", Verdict: "PARTIAL", State: "unavailable", EgressIP: "203.0.113.20", HTTPStatus: 404, ErrorCode: "http-404",
		Message: "Узел передаёт трафик, но выбранный сервис через него не подтверждён. Сервис ответил отказом или неожиданным ответом.", CheckedAt: at, ExpiresAt: at.Add(30 * time.Minute)}
}

func TestSearchDefiniteServiceRefusalAdvancesToPeerInOneRound(t *testing.T) {
	refusals := map[string]func(*CheckRecord){
		"http-404":        func(*CheckRecord) {},
		"http-401":        func(r *CheckRecord) { r.HTTPStatus, r.ErrorCode = 401, "http-401" },
		"http-407":        func(r *CheckRecord) { r.HTTPStatus, r.ErrorCode = 407, "http-407" },
		"body-mismatch":   func(r *CheckRecord) { r.Verdict, r.HTTPStatus, r.ErrorCode = "ERROR", 200, "body-predicate-mismatch" },
		"content-type":    func(r *CheckRecord) { r.Verdict, r.HTTPStatus, r.ErrorCode = "ERROR", 200, "content-type-mismatch" },
		"invalid-json":    func(r *CheckRecord) { r.Verdict, r.HTTPStatus, r.ErrorCode = "ERROR", 204, "invalid-json" },
		"json-schema":     func(r *CheckRecord) { r.Verdict, r.HTTPStatus, r.ErrorCode = "ERROR", 200, "json-schema-mismatch" },
		"blocked-http403": func(r *CheckRecord) { r.Verdict, r.HTTPStatus, r.ErrorCode = "BLOCKED", 403, "http-403" },
	}
	for _, engine := range []string{"sing-box", "xray"} {
		for name, refusal := range refusals {
			t.Run(engine+"/"+name, func(t *testing.T) {
				s, ids, req, hooks := searchFixture(t, 3, engine)
				check := hooks.Check
				var events []string
				hooks.Check = func(ctx context.Context, id string) (SearchCheck, error) {
					if id == ids[0] {
						events = append(events, "check-A")
						at := hooks.Now()
						record := searchServiceRecord(id, engine, "refusal-A", at)
						refusal(&record)
						if _, err := s.RecordCheck(ctx, id, record, at); err != nil {
							t.Fatal(err)
						}
						return SearchCheck{Outcome: SearchDefiniteFailure, ProbeID: record.ProbeID, CheckedAt: record.CheckedAt}, nil
					}
					if id != ids[1] || !slices.Equal(events, []string{"check-A", "persist-A"}) {
						t.Fatal("B checked before A's refusal was consumed, or another peer checked", events)
					}
					events = append(events, "check-B")
					return check(ctx, id)
				}
				hooks.PersistCursor = func(_ context.Context, next int) error {
					events = append(events, map[int]string{1: "persist-A", 2: "persist-B"}[next])
					return nil
				}
				hooks.Apply = func(_ context.Context, route ResolvedRoute) error {
					if route.NodeID != ids[1] || route.Route != engine+":"+ids[1] {
						t.Fatal("refused candidate reached Apply", route)
					}
					events = append(events, "apply-B")
					return nil
				}
				result, err := s.SearchFirstUsable(context.Background(), req, hooks)
				if err != nil || result.Checks != 2 || result.Examined != 2 || result.Cursor != 2 || result.ApplyAttempts != 1 || result.Applied.NodeID != ids[1] || len(result.Rejected) != 0 ||
					!slices.Equal(events, []string{"check-A", "persist-A", "check-B", "persist-B", "apply-B"}) {
					t.Fatal("definite service refusal did not advance to one fresh peer", result, events, err)
				}
			})
		}
	}
}

// Only a definite answer of the service itself consumes. Timeouts, broken or
// retry-later answers, the literal-IP stage and every egress/local class keep
// the cursor where it is, even when the hook claims a definite failure.
func TestSearchServiceOutcomesWithoutDefiniteRefusalKeepCursor(t *testing.T) {
	scenarios := map[string]func(*CheckRecord){
		"service-timeout": func(r *CheckRecord) {
			r.Verdict, r.HTTPStatus, r.ErrorCode = "ERROR", 0, "request-failed"
			r.Message = "Узел передаёт трафик, но выбранный сервис через него не подтверждён. Сервис не ответил вовремя."
		},
		"service-transport":     func(r *CheckRecord) { r.Verdict, r.HTTPStatus, r.ErrorCode = "ERROR", 0, "request-failed" },
		"response-body-invalid": func(r *CheckRecord) { r.Verdict, r.HTTPStatus, r.ErrorCode = "ERROR", 0, "response-body-invalid" },
		"retry-later-408":       func(r *CheckRecord) { r.HTTPStatus, r.ErrorCode = 408, "http-408" },
		"too-early-425":         func(r *CheckRecord) { r.HTTPStatus, r.ErrorCode = 425, "http-425" },
		"rate-limit-429":        func(r *CheckRecord) { r.HTTPStatus, r.ErrorCode = 429, "http-429" },
		"server-error-503":      func(r *CheckRecord) { r.Verdict, r.HTTPStatus, r.ErrorCode = "ERROR", 503, "http-503" },
		"gateway-timeout-504":   func(r *CheckRecord) { r.Verdict, r.HTTPStatus, r.ErrorCode = "ERROR", 504, "http-504" },
		"unexpected-status": func(r *CheckRecord) {
			r.Verdict, r.HTTPStatus, r.ErrorCode = "INCONCLUSIVE", 200, "unexpected-http-status"
		},
		"redirect": func(r *CheckRecord) {
			r.Verdict, r.HTTPStatus, r.ErrorCode = "INCONCLUSIVE", 302, "redirect-not-resolved"
		},
		"json-sample": func(r *CheckRecord) {
			r.Verdict, r.HTTPStatus, r.ErrorCode = "INCONCLUSIVE", 200, "json-sample-incomplete"
		},
		"not-confirmed": func(r *CheckRecord) {
			r.Verdict, r.HTTPStatus, r.ErrorCode = "ERROR", 200, "node-service-not-confirmed"
		},
		"misrouted": func(r *CheckRecord) { r.Verdict, r.HTTPStatus, r.ErrorCode = "MISROUTED", 200, "node-route-mismatch" },
		"service-ip-refusal": func(r *CheckRecord) {
			r.Stage, r.Verdict, r.HTTPStatus, r.ErrorCode = "service_ip", "ERROR", 204, "node-service-ip-path-failed"
			r.Message = "Узел не подтвердил доступ к сервису по IP-адресу, необходимый для маршрута устройств. Сервис ответил отказом или неожиданным ответом."
		},
		"service-ip-timeout": func(r *CheckRecord) {
			r.Stage, r.Verdict, r.HTTPStatus, r.ErrorCode = "service_ip", "ERROR", 204, "node-service-ip-path-failed"
			r.Message = "Узел не подтвердил доступ к сервису по IP-адресу, необходимый для маршрута устройств. Сервис не ответил вовремя."
		},
		"probe-failed": func(r *CheckRecord) {
			r.TestLevel, r.Verdict, r.HTTPStatus, r.ErrorCode = "egress", "ERROR", 0, "node-service-probe-failed"
		},
		"no-egress":            func(r *CheckRecord) { r.EgressIP = "" },
		"direct-leak":          func(r *CheckRecord) { r.DirectLeak = true },
		"available":            func(r *CheckRecord) { r.State = "available" },
		"status-code-mismatch": func(r *CheckRecord) { r.ErrorCode = "http-403" },
		"error-verdict-4xx":    func(r *CheckRecord) { r.Verdict = "ERROR" },
		"content-mismatch-5xx": func(r *CheckRecord) { r.Verdict, r.HTTPStatus, r.ErrorCode = "ERROR", 500, "body-predicate-mismatch" },
		"egress-control-unavailable": func(r *CheckRecord) {
			r.TestLevel, r.Stage, r.Verdict, r.EgressIP, r.HTTPStatus, r.ErrorCode = "egress", "egress", "INCONCLUSIVE", "", 0, "node-egress-control-unavailable"
		},
		"direct-control-unavailable": func(r *CheckRecord) {
			r.TestLevel, r.Stage, r.Verdict, r.EgressIP, r.HTTPStatus, r.ErrorCode = "egress", "egress", "INCONCLUSIVE", "", 0, "node-direct-control-unavailable"
		},
		"egress-leak": func(r *CheckRecord) {
			r.TestLevel, r.Stage, r.Verdict, r.EgressIP, r.HTTPStatus, r.ErrorCode, r.DirectLeak = "egress", "egress", "MISROUTED", "", 0, "node-direct-leak", true
		},
		"config-rejected": func(r *CheckRecord) {
			r.TestLevel, r.Stage, r.Verdict, r.EgressIP, r.HTTPStatus, r.ErrorCode = "protocol", "configuration", "ERROR", "", 0, "node-runtime-config-rejected"
		},
	}
	for name, mutate := range scenarios {
		t.Run(name, func(t *testing.T) {
			s, ids, req, hooks := searchFixture(t, 2, "sing-box")
			checks, persists, applies := 0, 0, 0
			hooks.Check = func(ctx context.Context, id string) (SearchCheck, error) {
				checks++
				if checks != 1 || id != ids[0] {
					t.Fatal("peer checked after a non-definite service outcome")
				}
				at := hooks.Now()
				record := searchServiceRecord(id, "sing-box", "outcome-A", at)
				mutate(&record)
				if _, err := s.RecordCheck(ctx, id, record, at); err != nil {
					t.Fatal("fixture record not persisted", err)
				}
				return SearchCheck{Outcome: SearchDefiniteFailure, ProbeID: record.ProbeID, CheckedAt: record.CheckedAt}, nil
			}
			hooks.PersistCursor = func(context.Context, int) error { persists++; return nil }
			hooks.Apply = func(context.Context, ResolvedRoute) error { applies++; return nil }
			result, err := s.SearchFirstUsable(context.Background(), req, hooks)
			if !errors.Is(err, ErrSearchInconclusive) || checks != 1 || persists != 0 || applies != 0 || result.Cursor != 0 || result.Examined != 0 || result.Applied.NodeID != "" {
				t.Fatal("non-definite service outcome consumed the candidate", result, err)
			}
		})
	}
}

// verifySearchRecord accepts the new class only for the exact, fresh record
// the hook names, on the same route, service and network.
func TestSearchServiceRefusalRequiresMatchingStoredRecord(t *testing.T) {
	for _, scenario := range []string{"probe", "check-time", "old", "expired", "engine", "service", "network", "newer-timeout", "closing-guard"} {
		t.Run(scenario, func(t *testing.T) {
			s, ids, req, hooks := searchFixture(t, 2, "sing-box")
			checks, persists, applies := 0, 0, 0
			allowed := true
			hooks.Guard = func(context.Context) error {
				if !allowed {
					return errors.New("closing guard refused")
				}
				return nil
			}
			hooks.Check = func(ctx context.Context, id string) (SearchCheck, error) {
				checks++
				if checks != 1 || id != ids[0] {
					t.Fatal("peer checked after an unconfirmed refusal record")
				}
				at := hooks.Now()
				record := searchServiceRecord(id, "sing-box", "refusal-A", at)
				switch scenario {
				case "old":
					record.CheckedAt = at.Add(-time.Second)
				case "expired":
					record.ExpiresAt = at.Add(time.Millisecond)
				case "engine":
					record.RoutePathID = "xray:" + id
				case "service":
					record.ServiceID = "youtube"
				case "network":
					record.NetworkProfile = "wan-ffffffffffff"
				case "closing-guard":
					allowed = false
				}
				if _, err := s.RecordCheck(ctx, id, record, at); err != nil {
					t.Fatal(err)
				}
				check := SearchCheck{Outcome: SearchDefiniteFailure, ProbeID: record.ProbeID, CheckedAt: record.CheckedAt}
				switch scenario {
				case "probe":
					check.ProbeID = "foreign-probe"
				case "check-time":
					check.CheckedAt = at.Add(time.Millisecond)
				case "newer-timeout":
					// A later timeout on the same route supersedes the refusal.
					later := hooks.Now()
					timeout := searchServiceRecord(id, "sing-box", "timeout-A", later)
					timeout.Verdict, timeout.HTTPStatus, timeout.ErrorCode = "ERROR", 0, "request-failed"
					if _, err := s.RecordCheck(ctx, id, timeout, later); err != nil {
						t.Fatal(err)
					}
				}
				return check, nil
			}
			hooks.PersistCursor = func(context.Context, int) error { persists++; return nil }
			hooks.Apply = func(context.Context, ResolvedRoute) error { applies++; return nil }
			result, err := s.SearchFirstUsable(context.Background(), req, hooks)
			if err == nil || checks != 1 || persists != 0 || applies != 0 || result.Cursor != 0 || result.Examined != 0 || result.Applied.NodeID != "" {
				t.Fatal("refusal without its exact stored record consumed the candidate", result, err)
			}
		})
	}
}
