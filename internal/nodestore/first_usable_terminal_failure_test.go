package nodestore

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

func searchTerminalRecord(id, engine, kind, probe string, at time.Time) CheckRecord {
	r := CheckRecord{ProbeID: probe, ServiceID: "telegram", NetworkProfile: "wan-0123456789ab", RoutePathID: engine + ":" + id,
		Verdict: "ERROR", State: "unavailable", TestLevel: "protocol", Stage: "egress", ErrorCode: "node-egress-failed", CheckedAt: at, ExpiresAt: at.Add(30 * time.Minute)}
	if kind == "transport" {
		r.TestLevel, r.Stage, r.ErrorCode = "transport", "transport", "node-transport-failed"
	}
	return r
}

func TestSearchTerminalNodeFailureRequiresFreshPersistedRecordBeforePeer(t *testing.T) {
	for _, test := range []struct{ engine, kind string }{{"sing-box", "egress"}, {"xray", "egress"}, {"sing-box", "transport"}, {"xray", "transport"}} {
		t.Run(test.engine+"/"+test.kind, func(t *testing.T) {
			engine := test.engine
			s, ids, req, hooks := searchFixture(t, 3, engine)
			cached := enginePass(ids[1], engine, "old-C", testTime.Add(time.Second))
			if _, err := s.RecordCheck(context.Background(), ids[1], cached, cached.CheckedAt); err != nil {
				t.Fatal(err)
			}
			check := hooks.Check
			var events []string
			hooks.Check = func(ctx context.Context, id string) (SearchCheck, error) {
				if id == ids[0] {
					events = append(events, "check-B")
					at := hooks.Now()
					record := searchTerminalRecord(id, engine, test.kind, "terminal-B", at)
					if _, err := s.RecordCheck(ctx, id, record, at); err != nil {
						t.Fatal(err)
					}
					return SearchCheck{Outcome: SearchDefiniteFailure, ProbeID: record.ProbeID, CheckedAt: record.CheckedAt}, nil
				}
				if id != ids[1] || !slices.Equal(events, []string{"check-B", "persist-B"}) {
					t.Fatal("C checked before actual B record consumption or another peer checked")
				}
				events = append(events, "check-C")
				return check(ctx, id)
			}
			hooks.PersistCursor = func(_ context.Context, next int) error {
				if next == 1 {
					events = append(events, "persist-B")
				} else if next == 2 {
					events = append(events, "persist-C")
				} else {
					t.Fatal("unexpected cursor")
				}
				return nil
			}
			hooks.Apply = func(_ context.Context, route ResolvedRoute) error {
				if route.NodeID != ids[1] || !slices.Equal(events, []string{"check-B", "persist-B", "check-C", "persist-C"}) {
					t.Fatal("negative record/cached C proof reached Apply")
				}
				events = append(events, "apply-C")
				return nil
			}
			result, err := s.SearchFirstUsable(context.Background(), req, hooks)
			if err != nil || result.Checks != 2 || result.Examined != 2 || result.ApplyAttempts != 1 || result.Applied.NodeID != ids[1] || len(result.Rejected) != 0 || !slices.Equal(events, []string{"check-B", "persist-B", "check-C", "persist-C", "apply-C"}) {
				t.Fatal("exact persisted negative did not advance to one fresh peer", result, err)
			}
		})
	}
}

func TestSearchTerminalFailureKeepsExactRecordAndClosingGuards(t *testing.T) {
	for _, kind := range []string{"egress", "transport"} {
		for _, scenario := range []string{"probe", "check-time", "old", "future", "expired", "node", "engine", "service", "network", "available", "verdict", "level", "stage", "code", "direct-leak", "global-control", "http-response", "egress-present", "closing-guard"} {
			t.Run(kind+"/"+scenario, func(t *testing.T) {
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
						t.Fatal("peer checked after unconfirmed exact record")
					}
					at := hooks.Now()
					record := searchTerminalRecord(id, "sing-box", kind, "terminal-B", at)
					switch scenario {
					case "old":
						record.CheckedAt = at.Add(-time.Second)
					case "future":
						record.CheckedAt = at.Add(time.Second)
					case "expired":
						record.ExpiresAt = at.Add(time.Millisecond)
					case "node":
						id, record.RoutePathID = ids[1], "sing-box:"+ids[1]
					case "engine":
						record.RoutePathID = "xray:" + id
					case "service":
						record.ServiceID = "youtube"
					case "network":
						record.NetworkProfile = "wan-ffffffffffff"
					case "available":
						record.State = "available"
					case "verdict":
						record.Verdict = "INCONCLUSIVE"
					case "level":
						record.TestLevel = "service"
					case "stage":
						record.Stage = "service"
					case "code":
						record.ErrorCode = "node-protocol-start-failed"
					case "direct-leak":
						record.DirectLeak = true
					case "global-control":
						record.Verdict, record.TestLevel, record.ErrorCode = "INCONCLUSIVE", "egress", "node-egress-control-unavailable"
					case "http-response":
						record.HTTPStatus = 200
					case "egress-present":
						record.EgressIP = "93.184.216.34"
					case "closing-guard":
						allowed = false
					}
					writeAt := at
					if record.CheckedAt.After(writeAt) {
						writeAt = record.CheckedAt
					}
					if _, err := s.RecordCheck(ctx, id, record, writeAt); err != nil {
						t.Fatal("fixture negative record not persisted", err)
					}
					check := SearchCheck{Outcome: SearchDefiniteFailure, ProbeID: record.ProbeID, CheckedAt: record.CheckedAt}
					if scenario == "probe" {
						check.ProbeID = "foreign-probe"
					} else if scenario == "check-time" {
						check.CheckedAt = at.Add(time.Millisecond)
					}
					return check, nil
				}
				hooks.PersistCursor = func(context.Context, int) error { persists++; return nil }
				hooks.Apply = func(context.Context, ResolvedRoute) error { applies++; return nil }
				result, err := s.SearchFirstUsable(context.Background(), req, hooks)
				if err == nil || checks != 1 || persists != 0 || applies != 0 || result.Cursor != 0 || result.Examined != 0 || result.Applied.NodeID != "" || len(result.Rejected) != 0 {
					t.Fatal("invalid/uncertain negative bypassed actual record guards", result, err)
				}
			})
		}
	}
}
