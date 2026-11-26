package nodestore

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSourceUtilityUsesExactServiceNetworkOriginAndDistinctServers(t *testing.T) {
	s, path := setup(t)
	a, b := Source{ID: "feed-a", Kind: "subscription"}, Source{ID: "feed-b", Kind: "subscription"}
	first, err := s.Import(context.Background(), a, good, testTime, time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	id := first.Nodes[0].ID
	// A second source keeps the same node usable after the first origin expires.
	if _, err = s.Import(context.Background(), b, good, testTime, time.Hour, false); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{strings.Replace(good, "174000", "174001", 1), strings.Replace(good, ":443?", ":8443?", 1)} {
		if _, err = s.Import(context.Background(), b, raw, testTime, time.Hour, false); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := s.Snapshot(context.Background(), testTime)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range snapshot.Nodes {
		r := CheckRecord{ProbeID: "utility-pass", ServiceID: "telegram", NetworkProfile: "wan-0123456789ab", RoutePathID: "sing-box:" + n.ID,
			TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: testTime, ExpiresAt: testTime.Add(time.Hour)}
		if _, err = s.RecordCheck(context.Background(), n.ID, r, testTime); err != nil {
			t.Fatal(err)
		}
	}
	before := readBytes(t, path)
	utility := func(service, network string, protocols []string, now time.Time) map[string]int {
		t.Helper()
		v, e := s.SourceUtility(context.Background(), []string{a.ID, b.ID, "absent"}, protocols, service, network, now)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	got := utility("telegram", "wan-0123456789ab", []string{"vless"}, testTime)
	if !reflect.DeepEqual(got, map[string]int{a.ID: 1, b.ID: 1, "absent": 0}) {
		t.Fatal(got)
	}
	got = utility("telegram", "wan-0123456789ab", []string{"vless"}, testTime.Add(2*time.Minute))
	if got[a.ID] != 0 || got[b.ID] != 1 {
		t.Fatal("expired source received another source's proof", got)
	}
	for _, query := range []struct {
		service, network string
		protocols        []string
		now              time.Time
	}{
		{"youtube", "wan-0123456789ab", []string{"vless"}, testTime},
		{"telegram", "wan-abcdef012345", []string{"vless"}, testTime},
		{"telegram", "wan-0123456789ab", []string{"tuic"}, testTime},
		{"telegram", "wan-0123456789ab", []string{"vless"}, testTime.Add(time.Hour)},
		{"telegram", "wan-0123456789ab", []string{"vless"}, testTime.Add(-time.Second)},
	} {
		v := utility(query.service, query.network, query.protocols, query.now)
		if v[a.ID] != 0 || v[b.ID] != 0 {
			t.Fatal("inapplicable proof ranked source", v)
		}
	}
	data, _ := json.Marshal(got)
	if strings.Contains(string(data), id) || strings.Contains(string(data), "private-host") || string(before) != string(readBytes(t, path)) {
		t.Fatal("utility leaked material or wrote store")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = s.SourceUtility(ctx, []string{a.ID}, []string{"vless"}, "telegram", "wan-0123456789ab", testTime); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestSourceUtilityCannotReviveLatestFailureOrDisabledNode(t *testing.T) {
	for _, scenario := range []string{"failure", "inconclusive", "transport-only", "disabled"} {
		t.Run(scenario, func(t *testing.T) {
			s, _ := setup(t)
			snapshot := importGood(t, s)
			id := snapshot.Nodes[0].ID
			r := CheckRecord{ProbeID: "utility-pass", ServiceID: "telegram", NetworkProfile: "wan-0123456789ab", RoutePathID: "sing-box:" + id, TestLevel: "service", Verdict: "PASS", State: "available", Stage: "service", CheckedAt: testTime, ExpiresAt: testTime.Add(time.Hour)}
			if _, err := s.RecordCheck(context.Background(), id, r, testTime); err != nil {
				t.Fatal(err)
			}
			if scenario == "disabled" {
				if _, err := s.SetDisabled(context.Background(), id, true, testTime); err != nil {
					t.Fatal(err)
				}
			} else {
				r.ProbeID = "utility-latest"
				r.CheckedAt = testTime.Add(time.Second)
				switch scenario {
				case "failure":
					r.Verdict = "ERROR"
					r.State = "unavailable"
				case "inconclusive":
					r.Verdict = "INCONCLUSIVE"
					r.State = "unavailable"
				case "transport-only":
					r.TestLevel = "transport"
					r.Stage = "transport"
				}
				if _, err := s.RecordCheck(context.Background(), id, r, r.CheckedAt); err != nil {
					t.Fatal(err)
				}
			}
			got, err := s.SourceUtility(context.Background(), []string{manual.ID}, []string{"vless"}, "telegram", "wan-0123456789ab", testTime.Add(2*time.Second))
			if err != nil || got[manual.ID] != 0 {
				t.Fatal(got, err)
			}
		})
	}
}
