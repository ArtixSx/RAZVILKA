package nodestore

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestExactCheckTerminalFailureStagesPersistAndRevokeProof(t *testing.T) {
	for _, stage := range []string{"service_ip", "deadline", "canceled"} {
		t.Run(stage, func(t *testing.T) {
			store, path := setup(t)
			initial := importGood(t, store)
			id := initial.Nodes[0].ID
			pass := CheckRecord{ProbeID: "node-check-pass", ServiceID: "discord", NetworkProfile: "wan-0123456789ab", RoutePathID: "sing-box:" + id,
				TestLevel: "service", Stage: "service", Verdict: "PASS", State: "available", CheckedAt: testTime, ExpiresAt: testTime.Add(time.Hour)}
			if _, err := store.RecordCheck(context.Background(), id, pass, testTime); err != nil {
				t.Fatal(err)
			}
			failure := pass
			failure.ProbeID, failure.Stage = "node-check-failure", stage
			failure.Verdict, failure.State, failure.ErrorCode = "INCONCLUSIVE", "unavailable", "node-check-unconfirmed"
			failure.CheckedAt = testTime.Add(time.Second)
			failure.Message = strings.Repeat("Проверка ", 20) + "не завершена."
			if len(failure.Message) <= 240 {
				t.Fatal("fixture must exceed the former byte limit")
			}
			after, err := store.RecordCheck(context.Background(), id, failure, failure.CheckedAt)
			if err != nil || after.Nodes[0].Health.State != "unavailable" || after.Nodes[0].Health.History[0].Stage != stage || after.Nodes[0].Health.Message != failure.Message {
				t.Fatalf("failure report was rejected or lost: %+v err=%v", after, err)
			}
			services, err := store.RouteServices(context.Background(), id, pass.NetworkProfile, failure.CheckedAt)
			if err != nil || len(services) != 0 {
				t.Fatalf("failure retained old route authority: %v %v", services, err)
			}
			_, err = store.MaterializeSingBox(context.Background(), []RouteBinding{{ServiceID: "discord", NodeID: id, NetworkProfile: pass.NetworkProfile, Domains: []string{"discord.com"}}}, failure.CheckedAt)
			if !errors.Is(err, ErrRouteProof) {
				t.Fatalf("failed node remained materializable: %v", err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			after, err = reopened.Snapshot(context.Background(), failure.CheckedAt)
			if err != nil || len(after.Nodes[0].Health.History) != 2 || after.Nodes[0].Health.History[0].Stage != stage {
				t.Fatalf("failure did not survive reopen: %+v err=%v", after, err)
			}
		})
	}
}

func TestExactCheckMessagesHaveBoundedUTF8Characters(t *testing.T) {
	cases := []struct {
		name    string
		message string
		valid   bool
	}{
		{"ascii-limit", strings.Repeat("a", 240), true},
		{"russian-limit", strings.Repeat("я", 240), true},
		{"unicode-limit", strings.Repeat("🌍", 240), true},
		{"too-many-characters", strings.Repeat("я", 241), false},
		{"invalid-utf8", string([]byte{0xff}), false},
		{"control", "Ошибка\nпроверки", false},
		{"surrounding-space", " Ошибка", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store, path := setup(t)
			initial := importGood(t, store)
			id := initial.Nodes[0].ID
			record := CheckRecord{ProbeID: "node-check-message", ServiceID: "discord", NetworkProfile: "wan-0123456789ab", RoutePathID: "sing-box:" + id,
				TestLevel: "service", Stage: "service_ip", Verdict: "ERROR", State: "unavailable", CheckedAt: testTime, ExpiresAt: testTime.Add(time.Hour), Message: tc.message}
			before := readBytes(t, path)
			after, err := store.RecordCheck(context.Background(), id, record, testTime)
			if tc.valid {
				if err != nil || after.Nodes[0].Health.Message != tc.message {
					t.Fatalf("valid localized message rejected: %v", err)
				}
			} else if !errors.Is(err, ErrStore) || !bytes.Equal(before, readBytes(t, path)) {
				t.Fatalf("invalid message changed store: %v", err)
			}
		})
	}
}

func TestExactCheckFailureStagesCannotBecomePASS(t *testing.T) {
	store, path := setup(t)
	initial := importGood(t, store)
	id := initial.Nodes[0].ID
	for _, stage := range []string{"service_ip", "deadline", "canceled"} {
		for _, successField := range []string{"state", "verdict"} {
			record := CheckRecord{ProbeID: "node-check-invalid", ServiceID: "discord", NetworkProfile: "wan-0123456789ab", RoutePathID: "sing-box:" + id,
				TestLevel: "service", Stage: stage, Verdict: "ERROR", State: "unavailable", CheckedAt: testTime, ExpiresAt: testTime.Add(time.Hour)}
			if successField == "state" {
				record.State = "available"
			} else {
				record.Verdict = "PASS"
			}
			before := readBytes(t, path)
			if _, err := store.RecordCheck(context.Background(), id, record, testTime); !errors.Is(err, ErrStore) || !bytes.Equal(before, readBytes(t, path)) {
				t.Fatalf("failure stage %s accepted success %s: %v", stage, successField, err)
			}
		}
	}
}
