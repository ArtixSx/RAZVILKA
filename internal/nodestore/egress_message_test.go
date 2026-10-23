package nodestore

import (
	"context"
	"testing"
	"time"
)

func TestNodeEgressExplanationSurvivesReopenWithLegacyReaderRequirement(t *testing.T) {
	s, path := setup(t)
	id := importGood(t, s).Nodes[0].ID
	const message = "Точный выход через узел не подтвердился. TLS-сертификат контрольного адреса не прошёл проверку."
	record := CheckRecord{ProbeID: "node-egress-diagnostic", ServiceID: "discord", NetworkProfile: "wan-0123456789ab", RoutePathID: "sing-box:" + id,
		TestLevel: "protocol", Stage: "egress", Verdict: "ERROR", State: "unavailable", CheckedAt: testTime, ExpiresAt: testTime.Add(time.Hour), ErrorCode: "node-egress-failed", Message: message}
	if _, err := s.RecordCheck(context.Background(), id, record, testTime); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	snapshot, err := reopened.Snapshot(context.Background(), testTime)
	if err != nil || len(snapshot.Nodes[0].Health.History) != 1 || snapshot.Nodes[0].Health.Message != message || snapshot.Nodes[0].Health.History[0].Message != message {
		t.Fatal("explanation was lost after reopen", err)
	}
	if reader, err := reopened.RequiredHistoryReadVersion(context.Background()); err != nil || reader != 1 {
		t.Fatal("explanation changed legacy reader requirement", reader, err)
	}
	services, err := reopened.RouteServices(context.Background(), id, record.NetworkProfile, testTime)
	if err != nil || len(services) != 0 {
		t.Fatal("diagnostic granted route authority", services, err)
	}
}
