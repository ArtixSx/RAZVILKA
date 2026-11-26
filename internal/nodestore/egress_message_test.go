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

// Timeout and service-stage explanations travel only in Message. Records with
// the former wording must load exactly as stored, and the new wording must fit
// the same record without raising the history reader requirement.
func TestStoredCheckExplanationsLoadUnchangedAcrossWording(t *testing.T) {
	s, path := setup(t)
	id := importGood(t, s).Nodes[0].ID
	route := "sing-box:" + id
	egress := func(probe, message string) CheckRecord {
		return CheckRecord{ProbeID: probe, ServiceID: "discord", NetworkProfile: "wan-0123456789ab", RoutePathID: route,
			TestLevel: "protocol", Stage: "egress", Verdict: "ERROR", State: "unavailable", ErrorCode: "node-egress-failed", Message: message}
	}
	service := func(probe, stage, code, verdict, message string) CheckRecord {
		return CheckRecord{ProbeID: probe, ServiceID: "discord", NetworkProfile: "wan-0123456789ab", RoutePathID: route, EgressIP: "203.0.113.20",
			TestLevel: "service", Stage: stage, Verdict: verdict, State: "unavailable", HTTPStatus: 204, ErrorCode: code, Message: message}
	}
	refused := func(record CheckRecord) CheckRecord {
		record.HTTPStatus = 403
		return record
	}
	records := []CheckRecord{
		// Former wording, exactly as earlier releases stored it.
		egress("node-check-old-timeout", "Точный выход через узел не подтвердился. Контрольный запрос через узел не уложился в срок."),
		service("node-check-old-service", "service", "request-failed", "ERROR", "Узел передаёт трафик, но выбранный сервис через него не подтверждён."),
		service("node-check-old-ip", "service_ip", "node-service-ip-path-failed", "ERROR", "Узел не подтвердил доступ к сервису по IP-адресу, необходимый для маршрута устройств."),
		// The longest new wording of each kind.
		egress("node-check-new-dial", "Точный выход через узел не подтвердился. Соединение через узел не открылось вовремя. Возможно, узел не ответил."),
		egress("node-check-new-tls", "Точный выход через узел не подтвердился. Защищённое соединение через узел не установилось вовремя. Возможно, узел не ответил."),
		egress("node-check-new-response", "Точный выход через узел не подтвердился. Соединение через узел установлено, но ответ не пришёл вовремя."),
		service("node-check-new-service", "service", "request-failed", "ERROR", "Узел передаёт трафик, но выбранный сервис через него не подтверждён. Сервис не ответил вовремя."),
		refused(service("node-check-new-refusal", "service", "http-403", "BLOCKED", "Узел передаёт трафик, но выбранный сервис через него не подтверждён. Сервис ответил отказом или неожиданным ответом.")),
		service("node-check-new-ip", "service_ip", "node-service-ip-path-failed", "ERROR", "Узел не подтвердил доступ к сервису по IP-адресу, необходимый для маршрута устройств. Соединение с сервисом не установилось или оборвалось."),
	}
	for i := range records {
		records[i].CheckedAt = testTime.Add(time.Duration(i) * time.Second)
		records[i].ExpiresAt = records[i].CheckedAt.Add(time.Hour)
		if _, err := s.RecordCheck(context.Background(), id, records[i], records[i].CheckedAt); err != nil {
			t.Fatalf("%s was refused: %v", records[i].ProbeID, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	now := records[len(records)-1].CheckedAt
	snapshot, err := reopened.Snapshot(context.Background(), now)
	if err != nil || len(snapshot.Nodes) != 1 || len(snapshot.Nodes[0].Health.History) != len(records) {
		t.Fatal("history was not retained", err)
	}
	stored := map[string]CheckRecord{}
	for _, record := range snapshot.Nodes[0].Health.History {
		stored[record.ProbeID] = record
	}
	for _, want := range records {
		got, ok := stored[want.ProbeID]
		if !ok || got.Message != want.Message || got.ErrorCode != want.ErrorCode || got.Stage != want.Stage || got.Verdict != want.Verdict ||
			got.State != want.State || got.HTTPStatus != want.HTTPStatus || got.TestLevel != want.TestLevel || got.RoutePathID != want.RoutePathID {
			t.Fatalf("%s changed on reload: %+v", want.ProbeID, got)
		}
	}
	if reader, err := reopened.RequiredHistoryReadVersion(context.Background()); err != nil || reader != 1 {
		t.Fatal("explanations changed the legacy reader requirement", reader, err)
	}
	if services, err := reopened.RouteServices(context.Background(), id, "wan-0123456789ab", now); err != nil || len(services) != 0 {
		t.Fatal("explanations granted route authority", services, err)
	}
}
