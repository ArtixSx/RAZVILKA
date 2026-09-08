package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/privatebackup"
)

func TestPrivatePolicyExportPreviewAndPausedImport(t *testing.T) {
	source, _ := privateRestoreTestApp(t)
	stagePrivateBackupExportFixture(t, source)
	policy := config.DefaultServicePolicy("youtube", source.Store.Get().AppliedServices["youtube"])
	policy.Enabled, policy.Mode = true, "auto"
	policy.AllowedSourceIDs = []string{"feed-private-policy-reference"}
	policy.TrustClasses = []string{"subscription"}
	if _, err := source.Store.UpdateServicePolicy(policy, source.Store.Get().Revision, 0); err != nil {
		t.Fatal(err)
	}
	before := source.Store.Get()
	exported := requestPrivateBackupExport(source)
	var envelope privatebackup.Envelope
	if exported.Code != 200 || json.Unmarshal(exported.Body.Bytes(), &envelope) != nil {
		t.Fatalf("export HTTP %d", exported.Code)
	}
	payload, err := privatebackup.Decrypt(envelope, "correct horse battery staple")
	if err != nil || !reflect.DeepEqual(payload.ServicePolicies, before.ServicePolicies) || !reflect.DeepEqual(before, source.Store.Get()) {
		t.Fatal("export lost or modified policy settings")
	}
	target, _ := privateRestoreTestApp(t)
	beforeTarget := target.Store.Get()
	requestBody := map[string]any{"envelope": envelope, "password": "correct horse battery staple"}
	call := func(action string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(requestBody)
		w := httptest.NewRecorder()
		target.Handler(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/private-backups/"+action, bytes.NewReader(body)))
		return w
	}
	preview := call("preview")
	if preview.Code != 200 || !strings.Contains(preview.Body.String(), `"service_policies":1`) || !strings.Contains(preview.Body.String(), "на паузе") || strings.Contains(preview.Body.String(), "feed-private-policy-reference") || !reflect.DeepEqual(beforeTarget, target.Store.Get()) {
		t.Fatalf("policy preview was not safe and clear: HTTP %d", preview.Code)
	}
	requestBody["confirm"] = "IMPORT_PRIVATE_BACKUP"
	imported := call("import")
	if imported.Code != 200 {
		t.Fatalf("policy import HTTP %d", imported.Code)
	}
	after := target.Store.Get()
	want := before.ServicePolicies["youtube"]
	want.Enabled, want.Mode, want.Revision, want.LegacyOptIn = false, "paused", 1, false
	if !reflect.DeepEqual(after.ServicePolicies["youtube"], want) || !reflect.DeepEqual(beforeTarget.AppliedServices, after.AppliedServices) || beforeTarget.SafeMode != after.SafeMode {
		t.Fatal("policy import granted live authority or lost restrictions")
	}

	unknown := payload.ServicePolicies["youtube"]
	unknown.ServiceID = "unknown-policy-service"
	payload.ServicePolicies = map[string]config.ServicePolicy{unknown.ServiceID: unknown}
	if err := privatebackup.Seal(&payload); err != nil {
		t.Fatal(err)
	}
	if _, err := target.previewPrivateBackup(payload); err == nil {
		t.Fatal("preview accepted policy for an unknown service")
	}
}
