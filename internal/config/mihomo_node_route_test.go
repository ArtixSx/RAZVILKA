package config

import (
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestMihomoManualNodeCommitPersistsExactScopeWithoutLegacyEligibility(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	store, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	if err = store.UpdateService("other", ServiceState{Enabled: true, Route: "direct", Sources: []string{"192.168.1.77/32"}}); err != nil {
		t.Fatal(err)
	}
	before := store.Get()
	node := "node-" + strings.Repeat("a", 64)
	if _, err = store.ApplyNodeRouteScopeWithRollback("listed", "mihomo:"+node, []string{"192.168.1.42/32"}, before.Revision); err == nil {
		t.Fatal("manual path leaked into legacy node writer")
	}
	image, undo, err := store.ApplyMihomoNodeRouteScopeWithImage("listed", node, []string{"192.168.1.42"}, before.Revision)
	if err != nil || image.Revision != before.Revision+1 || image.Services["listed"].Route != "mihomo:"+node || !reflect.DeepEqual(image.Services["listed"].Sources, []string{"192.168.1.42/32"}) || !reflect.DeepEqual(image.Services["other"], before.Services["other"]) || !reflect.DeepEqual(image.AppliedServices["other"], before.AppliedServices["other"]) {
		t.Fatal("manual service-only CAS", err)
	}
	reloaded, err := LoadExisting(path)
	if err != nil || !reflect.DeepEqual(reloaded.Get(), image) {
		t.Fatal("persisted manual intent unreadable", err)
	}
	image.Services["listed"] = ServiceState{Route: "foreign"}
	if err = undo(); err != nil || !reflect.DeepEqual(store.Get(), before) {
		t.Fatal("returned image aliases original rollback", err)
	}
	for _, sources := range [][]string{nil, {"0.0.0.0/0"}, {"1.1.1.1/32"}, {"192.0.0.0/8"}, {"fc00::/64"}} {
		if _, _, err = store.ApplyMihomoNodeRouteScopeWithImage("listed", node, sources, before.Revision); err == nil {
			t.Fatal("unsupported scope persisted", sources)
		}
	}
	if _, _, err = store.ApplyMihomoNodeRouteScopeWithImage("listed", node, []string{"192.168.1.42/32"}, before.Revision+1); !errors.Is(err, ErrRevisionChanged) {
		t.Fatal("stale manual CAS", err)
	}
}
