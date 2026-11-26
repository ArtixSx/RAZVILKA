package config

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

func TestReviewedDraftScopeCASRejectsStaleRevisionAndRetainsGuardedUndo(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	oldRevision := s.Get().Revision
	if err := s.UpdateService("telegram", ServiceState{Enabled: true, Route: "direct", Sources: []string{"192.168.1.40/32"}}); err != nil {
		t.Fatal(err)
	}
	before := s.Get()
	undo, err := s.ApplyDraftScopeAtRevisionWithRollback(DraftScopeServices, oldRevision)
	if !errors.Is(err, ErrRevisionChanged) || undo != nil || !reflect.DeepEqual(s.Get(), before) {
		t.Fatal("stale review changed configuration")
	}
	undo, err = s.ApplyDraftScopeAtRevisionWithRollback(DraftScopeServices, before.Revision)
	if err != nil || undo == nil {
		t.Fatalf("current review refused: %v", err)
	}
	current := s.Get()
	if !current.AppliedServices["telegram"].Enabled || len(current.AppliedServices["telegram"].Sources) != 0 || !reflect.DeepEqual(current.Services, before.Services) {
		t.Fatal("reviewed service apply consumed device scope")
	}
	if err := undo(); err != nil || !reflect.DeepEqual(s.Get(), before) {
		t.Fatal("reviewed apply lost exact guarded rollback")
	}
}
