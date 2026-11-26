package config

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

func TestNFQWSFirstStartRecipeDraftPersistsAndScopesApplyDiscardRollback(t *testing.T) {
	for _, recipe := range []engineconfig.NFQWSFirstStartRecipe{engineconfig.NFQWSFirstStartStockTLSCircular, engineconfig.NFQWSFirstStartStockTLSCircularAuto} {
		t.Run(string(recipe), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			s, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			before := s.Get()
			if err := s.SetNFQWSFirstStartRecipe(before.Revision, recipe); err != nil {
				t.Fatal(err)
			}
			staged := s.Get()
			if staged.AppliedNFQWSFirstStartRecipe != "" || !s.DirtyScope(DraftScopeAll) || !s.DirtyScope(DraftScopeServices) || s.DirtyScope(DraftScopeDevices) {
				t.Fatal("draft applied or wrong scope")
			}
			loaded, err := Load(path)
			if err != nil || loaded.Get().NFQWSFirstStartRecipe != staged.NFQWSFirstStartRecipe || loaded.Get().AppliedNFQWSFirstStartRecipe != "" {
				t.Fatal("draft lost on restart", err)
			}
			if err := s.SetNFQWSFirstStartRecipe(before.Revision, ""); !errors.Is(err, ErrRevisionChanged) {
				t.Fatal("stale revision accepted", err)
			}
			if _, err := s.ApplyDraftScopeWithRollback(DraftScopeDevices); err != nil {
				t.Fatal(err)
			}
			if s.Get().AppliedNFQWSFirstStartRecipe != "" {
				t.Fatal("device Apply consumed recipe")
			}
			undo, err := s.ApplyDraftScopeWithRollback(DraftScopeServices)
			if err != nil || s.Get().AppliedNFQWSFirstStartRecipe != staged.NFQWSFirstStartRecipe || s.Dirty() {
				t.Fatal("service Apply did not commit recipe", err)
			}
			if err := undo(); err != nil {
				t.Fatal(err)
			}
			if s.Get().AppliedNFQWSFirstStartRecipe != "" || !s.DirtyScope(DraftScopeServices) {
				t.Fatal("config rollback lost recipe baseline")
			}
			if err := s.DiscardDraftScope(DraftScopeDevices); err != nil {
				t.Fatal(err)
			}
			if s.Get().NFQWSFirstStartRecipe == "" {
				t.Fatal("device discard consumed recipe")
			}
			if err := s.DiscardDraftScope(DraftScopeServices); err != nil {
				t.Fatal(err)
			}
			if s.Get().NFQWSFirstStartRecipe != "" || s.Dirty() {
				t.Fatal("recipe discard failed")
			}
		})
	}
}

func TestNFQWSFirstStartRecipeRejectsUnknownAndLegacyLoadKeepsDefault(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetNFQWSFirstStartRecipe(s.Get().Revision, "arbitrary-argv"); !errors.Is(err, ErrNFQWSFirstStartRecipe) {
		t.Fatal(err)
	}
	for _, field := range []string{"nfqws_first_start_recipe", "applied_nfqws_first_start_recipe"} {
		var cfg map[string]any
		data, _ := json.Marshal(Default())
		_ = json.Unmarshal(data, &cfg)
		cfg[field] = "unknown"
		data, _ = json.Marshal(cfg)
		if _, _, err := InspectBytes(data); !errors.Is(err, ErrNFQWSFirstStartRecipe) {
			t.Fatal("loaded unknown recipe", field, err)
		}
	}
	data, _ := json.Marshal(Default())
	cfg, _, err := InspectBytes(data)
	if err != nil || cfg.NFQWSFirstStartRecipe != "" || cfg.AppliedNFQWSFirstStartRecipe != "" {
		t.Fatal("legacy default changed", err)
	}
}
