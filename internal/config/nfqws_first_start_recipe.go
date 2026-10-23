package config

import (
	"errors"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

var ErrNFQWSFirstStartRecipe = errors.New("unknown closed NFQWS2 first-start recipe")

func validateNFQWSFirstStartRecipes(cfg Config) error {
	if !cfg.NFQWSFirstStartRecipe.Valid() || !cfg.AppliedNFQWSFirstStartRecipe.Valid() {
		return ErrNFQWSFirstStartRecipe
	}
	return nil
}

// SetNFQWSFirstStartRecipe stages only desired intent. Live process/configuration
// and the applied recipe change exclusively through the ordinary transaction.
func (s *Store) SetNFQWSFirstStartRecipe(expectedRevision uint64, recipe engineconfig.NFQWSFirstStartRecipe) error {
	if !recipe.Valid() {
		return ErrNFQWSFirstStartRecipe
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.Revision != expectedRevision {
		return ErrRevisionChanged
	}
	if s.cfg.NFQWSFirstStartRecipe == recipe {
		return nil
	}
	before := cloneConfig(s.cfg)
	s.cfg.NFQWSFirstStartRecipe = recipe
	s.cfg.Revision++
	if err := s.saveLocked(); err != nil {
		s.cfg = before
		return err
	}
	return nil
}
