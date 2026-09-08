package main

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/nodestore"
)

// The NodeStore follows the selected config by default, so candidate installs
// cannot share private proxy material with the live application accidentally.
func nodeStorePath(configPath, override string) (string, error) {
	path := override
	if path == "" {
		path = filepath.Join(filepath.Dir(configPath), "nodes-private")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return "", nodestore.ErrStore
	}
	return path, nil
}

func openNodeStore(configPath, override string) (*nodestore.Store, error) {
	path, err := nodeStorePath(configPath, override)
	if err != nil {
		return nil, err
	}
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, nodestore.ErrStore
	}
	return nodestore.Open(path)
}
