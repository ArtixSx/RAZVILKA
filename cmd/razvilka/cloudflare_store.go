package main

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/cloudflareprovider"
)

// The default follows the selected config, so a separate candidate installation
// cannot accidentally import into the live application's store. Only this leaf
// directory may be created; existing permissions/data are never overwritten.
func openCloudflareStore(configPath, override string) (*cloudflareprovider.Store, error) {
	path := override
	if path == "" {
		path = filepath.Join(filepath.Dir(configPath), "cloudflare-private")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, cloudflareprovider.ErrStore
	}
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, cloudflareprovider.ErrStore
	}
	return cloudflareprovider.OpenStore(path)
}
