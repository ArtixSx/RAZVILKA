package app

import (
	"errors"
	"io"
	"os"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// CheckAutonomyState is used before a version rollback. It must not open a
// config store, reset observations, migrate consent or create directories.
func CheckAutonomyState(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > maxAutonomyBytes {
		return restorejournal.ErrInvalid
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return restorejournal.ErrInvalid
	}
	data, err := io.ReadAll(io.LimitReader(file, maxAutonomyBytes+1))
	if err != nil {
		return err
	}
	_, err = decodeAutonomy(data)
	return err
}
