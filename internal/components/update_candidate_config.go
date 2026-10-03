package components

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func (tx *updateTransaction) captureCandidateConfig(spec Spec) error {
	images, err := tx.manager.snapshotConffiles(spec)
	if err != nil {
		return err
	}
	root, err := ownedfs.Open(filepath.Join(tx.manager.updateJournalDir(), tx.doc.TransactionID))
	if err != nil {
		return err
	}
	defer root.Close()
	tx.doc.CandidateConfigs = nil
	for i, image := range images {
		conf := journalConfig{Path: image.path, Exists: image.exists, Mode: uint32(image.mode)}
		if image.exists {
			conf.Blob = fmt.Sprintf("candidate-config-%02d", i)
			conf.SHA256 = digest(image.data)
			if err := root.WriteAtomic(conf.Blob, image.data, 0600); err != nil {
				return err
			}
		}
		tx.doc.CandidateConfigs = append(tx.doc.CandidateConfigs, conf)
	}
	if err := syncUpdateDirectory(root); err != nil {
		return err
	}
	tx.doc.CandidateSnapshot = true
	return nil
}

func (tx *updateTransaction) verifyCandidate(ctx context.Context) error {
	if !tx.doc.CandidateSnapshot {
		return ErrUpdatePending
	}
	if err := tx.verifyVersion(ctx, tx.doc.AfterVersion); err != nil {
		return err
	}
	spec, _ := lookup(tx.doc.Component)
	current, err := tx.manager.snapshotConffiles(spec)
	if err != nil || len(current) != len(tx.doc.CandidateConfigs) {
		return errors.New("candidate conffile declarations changed")
	}
	for i, image := range current {
		conf := tx.doc.CandidateConfigs[i]
		if image.path != conf.Path || image.exists != conf.Exists || (image.exists && (digest(image.data) != conf.SHA256 || !updateModeMatches(image.mode, os.FileMode(conf.Mode)))) {
			return errors.New("candidate configuration changed")
		}
	}
	snapshot, err := ownedfs.Open(filepath.Join(tx.manager.updateJournalDir(), tx.doc.TransactionID))
	if err != nil {
		return err
	}
	defer snapshot.Close()
	total := 0
	for _, conf := range tx.doc.CandidateConfigs {
		if err := ctx.Err(); err != nil {
			return err
		}
		root, err := ownedfs.Open(filepath.Dir(conf.Path))
		if err != nil {
			return err
		}
		info, statErr := root.Stat(filepath.Base(conf.Path))
		if !conf.Exists {
			root.Close()
			if !errors.Is(statErr, os.ErrNotExist) {
				return errors.New("previously absent candidate config exists")
			}
			continue
		}
		if statErr != nil {
			root.Close()
			return statErr
		}
		expected, err := snapshot.ReadLimited(conf.Blob, maxConffileBytes)
		if err != nil || digest(expected) != conf.SHA256 {
			root.Close()
			return errors.New("candidate config snapshot checksum mismatch")
		}
		data, err := root.ReadLimited(filepath.Base(conf.Path), maxConffileBytes)
		root.Close()
		total += len(expected)
		if err != nil || digest(data) != conf.SHA256 || !updateModeMatches(info.Mode().Perm(), os.FileMode(conf.Mode)) || total > maxConffileBytes {
			return errors.New("installed configuration does not match candidate snapshot")
		}
	}
	return nil
}
