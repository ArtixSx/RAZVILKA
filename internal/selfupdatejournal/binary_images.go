package selfupdatejournal

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strconv"
)

// BinaryImage binds a retained controller to the validated immutable image
// digest. It is a trusted read-only inventory, never an HTTP destination.
type BinaryImage struct {
	Path   string
	SHA256 string
}

func (s *Store) RetainedBinaryImages(ctx context.Context) ([]BinaryImage, error) {
	current, present, err := s.Current()
	if err != nil {
		return nil, err
	}
	directory, err := s.journalFiles.Open(".")
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	entries, err := directory.ReadDir(258)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(entries) > 257 {
		return nil, ErrMismatch
	}
	var images []BinaryImage
	found := false
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if entry.Name() == "current.json" || entry.Name() == ".writer.lock" {
			continue
		}
		if !entry.IsDir() || !idPattern.MatchString(entry.Name()) {
			return nil, ErrMismatch
		}
		data, err := s.journal.ReadLimited(entry.Name()+"/receipt.json", 16<<10)
		if err != nil {
			return nil, err
		}
		var receipt Receipt
		if decode(data, &receipt) != nil || !valid(receipt) || receipt.ID != entry.Name() || receipt.Pending() {
			return nil, ErrPending
		}
		canonical, err := json.Marshal(receipt)
		if err != nil || !bytes.Equal(data, canonical) {
			return nil, ErrMismatch
		}
		if receipt.ID == current.ID {
			found = true
		}
		if err := s.verifyImages(receipt); err != nil {
			return nil, err
		}
		for i, file := range receipt.Files {
			if file.Target != "bin/razvilka" {
				continue
			}
			base := filepath.Join(s.journalFiles.Name(), receipt.ID)
			if file.OldPresent {
				images = append(images, BinaryImage{filepath.Join(base, "old-"+strconv.Itoa(i)), file.OldHash})
			}
			images = append(images, BinaryImage{filepath.Join(base, "new-"+strconv.Itoa(i)), file.NewHash})
		}
	}
	if present && (!found || current.Pending()) || !present && len(images) > 0 {
		return nil, ErrPending
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return images, nil
}
