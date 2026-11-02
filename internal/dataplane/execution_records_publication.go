package dataplane

import (
	"errors"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// The descriptor transfers before directory sync. A failed durability ACK must
// retain the actual authored inode for a same-owner retry, never close it and
// reopen whatever subsequently appears at the destination. The private sync
// callback is a durability operation only; it grants no resource authority.
func (d *xraySelectedTCPExecutionRecords) publishOriginalDurable(index int, data []byte, syncDirectory func(*ownedfs.Root) error) error {
	if d == nil || index < 0 || index > 1 || syncDirectory == nil {
		return ErrExecutionJournal
	}
	root, name := d.recordPath(index)
	if root == nil {
		return ErrExecutionJournal
	}
	file, err := root.WriteAtomicRetained(name, data, 0600)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err == nil {
		err = d.captureOriginalRecord(index, file, info, data, root, name)
	}
	if err != nil {
		return errors.Join(err, file.Close())
	}
	// captureOriginalRecord owns file even when the following sync fails.
	return syncDirectory(root)
}
