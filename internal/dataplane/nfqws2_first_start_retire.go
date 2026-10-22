package dataplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

// Explicit application removal relinquishes only exact owned data blocks.
// Its script stays inert even after the project state is archived or purged.
// A durable phase in the SAME resource lease permits interrupted CAS retry.
func (a *NFQWS2Adapter) retireFirstStart(ctx context.Context, lease *nfqws2Lease) error {
	if !isNFQWS2Removal(ctx) || lease == nil || lease.FirstStart == nil {
		return errors.New("explicit NFQWS2 removal intent is required")
	}
	if lease.FirstStart.Phase != nfqws2FirstRetiring {
		if err := a.deactivateFirstStart(ctx, lease); err != nil {
			return err
		}
		current, err := a.readLease()
		if err != nil || !reflect.DeepEqual(current, lease) {
			return ErrReviewChanged
		}
		updated := *lease
		first := *lease.FirstStart
		first.Phase = nfqws2FirstRetiring
		updated.FirstStart = &first
		if err := a.writeLease(&updated); err != nil {
			return err
		}
		*lease = updated
	}
	if err := a.verifyOwnedRuntime(lease, true); err != nil {
		return err
	}
	init, exists, err := nfqws2Read(a.InitPath)
	if err != nil || !exists || nfqws2Hash(init) != lease.InitHash {
		return ErrReviewChanged
	}
	if _, err := engineconfig.NFQWSFirstStartOriginalInit(init, lease.Owner); err != nil {
		return err
	}
	if err := a.firstStartRuntimeAbsent(ctx); err != nil {
		return err
	}
	type change struct {
		path          string
		before, after []byte
		exists        bool
		mode          os.FileMode
	}
	changes := []change{}
	config, exists, err := nfqws2Read(a.ConfigPath)
	if err != nil || !exists {
		return ErrReviewChanged
	}
	original, err := engineconfig.NFQWSFirstStartOriginalConfig(config, lease.Owner)
	if err != nil || nfqws2Hash(original) != lease.ConfigOwner {
		return ErrReviewChanged
	}
	changes = append(changes, change{a.ConfigPath, config, original, true, 0600})
	for index, path := range a.ownedListPaths() {
		raw, exists, err := nfqws2Read(path)
		if err != nil {
			return err
		}
		if err := a.checkListOwnership(lease, index, raw, true); err != nil {
			return err
		}
		cleaned, _, err := removeManagedBlock(string(raw))
		if err != nil {
			return err
		}
		changes = append(changes, change{path, raw, []byte(cleaned), exists, 0644})
	}
	for _, change := range changes {
		if a.firstStartRetirementReady != nil {
			a.firstStartRetirementReady(change.path)
		}
		if err := firstStartReplace(change.path, change.before, change.exists, change.after, change.exists, change.mode); err != nil {
			return err
		}
	}
	for _, change := range changes {
		raw, exists, err := nfqws2Read(change.path)
		if err != nil || exists != change.exists || !bytes.Equal(raw, change.after) {
			return ErrReviewChanged
		}
	}
	actual, exists, err := nfqws2Read(a.InitPath)
	if err != nil || !exists || !bytes.Equal(actual, init) {
		return ErrReviewChanged
	}
	for _, path := range []string{a.ConfigPath + ".run", a.firstStartPIDPath()} {
		if _, exists, err := nfqws2Read(path); err != nil || exists {
			return ErrReviewChanged
		}
	}
	if err := a.firstStartRuntimeAbsent(ctx); err != nil {
		return err
	}
	current, err := a.readLease()
	if err != nil || !reflect.DeepEqual(current, lease) {
		return ErrReviewChanged
	}
	return a.writeLease(nil)
}
