package app

import (
	"context"
	"errors"
	"reflect"

	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

type selfUpdateBoundFileJournal interface {
	OpenFileJournal() (*selfupdatejournal.Store, error)
}

// Production construction binds the actual adapter only for its fixed roots.
// Its paired reader owns the prior archive and helper evidence. A provider
// refusal never falls back to an unbound Store; legacy constructions keep the
// ordinary reader, which independently refuses paired state.
func (f *SelfUpdateFiles) openFileJournal() (*selfupdatejournal.Store, error) {
	if provider, ok := f.Adapter.(selfUpdateBoundFileJournal); ok {
		return provider.OpenFileJournal()
	}
	return selfupdatejournal.Open(f.Installation, f.Directory)
}

func readPairedFileCurrent(ctx context.Context, s *selfupdatejournal.Store, opening selfupdatejournal.Receipt) (selfupdatejournal.Receipt, error) {
	retained, err := s.RetainedReceipt(ctx, opening.ID)
	if err != nil {
		return opening, err
	}
	closing, present, err := s.Current()
	if err != nil || !present || !reflect.DeepEqual(opening, retained) || !reflect.DeepEqual(opening, closing) {
		return opening, errors.Join(selfupdatejournal.ErrMismatch, err)
	}
	return closing, ctx.Err()
}
