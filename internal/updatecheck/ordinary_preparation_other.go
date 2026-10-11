//go:build !linux

package updatecheck

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

func newOrdinaryPreparation(context.Context, *Updater, map[string]string, chan struct{}) (*ordinaryPreparation, error) {
	return nil, errOrdinaryPreparation
}
func (p *ordinaryPreparation) current(context.Context) error   { return errOrdinaryPreparation }
func (p *ordinaryPreparation) preflight(context.Context) error { return errOrdinaryPreparation }
func (p *ordinaryPreparation) capabilities(context.Context, string, int, int) error {
	return errOrdinaryPreparation
}
func (p *ordinaryPreparation) migrate(context.Context, *ownedfs.Root) error {
	return errOrdinaryPreparation
}
func (a *SelfUpdateFileAdapter) ordinaryFutureReady(context.Context, string, updateRecord, fileReview) error {
	return errOrdinaryPreparation
}
