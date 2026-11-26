//go:build linux

package updatecheck

import (
	"context"
	"errors"
	"reflect"
)

func (a *SelfUpdateFileAdapter) ordinaryInstallerControllerReview(ctx context.Context, id string) (bool, error) {
	refuse := func(err error) (bool, error) { return false, errors.Join(ErrOrdinaryInstallerControllerRole, err) }
	if !productionOrdinaryRoleAdapter(a) {
		return refuse(ErrFileProtocol)
	}
	if err := a.checkStop(ctx, id, "read/observe"); err != nil {
		return refuse(err)
	}
	record, review, err := a.loadHeader(ctx, id)
	if err != nil {
		return refuse(err)
	}
	ordinary, err := ordinaryInstallerReviewKind(review, record)
	if err != nil {
		return refuse(err)
	}
	freshRecord, freshReview, err := a.loadHeader(ctx, id)
	if err != nil || !reflect.DeepEqual(freshRecord, record) || !reflect.DeepEqual(freshReview, review) {
		return refuse(errors.Join(ErrFileProtocol, err))
	}
	if err := a.checkStop(ctx, id, "read/observe"); err != nil {
		return refuse(err)
	}
	if err := ctx.Err(); err != nil {
		return refuse(err)
	}
	return ordinary, nil
}
