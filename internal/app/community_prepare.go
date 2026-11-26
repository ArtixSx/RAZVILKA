package app

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/community"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

var errCommunityChanged = errors.New("community preparation context changed")
var errCommunityAuth = errors.New("community preparation authentication expired")

type communityPreparation struct {
	manager     *community.Manager
	revision    uint64
	catalogHash string
	services    []catalog.Service
	close       func()
}

// Capture only immutable memory under admission. Source IO/cache preparation
// does not touch config, custom services or the dataplane and runs outside it.
func (a *App) beginCommunityPreparation(r *http.Request) (communityPreparation, error) {
	if a.Security == nil || !a.Security.Authenticated(r) {
		return communityPreparation{}, errCommunityAuth
	}
	// Bounded read-only preparation, not another network mutation queue.
	for {
		n := a.communityPreparationCount.Load()
		if n >= 2 {
			return communityPreparation{}, operationgate.ErrBusy
		}
		if a.communityPreparationCount.CompareAndSwap(n, n+1) {
			break
		}
	}
	var once sync.Once
	close := func() { once.Do(func() { a.communityPreparationCount.Add(-1) }) }
	retained := false
	defer func() {
		if !retained {
			close()
		}
	}()
	release, err := a.Operations.ObserveExclusive(r.Context(), nil)
	if err != nil {
		return communityPreparation{}, err
	}
	defer release()
	if a.Store == nil || a.Community == nil {
		return communityPreparation{}, errCommunityChanged
	}
	services := a.catalogSnapshot().Services
	retained = true
	return communityPreparation{manager: a.Community, revision: a.Store.Get().Revision, catalogHash: applyReviewHash(services), services: services, close: close}, nil
}

// Hold the short admission through response publication/import. Recheck the
// actual inputs rather than rejecting because an unrelated status was read.
func (a *App) finishCommunityPreparation(ctx context.Context, r *http.Request, p communityPreparation, importing bool) (func(), error) {
	var release func()
	var err error
	if importing {
		release, err = a.Operations.Exclusive(ctx)
	} else {
		release, err = a.Operations.ObserveExclusive(ctx, nil)
	}
	if err != nil {
		return nil, err
	}
	if a.Security == nil || !a.Security.Authenticated(r) {
		release()
		return nil, errCommunityAuth
	}
	if a.Store == nil || a.Community != p.manager || a.Store.Get().Revision != p.revision || applyReviewHash(a.catalogSnapshot().Services) != p.catalogHash {
		release()
		return nil, errCommunityChanged
	}
	return release, nil
}

func (a *App) writeCommunityPreparationFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errCommunityAuth):
		writeJSON(w, 401, map[string]any{"code": "SERVICE_SOURCE_AUTH_REQUIRED", "error": "Сеанс завершён. Войдите снова.", "not_started": true})
	case errors.Is(err, errCommunityChanged):
		writeJSON(w, 409, map[string]any{"code": "SERVICE_SOURCE_CHANGED", "error": "Сервисы или настройки изменились во время загрузки. Откройте новый предпросмотр.", "not_started": true})
	case errors.Is(err, operationgate.ErrBusy), errors.Is(err, operationgate.ErrRecovery):
		a.writeOperationFailure(w, err)
	default:
		writeCommunityFailure(w, err)
	}
}

func communityPreparationContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), 45*time.Second)
}
