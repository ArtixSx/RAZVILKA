package app

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/operationgate"
)

func (a *App) StartNodeFeeds(ctx context.Context) {
	if a.NodeFeeds != nil {
		a.NodeFeeds.StartManaged(operationgate.WithLabel(ctx, "обновление подписок"), a.Operations.Enter)
	}
}
func (a *App) WaitNodeFeeds(ctx context.Context) error {
	if a.NodeFeeds == nil {
		return nil
	}
	return a.NodeFeeds.Wait(ctx)
}
