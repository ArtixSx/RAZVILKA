package app

import "context"

func (a *App) StartNodeFeeds(ctx context.Context) {
	if a.NodeFeeds != nil {
		a.NodeFeeds.StartManaged(ctx, a.Operations.Enter)
	}
}
func (a *App) WaitNodeFeeds(ctx context.Context) error {
	if a.NodeFeeds == nil {
		return nil
	}
	return a.NodeFeeds.Wait(ctx)
}
