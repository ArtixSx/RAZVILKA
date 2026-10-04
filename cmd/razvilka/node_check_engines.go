package main

import (
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

func configuredNodeCheckers(state string) (*dataplane.ExactNodeDispatcher, map[string]dataplane.NodeChecker, error) {
	root, err := filepath.Abs(state)
	if err != nil {
		return nil, nil, err
	}
	const slots = 2
	sing := dataplane.NewExactNodeCheckerSlots(filepath.Join(root, "node-check"), slots)
	xray := dataplane.NewExactXrayNodeCheckerSlots(filepath.Join(root, "node-check-xray"), slots)
	dispatch, err := dataplane.NewExactNodeDispatcher(slots, sing, xray)
	if err != nil {
		return nil, nil, err
	}
	views := map[string]dataplane.NodeChecker{}
	for _, engine := range []string{"sing-box", "xray"} {
		view, err := dispatch.ForEngine(engine)
		if err != nil {
			return nil, nil, err
		}
		views[engine] = view
	}
	return dispatch, views, nil
}
