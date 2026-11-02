package dataplane

import "slices"

func sameMihomoLiveSpec(a, b ProcessSpec) bool {
	return a.ID == b.ID && a.Binary == b.Binary && a.Dir == b.Dir && a.PIDPath == b.PIDPath && a.LogPath == b.LogPath && a.MatchArg == b.MatchArg && a.RouteProof == b.RouteProof && slices.Equal(a.Args, b.Args)
}
