package dataplane

import "github.com/ArtixSx/razvilka/internal/components"

// Present only as inert storage in ordinary builds. Only the tagged refusal
// fixture can arm it; no value is a runtime/cleanup admission.
type mihomoLiveHealthNativeCut struct {
	self    *mihomoLiveHealthNativeCut
	owner   *mihomoLiveResource
	child   *components.MihomoLiveProcess
	sidecar *mihomoLiveSidecar
	digest  string
	hits    int // Original scope.mu.
}
