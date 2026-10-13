//go:build !linux

package physicalscope

import "github.com/ArtixSx/razvilka/internal/netidentity"

func platformSource(*netidentity.Provider, bool) observerSource { return observerSource{} }

func platformFiniteIPv4Source(*netidentity.Provider) observerSource { return observerSource{} }
