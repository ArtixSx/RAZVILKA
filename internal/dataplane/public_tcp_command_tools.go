package dataplane

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// PublicTCPCommandAdmission is implemented only by the original COMMON
// capture resource. A descriptor or syntactically valid command cannot issue
// this short actual-Start barrier; Wait remains in the protected tool source.
type PublicTCPCommandAdmission interface {
	WithStart(context.Context, string, []string, string, func() error) error
	publicTCPCommandAdmission()
}

type PublicTCPCommandToolRunner interface {
	RunPublicTCP(context.Context, PublicTCPCommandAdmission, string, ...string) ([]byte, error)
	CheckPublicTCP(context.Context, netidentity.Identity) error
}

// PublicTCPCommandTools is comparison metadata retaining the original startup
// lease. It grants neither listener/capture permission nor baseline equivalence.
type PublicTCPCommandTools struct {
	IP, IPTables, IP6Tables, ReviewSHA256 string
	Identity                              netidentity.Identity
	Provider                              *netidentity.Provider
	Runner                                PublicTCPCommandToolRunner
}
