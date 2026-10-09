package dataplane

import (
	"context"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// The admission is a private original Manager command carrier. The retained
// StartupTools source invokes it only around its actual held-image Cmd.Start;
// process Wait and the COMMON durable acknowledgement remain outside it.
type SyntheticDNSCommandAdmission interface {
	WithStart(context.Context, string, []string, string, func() error) error
	syntheticDNSCommandAdmission()
}

type SyntheticDNSCommandToolRunner interface {
	RunSyntheticDNS(context.Context, SyntheticDNSCommandAdmission, string, ...string) ([]byte, error)
	CheckSyntheticDNS(context.Context, netidentity.Identity) error
}

// This descriptor compares the SAME retained native tool source. Paths,
// hashes and a successful Check cannot issue a command or publication lease.
// Production obtains it from the original StartupTools policy Lease factory.
type SyntheticDNSCommandTools struct {
	IPTables, ReviewSHA256 string
	Identity               netidentity.Identity
	Provider               *netidentity.Provider
	Runner                 SyntheticDNSCommandToolRunner
}

func (t *SyntheticDNSCommandTools) valid() bool {
	return t != nil && t.Provider != nil && t.Identity.Validate() == nil &&
		validPlanDigest(t.ReviewSHA256) && t.IPTables != "" && filepath.IsAbs(t.IPTables) &&
		filepath.Clean(t.IPTables) == t.IPTables && sameNetworkPolicyDependency(t.Runner, t.Runner)
}
