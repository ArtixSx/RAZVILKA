package startuptools

import "github.com/ArtixSx/razvilka/internal/dataplane"

// The registered original policy runner exposes only its SAME retained tool
// lease identity/descriptor to the Manager's domain coordinator. No command,
// lease acquisition or alternate tool source is accepted through this view.
func (r *policyRunner) DomainTCPCommandSource() (any, dataplane.SyntheticDNSCommandTools, error) {
	if r == nil || r.lease == nil {
		return nil, dataplane.SyntheticDNSCommandTools{}, at("POLICY_UNISSUED", nil)
	}
	descriptor, err := r.lease.SyntheticDNSCommandTools()
	return r.lease, descriptor, err
}
