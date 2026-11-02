package dataplane

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/autonomy"
	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

// Bracket only the existing two pure Guard comparisons. Neither sniffing nor
// WithFlow/Dial/Connect/Start borrows these facts; they run after this callback
// has joined and the original file/tool SHA closing observations succeeded.
func (c *DomainPolicyTCPCapture) guardPreparedFlow(ctx context.Context, mapping *dnscontrol.SyntheticDNSMapping, prepared *DomainPolicyTCPCaptureMapping, lease DomainPolicyTCPFlowLease, socket DomainPolicyTCPSocket) (autonomy.ScopeObservation, error) {
	ctx, finish := domainTCPMeasurePureGuard(ctx, "accepted-guard")
	defer finish()
	if c == nil || c.self != c || ctx == nil || ctx.Err() != nil || mapping == nil || prepared == nil || prepared.self != prepared || prepared.capture != c || prepared.source != mapping || lease == nil {
		return autonomy.ScopeObservation{}, ErrDomainPolicyTCPConsumer
	}
	original, ok := lease.(*domainTCPOriginalFlowLease)
	if !ok {
		if err := prepared.Current(ctx); err != nil {
			return autonomy.ScopeObservation{}, err
		}
		return lease.Guard(ctx, socket)
	}
	if original == nil || original.self != original || original.owner != c.owner || original.mapping != mapping || original.socket != socket {
		return autonomy.ScopeObservation{}, ErrDomainPolicyTCPConsumer
	}
	var result autonomy.ScopeObservation
	err := c.observePreparationClosing(ctx, mapping, func(observed context.Context, files *xrayDomainTCPFileObservation) error {
		if err := prepared.currentWithFiles(observed, files); err != nil {
			return err
		}
		var err error
		result, err = original.guardWithFiles(observed, socket, files)
		return err
	})
	if err != nil {
		return autonomy.ScopeObservation{}, errors.Join(err, ctx.Err())
	}
	return result, nil
}
