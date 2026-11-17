//go:build linux

package dataplane

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"os"
)

func domainTCPBaselineForwarding(ctx context.Context, original *networkPolicyIdentity) error {
	if original == nil || original.provider == nil || xraySelectedTCPFinite(ctx) != nil {
		domainTCPMeasure("baseline-forwarding-entry-refused")(0)
		return ErrDomainTCPBaselineKernel
	}
	// Fixed native-only stages observe the original calls. They neither repeat
	// a read nor replace an error; the ordinary build's measurement is a no-op.
	finishProvider := domainTCPMeasure("baseline-forwarding-provider-completed")
	result := original.provider.WithCurrent(ctx, func(held context.Context, actual netidentity.Identity) error {
		finishIdentity := domainTCPMeasure("baseline-forwarding-identity-completed")
		identityMatches := actual == original.value
		finishIdentity(0)
		if !identityMatches {
			domainTCPMeasure("baseline-forwarding-identity-refused")(0)
			return ErrDomainTCPBaselineKernel
		}
		finishOpen := domainTCPMeasure("baseline-forwarding-proc-open-completed")
		proc, err := openXraySelectedTCPProc(held, os.Getpid())
		finishOpen(0)
		if err != nil {
			domainTCPMeasure("baseline-forwarding-proc-open-refused")(0)
			return err
		}
		defer proc.close()
		finishNetwork := domainTCPMeasure("baseline-forwarding-network-completed")
		networkErr := proc.network(held, actual)
		finishNetwork(0)
		if networkErr != nil {
			domainTCPMeasure("baseline-forwarding-network-refused")(0)
			return networkErr
		}
		finishQdiscs := domainTCPMeasure("baseline-forwarding-qdiscs-completed")
		qdiscsErr := domainTCPBaselineQdiscs(held)
		finishQdiscs(0)
		if qdiscsErr != nil {
			domainTCPMeasure("baseline-forwarding-qdiscs-refused")(0)
			return qdiscsErr
		}
		finishPrograms := domainTCPMeasure("baseline-forwarding-programs-completed")
		programsErr := domainTCPBaselinePrograms(held, proc)
		finishPrograms(0)
		if programsErr != nil {
			domainTCPMeasure("baseline-forwarding-programs-refused")(0)
			return programsErr
		}
		finishForwarding := domainTCPMeasure("baseline-forwarding-ip-forward-completed")
		data, err := proc.read(held, proc.root, "sys/net/ipv4/ip_forward", 2)
		finishForwarding(0)
		if err != nil || string(data) != "1\n" {
			domainTCPMeasure("baseline-forwarding-ip-forward-refused")(0)
			return ErrDomainTCPBaselineKernel
		}
		// Retain the original || short-circuit: neither closing observation is
		// performed after an earlier refusal, and both still return the same
		// original baseline error rather than exposing a different cause.
		finishNetworkClosing := domainTCPMeasure("baseline-forwarding-network-closing-completed")
		networkClosingErr := proc.network(held, actual)
		finishNetworkClosing(0)
		if networkClosingErr != nil {
			domainTCPMeasure("baseline-forwarding-network-closing-refused")(0)
			return ErrDomainTCPBaselineKernel
		}
		finishCurrent := domainTCPMeasure("baseline-forwarding-proc-current-completed")
		currentErr := proc.current(held)
		finishCurrent(0)
		if currentErr != nil {
			domainTCPMeasure("baseline-forwarding-proc-current-refused")(0)
			return ErrDomainTCPBaselineKernel
		}
		if err := held.Err(); err != nil {
			domainTCPMeasure("baseline-forwarding-context-refused")(0)
			return err
		}
		return nil
	})
	finishProvider(0)
	if result != nil {
		domainTCPMeasure("baseline-forwarding-provider-refused")(0)
	}
	return result
}
