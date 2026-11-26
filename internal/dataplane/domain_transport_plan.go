package dataplane

import "errors"

var ErrDomainTransportRuntime = errors.New("original domain transport runtime owner unavailable")

// These fields are retained intent only. The legacy DIRECT DNS mode cannot
// carry a synthetic transport, and an incomplete pair cannot authorize use.
func validateDomainTransportIntent(domain *DomainPolicyRuntimePlan, synthetic *SyntheticDNSTransportPlan, legacy *ScopedDNSPlan, suspend, discard bool) error {
	if domain == nil && synthetic == nil {
		return nil
	}
	if domain == nil || legacy != nil || suspend || discard {
		return ErrDomainPolicy
	}
	if err := ValidateDomainPolicyRuntimePlan(domain); err != nil {
		return err
	}
	if synthetic != nil {
		return ValidateSyntheticDNSTransportPlan(synthetic, domain)
	}
	return nil
}

// FrozenDomainTransport returns only defensive, validated definitions. It
// provides no listener, capture, publication or effect-operation authority.
func (p Plan) FrozenDomainTransport() (*DomainPolicyRuntimePlan, *SyntheticDNSTransportPlan, error) {
	if p.DomainPolicy == nil || p.SyntheticDNS == nil {
		return nil, nil, ErrDomainPolicy
	}
	domain := CloneDomainPolicyRuntimePlan(p.DomainPolicy)
	synthetic := CloneSyntheticDNSTransportPlan(p.SyntheticDNS)
	if err := validateDomainTransportIntent(domain, synthetic, p.DNS, p.SuspendDNS, p.DiscardDNS); err != nil {
		return nil, nil, err
	}
	return domain, synthetic, nil
}

func validateDomainTransportForExecution(p Plan) error {
	if err := validateDomainTransportIntent(p.DomainPolicy, p.SyntheticDNS, p.DNS, p.SuspendDNS, p.DiscardDNS); err != nil {
		return err
	}
	if p.DomainPolicy != nil || p.SyntheticDNS != nil {
		// Replaced only when SAME Manager has the actual sealed production
		// binding. Ready/DTO data cannot stand in for that original owner.
		return ErrDomainTransportRuntime
	}
	return nil
}
