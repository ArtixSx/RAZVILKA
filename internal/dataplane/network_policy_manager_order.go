package dataplane

import "slices"

func validateNetworkPolicyParticipation(p Plan) error {
	bound := p.LAN != nil
	for _, r := range p.Routes {
		bound = bound || r.NetworkPolicyGeneration != "" || r.NetworkPolicyRole != ""
	}
	if !bound {
		return nil
	}
	if _, err := p.FrozenLAN(); err != nil {
		return err
	}
	if !slices.Contains(p.Adapters, NetworkPolicyAdapterID) || slices.Contains(p.RetiringAdapters, NetworkPolicyAdapterID) || p.Noop {
		return ErrLANPolicyRuntime
	}
	return nil
}

func networkPolicyGateFirstIDs(ids []string) []string {
	result := slices.Clone(ids)
	if index := slices.Index(result, NetworkPolicyAdapterID); index > 0 {
		copy(result[1:index+1], result[:index])
		result[0] = NetworkPolicyAdapterID
	}
	return result
}

func networkPolicyGateLastIDs(ids []string) []string {
	result := slices.Clone(ids)
	if index := slices.Index(result, NetworkPolicyAdapterID); index >= 0 {
		copy(result[index:], result[index+1:])
		result[len(result)-1] = NetworkPolicyAdapterID
	}
	return result
}

func networkPolicyGateFirst(adapters []Adapter) []Adapter {
	result := slices.Clone(adapters)
	for i, a := range result {
		if a.ID() == NetworkPolicyAdapterID && i > 0 {
			copy(result[1:i+1], result[:i])
			result[0] = a
			break
		}
	}
	return result
}

func networkPolicyGateLast(adapters []Adapter) []Adapter {
	result := slices.Clone(adapters)
	for i, a := range result {
		if a.ID() == NetworkPolicyAdapterID {
			copy(result[i:], result[i+1:])
			result[len(result)-1] = a
			break
		}
	}
	return result
}
