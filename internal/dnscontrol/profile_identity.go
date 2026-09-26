package dnscontrol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// ScopedProfileIdentity binds runtime authority to the complete selected
// provider definition, including bootstrap, trust and endpoint properties.
// A lab/negative-control resolver cannot become production by passing a probe.
func (m *Manager) ScopedProfileIdentity(id string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := profileByID(id)
	if !ok {
		return "", ErrScopedDNS
	}
	v, ok := providerByIDFor(p.ProviderID, m.doc)
	if !ok || !v.Configured || v.Scope != "production" || v.Experimental || v.TrustedLocal || v.DoH == "" {
		return "", ErrScopedDNS
	}
	data, err := json.Marshal(struct {
		Profile  Profile
		Provider Provider
	}{p, v})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
