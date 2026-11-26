package components

import "context"

// MihomoLiveProfileReference is comparison data from the original child, never
// a constructor, native validation verdict, service proof or packet grant.
type MihomoLiveProfileReference struct {
	ConfigSHA256 string `json:"config_sha256"`
	SOCKSPort    int    `json:"socks_port"`
}

func (p *MihomoLiveProcess) ProfileReference(ctx context.Context) (MihomoLiveProfileReference, error) {
	if err := p.Current(ctx); err != nil {
		return MihomoLiveProfileReference{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.closeErr != nil || p.profile == nil || p.source == nil {
		return MihomoLiveProfileReference{}, ErrMihomoLiveOwner
	}
	p.source.mu.Lock()
	defer p.source.mu.Unlock()
	profile := p.profile
	if p.source.self != p.source || !p.source.children[p] || !p.source.profiles[profile] || profile.self != profile || profile.source != p.source || digest(profile.config) != profile.configSHA {
		return MihomoLiveProfileReference{}, ErrMihomoLiveOwner
	}
	return MihomoLiveProfileReference{ConfigSHA256: profile.configSHA, SOCKSPort: profile.port}, nil
}
