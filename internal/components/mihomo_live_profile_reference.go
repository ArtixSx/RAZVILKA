package components

import "context"

// ReviewProfileReference compares a profile retained by this original source.
// It performs no native validation, Start or packet operation.
func (s *MihomoLiveSource) ReviewProfileReference(ctx context.Context, profile *MihomoLiveProfile) (MihomoLiveProfileReference, error) {
	if s == nil {
		return MihomoLiveProfileReference{}, ErrMihomoLiveOwner
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.currentLocked(ctx); err != nil {
		return MihomoLiveProfileReference{}, err
	}
	if profile == nil || profile.self != profile || profile.source != s || !s.profiles[profile] || digest(profile.config) != profile.configSHA {
		return MihomoLiveProfileReference{}, ErrMihomoLiveOwner
	}
	return MihomoLiveProfileReference{ConfigSHA256: profile.configSHA, SOCKSPort: profile.port}, nil
}
