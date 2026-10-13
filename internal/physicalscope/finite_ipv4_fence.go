package physicalscope

func (s *fenceCollectorState) checkNotifications(frames []message) error {
	if s.finite != nil {
		return checkFiniteIPv4Notifications(frames, s.finite.original)
	}
	return checkSnapshotNotifications(frames, s.original)
}

// An original UNKNOWN router can repeat the same keyed fact. Its removal,
// resolution, new MAC/role/state or a new UNKNOWN row revokes the issuer.
// All other frames still use the original full notification classifiers.
func checkFiniteIPv4Notifications(frames []message, snapshot Snapshot) error {
	remaining := make([]message, 0, len(frames))
	for _, m := range frames {
		matched := false
		if m.kind == 28 || m.kind == 29 {
			n, err := parseKernelNeighbor(m)
			if err != nil {
				// The original classifier owns malformed selected rows and the
				// existing narrowly reviewed foreign bookkeeping exceptions.
				remaining = append(remaining, m)
				continue
			}
			for _, segment := range snapshot.Segments {
				for _, original := range segment.unresolvedRouters {
					if n.index != original.index || n.address != original.address {
						continue
					}
					if m.kind != 28 || m.flags != 0 || n != original {
						return at("finite.notifications.unknown.changed", nil)
					}
					matched = true
				}
			}
		}
		if !matched {
			remaining = append(remaining, m)
		}
	}
	return checkSnapshotNotifications(remaining, snapshot)
}
