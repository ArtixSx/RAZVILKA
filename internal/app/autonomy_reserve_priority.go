package app

// refillBeforeApply keeps background reserve work off the critical path when
// replacement is already authorized and at least one fresh usable proof exists.
// It is only scheduling: every selected node still receives the existing fresh
// pre-Apply check and guarded transaction. Unknown current state is not authority.
func refillBeforeApply(healthy, replace bool, ready, target int, due bool) bool {
	if ready >= target && !due {
		return false
	}
	return healthy || !replace || ready == 0
}
