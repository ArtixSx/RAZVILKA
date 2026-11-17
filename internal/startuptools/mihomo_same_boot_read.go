package startuptools

import "slices"

// Exactly the existing offline Mihomo table absence read and its original
// numeric fallback. No selector is rewritten: CORE still parses the complete
// response, and runMihomoLiveRead independently checks its closed command ABI.
func mihomoSameBootObservedTableRead(args []string) bool {
	return slices.Equal(args, []string{"-N", "route", "show", "table", "207"}) ||
		slices.Equal(args, []string{"-N", "-6", "route", "show", "table", "207"}) ||
		slices.Equal(args, []string{"route", "show", "table", "207"}) ||
		slices.Equal(args, []string{"-6", "route", "show", "table", "207"})
}
