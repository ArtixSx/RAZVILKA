package startuptools

// The existing policy runner's fixed inspection ABI only. The stock profile
// translates numeric rule-show to its held legacy command before execution;
// its original no-name-input proof and numeric output parser remain required.
// This predicate never admits route/link/flush/delete or a policy effect.
func observedPolicyIPRead(stock bool, args []string) bool {
	if !stock {
		return ipReadArguments(args)
	}
	return len(args) == 3 && (args[0] == "-4" || args[0] == "-6") && args[1] == "rule" && args[2] == "show"
}
