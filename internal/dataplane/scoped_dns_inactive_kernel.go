package dataplane

import "strings"

// CheckScopedDNSInactiveRule is a pure consumer predicate for a structural row
// from the common backend inventory. The trusted callback MUST first read that
// inventory fresh in the supplied typed identity, RequireComplete, and visit
// EVERY row in EVERY registered table/family. This predicate is no collector,
// coverage proof, persisted grant or permission to mutate a rule.
func CheckScopedDNSInactiveRule(family int, table string, tokens []string) error {
	if (family != 4 && family != 6) || table == "" || len(table) > 256 || len(tokens) < 2 || len(tokens) > 256 {
		return ErrScopedDNSRuntimeInactive
	}
	for index, token := range tokens {
		if len(token) > 4096 || strings.ContainsAny(token, "\x00\r\n") {
			return ErrScopedDNSRuntimeInactive
		}
		if index > 0 && tokens[index-1] == "--comment" {
			continue
		} // Quoted literal is inert.
		if strings.Contains(token, "RZD_") {
			return ErrScopedDNSRuntimeInactive
		}
	}
	return nil
}
