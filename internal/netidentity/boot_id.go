package netidentity

// ValidBootID checks only canonical boot-token syntax. It observes no kernel
// state and does not construct an identity or grant any operation.
func ValidBootID(value string) bool { return validBoot(value) }
