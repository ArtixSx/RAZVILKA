//go:build !linux || !razvilka_native_fixture

package dataplane

func nfqwsOriginalRecoveryOptions(_ *nfqws2ActiveExecution, options policyAdditionOptions) policyAdditionOptions {
	return options
}
