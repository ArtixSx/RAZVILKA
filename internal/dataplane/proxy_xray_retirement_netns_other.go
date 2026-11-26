//go:build !linux

package dataplane

import "context"

func xrayRetirementProcTables(context.Context, [2]int, func() error) (string, error) {
	return "", ErrProxyPolicyUnknown
}
