package dataplane

import (
	"context"
	"errors"
	"testing"
)

type policyRuleReadCause struct{ cause error }

func (r policyRuleReadCause) Run(context.Context, string, ...string) ([]byte, error) {
	return nil, r.cause
}

func TestPolicyRuleReadPreservesOriginalRunnerCause(t *testing.T) {
	cause := errors.New("original protected inspection refused")
	for _, family := range []int{4, 6} {
		data, err := readPolicyRules(t.Context(), policyRuleReadCause{cause}, "original-ip", family)
		if data != nil || !errors.Is(err, cause) {
			t.Fatal("original read exception lost", family, err)
		}
	}
}
