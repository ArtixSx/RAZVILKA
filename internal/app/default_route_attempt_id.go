package app

import (
	"crypto/rand"
	"encoding/hex"
)

// Each reviewed attempt needs a fresh transaction name in the Manager's
// dp-<16 lowercase hex> contract. The complete policy/source digest stays in
// Plan.Digest and the review/CAS comparisons; the nonce grants no authority.
func newDefaultRouteAttemptID() (string, error) {
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return "dp-" + hex.EncodeToString(nonce[:]), nil
}
