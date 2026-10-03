//go:build linux

package dataplane

import "testing"

// Uses already installed compatible AWG 3.1, with two independently keyed
// servers in owned namespaces. Actual HTTP/UDP, handshake and live-after
// assertions reuse the accepted D04 harness. Does not install/load a module.
func TestAWG31NativeCandidateIsolation(t *testing.T) {
	nativeWGFixture(t, "TestAWG31NativeCandidateIsolation")
}
