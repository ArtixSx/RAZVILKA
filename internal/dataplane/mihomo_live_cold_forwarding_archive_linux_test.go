//go:build linux

package dataplane

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
)

// Real production forwarding writer -> bounded protected tree reader -> cold
// comparison decoder. Native process/kernel absence is not supplied here.
func TestMihomoColdRuntimeActualForwardingProducerRoundtrip(t *testing.T) {
	m, a, e, _, _, _ := mihomoLiveColdRetirementFixture(t)
	d := e.Resources[0].MihomoLive.Clone()
	lease := proxyForwardingLease{Version: 1, Policy: d.Policy}
	for _, table := range proxyFirewallTables(d.Policy) {
		lease.Created = append(lease.Created, proxyFirewallTableKey(table))
	}
	if err := a.writeForwardingLease(lease); err != nil {
		t.Fatal(err)
	}
	root, err := openBootRetirementRoot(m.StateRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	image, err := readMihomoColdRuntime(root, "mihomo", a)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateMihomoColdRuntime(a, d, image); err != nil {
		t.Fatal("real present forwarding manifest refused", err)
	}
	name := filepath.Base(a.forwardingPath())
	written := bytes.Clone(image.Files[name])
	if !bytes.Contains(written, []byte(`"created_tables"`)) {
		t.Fatal("fixture omitted actual producer wrapper")
	}
	for _, kind := range []string{"bare", "version", "policy", "unknown-table", "duplicate", "unknown-field"} {
		t.Run(kind, func(t *testing.T) {
			bad := lease
			bad.Created = append([]string(nil), lease.Created...)
			var raw []byte
			switch kind {
			case "bare":
				raw, _ = json.Marshal(d.Policy.Forwarding)
			case "version":
				bad.Version = 2
			case "policy":
				bad.Policy.Table++
			case "unknown-table":
				bad.Created = []string{"false/mangle"}
			case "duplicate":
				bad.Created = []string{lease.Created[0], lease.Created[0]}
			case "unknown-field":
				raw = bytes.Replace(written, []byte(`"version": 1`), []byte(`"version": 1,"foreign":true`), 1)
			}
			if raw == nil {
				raw, _ = json.Marshal(bad)
			}
			image.Files[name] = raw
			if validateMihomoColdRuntime(a, d, image) == nil {
				t.Fatal("invalid documentary forwarding lease accepted", kind)
			}
		})
	}
	image.Files[name] = written
	if err := validateMihomoColdRuntime(a, d, image); err != nil {
		t.Fatal("negative cases mutated valid frozen input", err)
	}
}
