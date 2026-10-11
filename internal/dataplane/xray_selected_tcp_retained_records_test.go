package dataplane

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Actual original atomic Manager writers and descriptors, tested separately
// from native/process admission. The private protocol fixture starts no child.
func TestXraySelectedTCPRecordsRetainOriginalBothWritersAcrossScopeDescriptorClose(t *testing.T) {
	for _, change := range []string{"unchanged", "transaction-ABA", "latest-ABA", "transaction-content", "latest-content"} {
		t.Run(change, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "manager")
			transaction := filepath.Join(path, "transactions", "dp-aaaaaaaaaaaaaaaa")
			if err := os.MkdirAll(transaction, 0700); err != nil {
				t.Fatal(err)
			}
			m := &Manager{StateRoot: path}
			s := &executionResourceScope{manager: m, managerRoot: path, root: transaction, execution: &Execution{PlanID: "dp-aaaaaaaaaaaaaaaa", Digest: strings.Repeat("a", 64), State: "planned"}}
			var err error
			s.owned, s.anchor, err = openNetworkPolicyObservationRoot(transaction)
			if err != nil {
				t.Fatal(err)
			}
			defer s.owned.Close()
			d := &xraySelectedTCPExecutionRecords{scope: s}
			d.root, d.anchor, err = openNetworkPolicyObservationRoot(path)
			if err != nil {
				t.Fatal(err)
			}
			d.transactionRoot, d.transactionAnchor, err = openNetworkPolicyObservationRoot(transaction)
			if err != nil {
				t.Fatal(err)
			}
			defer d.close()
			r := &XraySelectedTCPExecutionResource{scope: s, records: d}
			r.self = r
			s.xraySelectedTCP = map[string]*XraySelectedTCPExecutionResource{"original": r}
			if err := m.writeExecutionOwned(transaction, *s.execution, s); err != nil {
				t.Fatal("actual original writer failed", err)
			}
			c, end := context.WithTimeout(context.Background(), time.Second)
			defer end()
			if err := d.current(c, true); err != nil {
				t.Fatal(err)
			}
			if err := s.owned.Close(); err != nil {
				t.Fatal(err)
			}
			root, name := d.transactionRoot, "execution.json"
			if change == "latest-ABA" || change == "latest-content" {
				root, name = d.root, "latest-execution.json"
			}
			switch change {
			case "transaction-ABA", "latest-ABA":
				data, err := root.ReadLimited(name, 16<<20)
				if err != nil {
					t.Fatal(err)
				}
				if err := root.WriteAtomic(name, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "transaction-content", "latest-content":
				f, err := root.OpenFile(name, os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.WriteAt([]byte("!"), 0)
				f.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := d.current(c, true); (err == nil) != (change == "unchanged") {
				t.Fatal("retained FD/ABA outcome", change, err)
			}
			if change != "unchanged" && d.beforePublication() == nil {
				t.Fatal("new writer adopted replaced old record")
			}
		})
	}
}
