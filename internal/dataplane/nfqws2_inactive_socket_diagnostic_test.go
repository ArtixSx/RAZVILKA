package dataplane

import (
	"errors"
	"strings"
	"testing"
)

func TestNFQWSInactiveNetlinkTableClosedDiagnostics(t *testing.T) {
	const header = "sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode\n"
	const row = "ffffffc02b225400 12 2732525227 00000000 0 0 0 2 0 5914\n"
	// Port IDs are unsigned 32-bit socket identifiers, not OS process IDs.
	if err := nfqws2InactiveNetlinkTable(header + row + "ffffffc02b227000 15 480 00000001 0 0 0 2 0 5970\n"); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, input string }{
		{"encoding", ""}, {"header", "private malformed captured header"},
		{"columns", header + "private-short-row\n"},
		{"number", header + strings.Replace(row, "2732525227", "4294967296", 1)},
		{"duplicate", header + row + row},
		{"owner-inode", header + strings.Replace(row, "5914", "0", 1)},
		{"limit", header + strings.Repeat("\n", 8192)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := nfqws2InactiveNetlinkTable(tc.input)
			outer := nfqws2InactiveAt("observation", nfqws2InactiveAt("kernel", nfqws2InactiveKernelAt("socket.table", err)))
			want := "NFQWS runtime inactivity: observation/kernel/kernel.socket.table/kernel.socket.table." + tc.name
			if !errors.Is(err, ErrNFQWSManagedKernelOwner) || outer.Error() != want {
				t.Fatalf("unexpected bounded refusal: %v", outer)
			}
		})
	}
}
