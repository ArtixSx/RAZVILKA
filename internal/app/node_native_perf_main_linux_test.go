//go:build linux && !razvilka_native_fixture

package app

import (
	"fmt"
	"github.com/ArtixSx/razvilka/internal/nodestore"
	"os"
	"testing"
)

// Metadata-only controller ABI. It must precede testing's flag parser and
// never open a store or grant history admission; the actual fixed-path
// NodeHistoryAdmission still verifies this original installed executable.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "-node-history-read-version" {
		fmt.Println(nodestore.ExactHistoryReadVersion)
		os.Exit(0)
	}
	os.Exit(m.Run())
}
