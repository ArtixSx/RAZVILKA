package dataplane

import (
	"os"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Serialized by the SAME Manager operation, never reconstructed from a marker.
// All authored descriptors survive partial metadata publication. None is an
// authority to start, stop, adopt or reuse a native process or packet resource.
type mihomoTransitArchiveCursor struct {
	self          *mihomoTransitArchiveCursor
	owner         *mihomoLiveResource
	before, after []byte
	archive       Execution
	image         []byte
	selected      map[string]*executionTransitResource
	root          *ownedfs.Root
	anchor        os.FileInfo
	parentAnchor  os.FileInfo
	relative      string
	file          *os.File
	info          os.FileInfo
	written       int
	durable       bool
	originACK     bool
	fileClosed    bool
	rootClosed    bool
	closeErr      error
	complete      bool
	publishing    bool               // Scope.mu; only the cursor's original writer call.
	fault         func(string) error // Refusal-only private test cut; never a grant.
}
