package dataplane

import (
	"os"
	"sync"
)

// A retained original binary descriptor is a file owner, never a launcher.
// Actual command publication remains the original scope/token's obligation.
type xraySelectedTCPExecutable struct {
	self         *xraySelectedTCPExecutable
	mu           sync.RWMutex
	material     *XrayOperationMaterial
	file         *os.File
	info         os.FileInfo
	path, sha256 string
	closed       bool
}

func (*xraySelectedTCPExecutable) String() string   { return "[private original Xray executable FD]" }
func (*xraySelectedTCPExecutable) GoString() string { return "[private original Xray executable FD]" }
