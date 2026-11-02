package dataplane

import (
	"sync"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Only an original operation binds this resource to the same registered
// Mihomo adapter and COMMON writer. A decoded definition cannot construct it.
type mihomoLiveResource struct {
	mu               sync.Mutex
	validationUsed   bool
	startUsed        bool
	self             *mihomoLiveResource
	adapter          *MihomoProbeAdapter
	scope            *executionResourceScope
	source           *components.MihomoLiveSource
	node             *NodeDefaultSourceReview
	profile          *components.MihomoLiveProfile
	control          *operationgate.ControlEpochReview
	childControl     *operationgate.ControlEpochReview
	cleanup          *operationgate.ExclusiveCleanupReview
	child            *components.MihomoLiveProcess
	definition       ExecutionMihomoLiveDefinition
	id               string
	records          *xraySelectedTCPExecutionRecords
	active           bool
	pending          bool
	closed           bool
	closeErr         error
	reserveAttempted bool
	nativeUnused     bool
	proxy            *ProxyTunnelAdapter
	sidecar          *mihomoLiveSidecar
	sidecarAttempted bool
	sidecarUnused    bool
	tunIndex         int
	terminal         *MihomoLiveTerminal
	closing          *mihomoLiveClosing
	retired          bool
	filesMu          sync.Mutex
	compiledRoot     *ownedfs.Root
	compiledFiles    map[string]*mihomoLiveSidecarIdentityFile
}
