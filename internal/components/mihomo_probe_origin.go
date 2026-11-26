package components

import (
	"context"
	"encoding/hex"
	"errors"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

var ErrMihomoProbeOrigin = errors.New("original Mihomo probe parent/death boundary is unavailable")

// Comparison data only. This does not adopt a process or authorize a signal.
// The original installed source captures it before publishing COMMON intent.
type MihomoProbeParentOrigin struct {
	Schema             int    `json:"schema"`
	BootID             string `json:"boot_id"`
	PID                int    `json:"pid"`
	StartTicks         uint64 `json:"start_ticks"`
	ExecutableDevice   uint64 `json:"executable_device"`
	ExecutableInode    uint64 `json:"executable_inode"`
	ExecutableSHA256   string `json:"executable_sha256"`
	ExecutableSize     int64  `json:"executable_size"`
	PIDNamespaceDevice uint64 `json:"pid_namespace_device"`
	PIDNamespaceInode  uint64 `json:"pid_namespace_inode"`
	ProcDevice         uint64 `json:"proc_device"`
	ProcInode          uint64 `json:"proc_inode"`
	DeathSignal        string `json:"death_signal"`
}

func (o MihomoProbeParentOrigin) IsZero() bool { return o == MihomoProbeParentOrigin{} }
func (o MihomoProbeParentOrigin) Validate() error {
	hash, err := hex.DecodeString(o.ExecutableSHA256)
	if o.Schema != 1 || !netidentity.ValidBootID(o.BootID) || o.PID < 1 || o.StartTicks == 0 || o.ExecutableInode == 0 || o.ExecutableSize < 1 || o.ExecutableSize > 128<<20 || o.PIDNamespaceInode == 0 || o.ProcInode == 0 || o.DeathSignal != "linux-pdeathsig-sigkill-v1" || err != nil || len(hash) != 32 || hex.EncodeToString(hash) != o.ExecutableSHA256 {
		return ErrMihomoProbeOrigin
	}
	return nil
}

type mihomoProbeOriginOwner interface {
	reference() MihomoProbeParentOrigin
	current(context.Context) error
	close() error
}
