package dataplane

import (
	"slices"
	"strconv"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Original, immutable preparation. It contains no session, command hash or
// activation deadline and cannot be passed to the native process producer.
type nfqws2ActiveProcessIntent struct {
	StateRoot, Owner, ControlRoot, InstallationID string
	Sequence                                      uint64
	Program                                       nfqws2ManagedFile
	Assets                                        []nfqws2ManagedFile
	Args                                          []string
	Parent                                        components.NFQWSSupervisionIdentity
	NetworkIdentity                               netidentity.Identity
}

func nfqws2ActiveIntentFromCommand(c nfqws2ActiveProcessCommand) nfqws2ActiveProcessIntent {
	return nfqws2ActiveProcessIntent{StateRoot: c.StateRoot, Owner: c.Owner, ControlRoot: c.ControlRoot, InstallationID: c.InstallationID, Sequence: c.Sequence,
		Program: c.Program, Assets: slices.Clone(c.Assets), Args: slices.Clone(c.Args), Parent: c.Parent, NetworkIdentity: c.NetworkIdentity}
}

func (i nfqws2ActiveProcessIntent) command(id string, deadline time.Time) nfqws2ActiveProcessCommand {
	return nfqws2ActiveProcessCommand{Version: 1, Mode: nfqws2ActiveProcessMode, ID: id, StateRoot: i.StateRoot, Owner: i.Owner, ControlRoot: i.ControlRoot,
		InstallationID: i.InstallationID, Sequence: i.Sequence, Program: i.Program, Assets: slices.Clone(i.Assets), Args: slices.Clone(i.Args),
		Parent: i.Parent, NetworkIdentity: i.NetworkIdentity, ActivationDeadline: deadline}
}

func (r *NFQWSActiveMaterial) intentSpec() NFQWSScopedSpec {
	identity := r.intent.NetworkIdentity
	spec := NFQWSScopedSpec{Queue: r.queue, BootID: identity.BootID, NetworkIdentity: &identity,
		Candidate: NFQWSScopedCandidate{ID: r.reference.CandidateID, Incarnation: r.reference.Incarnation,
			ArgumentsSHA256: components.NFQWSRuntimeArgumentsSHA256(r.intent.Program.Path, r.intent.Args)}}
	if identity.Kind == netidentity.ProcNetInode {
		spec.NetNamespace = "net:[" + strconv.FormatUint(identity.Inode, 10) + "]"
	}
	return spec
}
