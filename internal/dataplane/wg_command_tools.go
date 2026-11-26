package dataplane

import (
	"context"
	"path/filepath"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// WGCommandAdmission is the original Manager owner's short Start leaf. A
// runner calls it under its own held tool and Provider bracket; it must not
// reenter Guard, Store, Scope, Provider or the tool source. Wait is outside it.
type WGCommandAdmission interface {
	WithStart(context.Context, string, []string, string, func() error) error
	wgCommandAdmission()
}

type WGCommandToolRunner interface {
	RunWG(context.Context, WGCommandAdmission, string, ...string) ([]byte, error)
	CheckWG(context.Context, netidentity.Identity) error
}

// WGCommandTools describes an original retained StartupTools source. These
// fields only compare owners; paths, digest and callback success issue no
// process or network authority. Production binds the actual startup lease's
// opaque runner, which independently verifies its held image and Provider.
type WGCommandTools struct {
	EngineID, WG, AWG, IP, IPTables, IP6Tables, ReviewSHA256 string
	Identity                                                 netidentity.Identity
	Provider                                                 *netidentity.Provider
	Runner                                                   WGCommandToolRunner
}

func (tools *WGCommandTools) valid(engine string) bool {
	if tools == nil || tools.EngineID != engine || (engine != "wireguard" && engine != "amneziawg") || tools.Provider == nil || tools.Identity.Validate() != nil || !sameNetworkPolicyDependency(tools.Runner, tools.Runner) || !validPlanDigest(tools.ReviewSHA256) {
		return false
	}
	primary := tools.WG
	if engine == "amneziawg" {
		primary = tools.AWG
	}
	for _, path := range []string{primary, tools.IP, tools.IPTables, tools.IP6Tables} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return false
		}
	}
	for _, path := range []string{tools.WG, tools.AWG} {
		if path != "" && (!filepath.IsAbs(path) || filepath.Clean(path) != path) {
			return false
		}
	}
	return true
}

// BindWGCommandTools retains the concrete startup descriptor before the
// original operation owner is constructed. It grants neither a path PASS nor
// command admission. A binding cannot be replaced on an existing adapter.
func (a *WARPWireGuardAdapter) BindWGCommandTools(tools WGCommandTools) error {
	if a == nil || a.wgCommandTools != nil || !tools.valid(a.ID()) {
		return ErrWGOperationOwner
	}
	runner, ok := a.Runner.(wgExecRunner)
	if !ok || runner.adapter != a {
		return ErrWGOperationOwner
	}
	copy := tools
	a.wgCommandTools = &copy
	a.IP, a.IPTables, a.IP6Tables = tools.IP, tools.IPTables, tools.IP6Tables
	a.WG = tools.WG
	if a.ID() == "amneziawg" {
		a.WG = tools.AWG
	}
	a.NativeOnly = true
	return nil
}
