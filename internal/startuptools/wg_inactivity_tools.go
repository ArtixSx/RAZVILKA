package startuptools

import (
	"context"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/netidentity"
	"github.com/ArtixSx/razvilka/internal/operationgate"
)

// ReviewWGInactivity issues only an original negative inspection source from
// THIS retained managed lease. WGCommandTools remains strict about its primary
// CLI. Here absent CLI still requires complete admitted IP/xtables observations.
func (l *Lease) ReviewWGInactivity(ctx context.Context, manager *dataplane.Manager, control *operationgate.ControlEpochReview, engine string) (*dataplane.WGInactivityRead, error) {
	if l == nil || l.lifetime == nil || ctx == nil || engine != "wireguard" && engine != "amneziawg" {
		return nil, at("WG_INACTIVITY_UNISSUED", nil)
	}
	if _, finite := ctx.Deadline(); !finite {
		return nil, at("WG_INACTIVITY_DEADLINE", nil)
	}
	c, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	var tools dataplane.WGCommandTools
	err := func() error {
		if err := l.lock(c); err != nil {
			return err
		}
		defer l.unlock()
		if l.profile.wgEngine != managedListWGProfile || l.review == nil || l.review.ipEntry == nil || l.digest == "" || l.provider == nil {
			return at("WG_INACTIVITY_UNISSUED", nil)
		}
		if l.review.profile.wgEngine != l.profile.wgEngine || l.review.profile.wgAliases != l.profile.wgAliases || l.review.profile.ipAlias != l.profile.ipAlias || l.review.profile.aliases != l.profile.aliases {
			return at("WG_INACTIVITY_UNISSUED", nil)
		}
		if err := l.review.wgAbsencesCurrent(c); err != nil {
			return err
		}
		if err := l.current(c, l.identity, true); err != nil {
			return err
		}
		aliases := l.profile.wgAliases
		for i := range aliases {
			if l.review.wgEntry[i] == nil {
				aliases[i] = ""
			} else {
				aliases[i] = l.review.wgEntry[i].path
			}
		}
		tools = dataplane.WGCommandTools{EngineID: engine, WG: aliases[0], AWG: aliases[1], IP: l.profile.ipAlias, IPTables: l.profile.aliases[0], IP6Tables: l.profile.aliases[1],
			ReviewSHA256: l.digest, Identity: l.identity, Provider: l.provider, Runner: &wgInactivityRunner{l, engine}}
		return nil
	}()
	if err != nil {
		return nil, err
	}
	// DP control/source admission and full Check happen OUTSIDE the tool gate.
	return dataplane.ReviewWGInactivityRead(ctx, l.lifetime, manager, control, tools)
}

type wgInactivityRunner struct {
	lease  *Lease
	engine string
}

func (r *wgInactivityRunner) SameWGToolSource(other dataplane.WGCommandToolRunner) bool {
	o, ok := other.(*wgRunner)
	return r != nil && ok && o != nil && r.lease != nil && r.lease == o.lease && r.engine == o.engine
}

func (r *wgInactivityRunner) CheckWG(ctx context.Context, expected netidentity.Identity) error {
	if r == nil || r.lease == nil {
		return at("WG_INACTIVITY_UNISSUED", nil)
	}
	return r.lease.Check(ctx, expected)
}

func (r *wgInactivityRunner) RunWG(ctx context.Context, admission dataplane.WGCommandAdmission, name string, args ...string) ([]byte, error) {
	if r == nil || r.lease == nil || admission == nil || r.lease.review == nil || !wgInactivitySourceArguments(r.lease, name, args) {
		return nil, at("WG_INACTIVITY_ABI", nil)
	}
	return r.lease.runWGInactivity(WithCommandAdmission(ctx, admission), name, args...)
}

// An independent source ABI: even another sealed admission cannot turn this
// opaque startup reader into an effect runner. DP additionally restricts the
// original adapter's tables/endpoint and its exact one-use read invocation.
func wgInactivitySourceArguments(l *Lease, name string, args []string) bool {
	if l == nil || l.review == nil || !boundedArguments(args) || name == "" {
		return false
	}
	for _, image := range l.review.wgEntry {
		if image != nil && name == image.path {
			return slices.Equal(args, []string{"show", "all", "public-key"})
		}
	}
	if slices.Contains(l.profile.aliases[:], name) {
		return len(args) == 3 && args[0] == "-t" && (args[1] == "nat" || args[1] == "filter") && args[2] == "-S"
	}
	if name != l.profile.ipAlias {
		return false
	}
	flags := map[string]bool{}
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		if !slices.Contains([]string{"-N", "-4", "-6", "-j", "-details"}, args[0]) || flags[args[0]] {
			return false
		}
		flags[args[0]] = true
		args = args[1:]
	}
	if flags["-4"] && flags["-6"] {
		return false
	}
	if slices.Equal(args, []string{"link", "show"}) {
		return flags["-j"] && len(flags) == 1
	}
	if slices.Equal(args, []string{"rule", "show"}) {
		return flags["-N"] && !flags["-j"] && !flags["-details"]
	}
	if !flags["-N"] || len(args) != 4 && len(args) != 6 || !slices.Equal(args[:3], []string{"route", "show", "table"}) || flags["-details"] && !flags["-j"] {
		return false
	}
	table, err := strconv.Atoi(args[3])
	if err != nil || table < 1 || table > 252 || strconv.Itoa(table) != args[3] {
		return false
	}
	if len(args) == 6 {
		prefix, err := netip.ParsePrefix(args[5])
		return args[4] == "exact" && flags["-j"] && err == nil && prefix.String() == args[5] && prefix == prefix.Masked() && prefix.Bits() == prefix.Addr().BitLen() && !prefix.Addr().Is4In6() && prefix.Addr().Is6() == flags["-6"]
	}
	return true
}
