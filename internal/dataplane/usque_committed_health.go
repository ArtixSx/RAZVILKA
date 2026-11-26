package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"time"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/routeidentity"
	"github.com/ArtixSx/razvilka/internal/usquediag"
)

// CheckCommittedUSQUEHealth runs the existing owned live probe for the same
// committed legacy service under the original Manager. It may refresh its
// health evidence. It does not stage, adopt, start or alter networking.
func (m *Manager) CheckCommittedUSQUEHealth(ctx context.Context, expected Plan, configs *engineconfig.Manager) error {
	return m.checkCommittedUSQUEHealth(ctx, expected, configs, nil)
}

func (m *Manager) checkCommittedUSQUEHealth(ctx context.Context, expected Plan, configs *engineconfig.Manager, repair *usqueLocalRepair) (retErr error) {
	if ctx == nil || m == nil || m.StateRoot == "" || configs == nil || expected.State != "committed" || expected.SafeMode || !expected.Ready || expected.Noop ||
		!validPlanID(expected.PlanID) || expected.NetworkProfileID == "" || expected.LAN != nil || !slices.Contains(expected.Adapters, "usque") {
		return ErrReviewChanged
	}
	if err := validateForwardPlan(expected); err != nil {
		return err
	}
	ctx = expected.SiteExclusions.probeContext(ctx)
	routes := expected.RoutePlanFor("usque").Routes
	if len(routes) != 1 || routes[0].Resolved != "usque" || routes[0].NetworkPolicyRole != "" || len(routes[0].Domains) != 0 || len(routes[0].CIDRs) == 0 {
		return ErrReviewChanged
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if err := m.beginOperation(ctx); err != nil {
		return err
	}
	defer m.endOperation()
	if err := m.checkExecutionRecoveryWithin(ctx); err != nil {
		return err
	}
	adapter, _ := m.adapter("usque")
	a, ok := adapter.(*ProxyTunnelAdapter)
	if !ok || a == nil || a.Configs != configs || a.valid() != nil {
		return ErrReviewChanged
	}
	image, err := json.Marshal(expected)
	if err != nil || json.Unmarshal(image, &expected) != nil {
		return ErrReviewChanged
	}
	verify := func() error {
		registered, _ := m.adapter("usque")
		current, exists, err := m.committedLocked()
		if err != nil || !exists || registered != a || a.Configs != configs || !canaryImageEqual(image, current) || !a.usqueInitialOwnsRuntime() {
			return errors.Join(ErrReviewChanged, err)
		}
		return a.checkUSQUEPlanAuthority(ctx, expected)
	}
	if err := verify(); err != nil {
		return err
	}
	state, exists, err := a.loadPolicy()
	if err != nil || !exists || state.Interface != a.Interface || state.Table != a.Table || state.PriorityBase != a.Priority || len(state.Prefixes) == 0 {
		return errors.Join(errOwnedUSQUELiveHealth, err)
	}
	if err := a.checkSidecarIdentity(); err != nil {
		return err
	}
	if err := a.verifyCommittedReceipt(ctx, state); err != nil {
		return err
	}
	before, err := a.committedUSQUESession()
	if err != nil {
		return err
	}
	var child *OriginalProcess
	if repair != nil && repair.control != nil {
		var startErr error
		child, startErr = repair.restart(ctx, m, a, image, before, state, verify)
		defer func() {
			if !repair.result.RestartAttempted {
				return
			}
			m.usqueRepairRetry = nil
			if retErr == nil {
				repair.result.Restarted = true
				return
			}
			cleanup, finish := context.WithTimeout(context.WithoutCancel(ctx), a.timeout())
			defer finish()
			if child != nil {
				if err := child.StopAndJoin(cleanup); err != nil {
					retErr = errors.Join(retErr, ErrOriginalProcessCleanup, err)
					return
				}
			} else if errors.Is(retErr, ErrOriginalProcessCleanup) {
				return // The launcher could not join its own failed Start.
			}
			repair.retainAfterJoin(cleanup, m)
		}()
		if startErr != nil {
			return startErr
		}
	}
	if err := a.healthState(ctx, expected, state); err != nil {
		return err
	}
	current, exists, err := a.loadPolicy()
	if err != nil || !exists || !reflect.DeepEqual(current, state) {
		return errors.Join(ErrReviewChanged, err)
	}
	after, err := a.committedUSQUESession()
	if err != nil || !after.sameMaterial(before) {
		return errors.Join(ErrReviewChanged, err)
	}
	if err := errors.Join(a.verifyCommittedReceipt(ctx, current), verify(), ctx.Err()); err != nil {
		return err
	}
	if child != nil {
		if err := errors.Join(repair.control.Current(ctx), verifyRestartedUSQUEChild(ctx, child, after), repair.control.Current(ctx)); err != nil {
			return err
		}
	}
	m.usqueRepairRetry = nil
	return nil
}

type committedUSQUESession struct {
	transport usqueTransport
	sha       string
	binarySHA string
	argsSHA   string
	runtimeID string
}

func (s committedUSQUESession) sameMaterial(other committedUSQUESession) bool {
	s.runtimeID, other.runtimeID = "", ""
	return s == other
}

func verifyRestartedUSQUEChild(ctx context.Context, child *OriginalProcess, after committedUSQUESession) error {
	err := child.withObservedLive(ctx, func() error {
		passport, err := routeidentity.Verify(child.spec.Dir, "usque", child.endpoint)
		if err != nil || passport.PID != child.receipt.PID || passport.ID != after.runtimeID || passport.ConfigHash != after.sha {
			return ErrReviewChanged
		}
		return nil
	})
	if err != nil {
		return errors.Join(ErrReviewChanged, ctx.Err())
	}
	return nil
}

func (a *ProxyTunnelAdapter) committedUSQUESession() (committedUSQUESession, error) {
	var empty committedUSQUESession
	content, err := a.Configs.Read("usque", "main")
	if err != nil || !filepath.IsAbs(content.Path) || filepath.Clean(content.Path) != content.Path {
		return empty, errOwnedUSQUELiveHealth
	}
	// The live catalog slot is independent of any uncommitted editor draft.
	live, err := readUSQUEHealthConfig(content.Path)
	if err != nil {
		return empty, err
	}
	defer clear(live)
	canonical, _, err := a.buildEngineCandidate(live, a.SOCKSPort)
	defer clear(canonical)
	if err != nil {
		return empty, errOwnedUSQUELiveHealth
	}
	active, err := readUSQUEHealthConfig(a.engineConfigPath())
	if err != nil {
		return empty, err
	}
	defer clear(active)
	if !bytes.Equal(canonical, active) {
		return empty, errOwnedUSQUELiveHealth
	}
	root, err := a.openUSQUEHealthReceiptRoot()
	if err != nil {
		return empty, err
	}
	defer root.root.Close()
	transport, err := root.readTransport()
	if err != nil {
		return empty, err
	}
	raw, err := root.root.ReadLimited(root.out, 64<<10)
	if err != nil {
		return empty, errOwnedUSQUELiveHealth
	}
	var previous usquediag.CanaryEvidence
	if json.Unmarshal(raw, &previous) != nil || previous.Owned == nil {
		return empty, errOwnedUSQUELiveHealth
	}
	// A historical receipt corroborates session identity only. The caller
	// still obtains fresh process, underlay, policy and service evidence.
	image, err := json.Marshal(previous.Owned.CanaryEvidence())
	sha := routeidentity.Hash(active)
	if err != nil || !bytes.Equal(raw, image) || previous.Transport != usqueTransportName(transport) || previous.Owned.Identity.SessionSHA256 != sha || root.check() != nil {
		return empty, errOwnedUSQUELiveHealth
	}
	return committedUSQUESession{transport: transport, sha: sha, binarySHA: previous.Owned.Identity.BinarySHA256, argsSHA: previous.Owned.Identity.ArgsSHA256,
		runtimeID: previous.Owned.Identity.RuntimeID}, nil
}

func readUSQUEHealthConfig(path string) ([]byte, error) {
	root, err := ownedfs.Open(filepath.Dir(path))
	if err != nil {
		return nil, errOwnedUSQUELiveHealth
	}
	defer root.Close()
	data, err := root.ReadLimited(filepath.Base(path), 8<<20)
	if err != nil {
		return nil, errOwnedUSQUELiveHealth
	}
	return data, nil
}
