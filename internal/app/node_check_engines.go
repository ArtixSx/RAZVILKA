package app

import (
	"context"
	"errors"

	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

var errNodeHistoryAdmission = errors.New("dual-engine node history requires trusted downgrade admission")

// RAW Xray exact history uses its frozen reader2 contract. A newer supported
// reader version is not the minimum required by this write. The trusted
// admission independently inspects current and retained XHTTP material.
const xrayHistoryWriteReadVersion = 2

func nodeCheckEngine(engine string) (string, error) {
	if engine == "" {
		return "sing-box", nil
	}
	if engine != "sing-box" && engine != "xray" {
		return "", dataplane.ErrExactNodeUnsupported
	}
	return engine, nil
}

func (a *App) nodeCheckerForEngine(engine string) (dataplane.NodeChecker, error) {
	if engine != "sing-box" && engine != "xray" {
		return nil, dataplane.ErrExactNodeUnsupported
	}
	checker := a.NodeCheckers[engine]
	if checker == nil && engine == "sing-box" {
		checker = a.NodeChecker
	}
	if checker == nil {
		return nil, dataplane.ErrExactNodeUnavailable
	}
	if fixed, ok := checker.(interface{ EngineID() string }); ok && fixed.EngineID() != engine {
		return nil, dataplane.ErrExactNodeUnavailable
	}
	return checker, nil
}

func (a *App) nodeHistoryAdmission(ctx context.Context, engine string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if engine == "sing-box" {
		return nil
	}
	if engine != "xray" {
		return dataplane.ErrExactNodeUnsupported
	}
	if a.NodeHistoryWriteGuard == nil {
		return errors.Join(dataplane.ErrExactNodeUnavailable, errNodeHistoryAdmission)
	}
	if err := a.NodeHistoryWriteGuard(ctx, xrayHistoryWriteReadVersion); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.Join(dataplane.ErrExactNodeUnavailable, errNodeHistoryAdmission, err)
	}
	return ctx.Err()
}

func exactNodeResultIdentity(result dataplane.NodeCheckResult, engine, id, service, profile string) bool {
	path := engine + ":" + id
	if result.NodeID != id || result.ServiceID != service || result.NetworkProfile != profile || result.RoutePathID != path {
		return false
	}
	if !result.Available {
		if !result.Evidence.AssuranceLevel().AtLeast(evidence.Service) {
			return true
		}
		// A positive diagnostic proof also keeps its engine binding even when
		// the overall node result remains unavailable (for example control loss).
		proof := result.Evidence
		return proof.Engine == engine && proof.Service == service && proof.NetworkProfile == profile &&
			proof.RoutePathID == path && proof.ExpectedRoutePathID == path && proof.ObservedRoutePathID == path
	}
	proof := result.Evidence
	return result.TestLevel == "service" && result.Verdict == evidence.VerdictPass && !result.DirectLeak &&
		proof.Valid() && proof.AssuranceLevel().AtLeast(evidence.Service) && proof.Engine == engine &&
		proof.Service == service && proof.NetworkProfile == profile && proof.RoutePathID == path &&
		proof.ExpectedRoutePathID == path && proof.ObservedRoutePathID == path
}
