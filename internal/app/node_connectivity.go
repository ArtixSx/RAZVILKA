package app

import (
	"context"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"github.com/ArtixSx/razvilka/internal/nodestore"
)

// Called only by the explicitly admitted durable job, through its SAME exclusive
// context. No catalogue service or NodeStore writer is manufactured.
func (a *App) runNodeConnectivity(parent context.Context, id, profile string) nodeCheckItem {
	return a.runNodeConnectivityWithReview(parent, id, profile, "", nil)
}

func (a *App) runNodeConnectivityWithReview(parent context.Context, id, profile, engine string, review func(context.Context) error) (item nodeCheckItem) {
	item = nodeCheckItem{NodeID: id, NetworkProfile: profile, TestLevel: "connectivity", Verdict: "INCONCLUSIVE", Message: "Общий HTTPS-тест не завершён."}
	defer func() {
		if item.CheckedAt.IsZero() {
			item.CheckedAt = time.Now().UTC()
			item.ExpiresAt = item.CheckedAt.Add(dataplane.NodeConnectivityTTL)
		}
		a.nodeChecks.mu.Lock()
		a.rememberNodeConnectivityLocked(item)
		a.nodeChecks.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(parent, time.Minute)
	defer cancel()
	if a.Store == nil || a.Nodes == nil {
		item.ErrorCode = "node-check-unavailable"
		return item
	}
	owner, cfg := a.Store, a.Store.Get()
	definitions := a.catalogSnapshot()
	for i := range definitions.Services {
		definitions.Services[i] = defaultRouteCloneCatalogService(definitions.Services[i])
	}
	eligible := func(c context.Context) error {
		snapshot, err := a.Nodes.Snapshot(c, time.Now())
		if err != nil {
			return err
		}
		for _, n := range snapshot.Nodes {
			if n.ID == id && !n.Disabled && n.State != "expired" {
				return nil
			}
		}
		return nodestore.ErrDisabled
	}
	guard := func(c context.Context, host string, address netip.Addr) error {
		if c.Err() != nil {
			return c.Err()
		}
		if review != nil {
			if err := review(c); err != nil {
				return err
			}
		}
		if a.Store != owner || !reflect.DeepEqual(definitions, a.catalogSnapshot()) {
			return dataplane.ErrNodeResourceDenied
		}
		if err := a.Operations.WithExclusiveContext(parent, func() error { return c.Err() }); err != nil {
			return err
		}
		if err := eligible(c); err != nil {
			return err
		}
		return owner.WithResourceExclusionObservation(c, cfg, func(set config.EffectiveExclusionSet) error {
			target := config.ResourceTarget{Domain: host, Address: address}
			if ip, e := netip.ParseAddr(host); e == nil {
				if address.IsValid() && address != ip {
					return dataplane.ErrNodeResourceDenied
				}
				target.Domain = ""
				target.Address = ip
			}
			if target.Domain == "" && !target.Address.IsValid() {
				return nil
			}
			excluded, err := set.Matches(target)
			if err != nil || excluded {
				return dataplane.ErrNodeResourceDenied
			}
			// Known service exclusions also cover auxiliary hostnames; importing
			// a generic URL cannot silently waive a catalogue-wide negative.
			for _, service := range definitions.Services {
				matches := false
				for _, domain := range service.Domains {
					matches = matches || strings.EqualFold(host, domain) || strings.HasSuffix(strings.ToLower(host), "."+strings.ToLower(domain))
				}
				for _, raw := range service.CIDRs {
					if p, e := netip.ParsePrefix(raw); e == nil && address.IsValid() && p.Contains(address) {
						matches = true
					}
				}
				if matches {
					excluded, err = set.Matches(config.ResourceTarget{ServiceID: service.ID})
					if err != nil || excluded {
						return dataplane.ErrNodeResourceDenied
					}
				}
			}
			return nil
		})
	}
	if err := guard(ctx, "", netip.Addr{}); err != nil {
		item.ErrorCode = "node-resource-refused"
		return item
	}
	if err := guard(ctx, "www.gstatic.com", netip.Addr{}); err != nil {
		item.ErrorCode = "node-resource-refused"
		return item
	}
	var err error
	if engine == "" {
		engine, err = a.compatibleNodeEngine(ctx, "sing-box", id)
	}
	if err != nil {
		item.ErrorCode = nodeCheckFailureCode(err)
		return item
	}
	item.Engine = engine
	base, err := a.nodeCheckerForEngine(engine)
	if err != nil {
		item.ErrorCode = nodeCheckFailureCode(err)
		return item
	}
	checker, ok := base.(dataplane.NodeConnectivityChecker)
	if !ok {
		item.ErrorCode = "node-check-unavailable"
		return item
	}
	checkCtx := dataplane.WithNodeResourceGuard(ctx, guard)
	current, err := a.freshNetworkProfile(checkCtx)
	if err != nil || current != profile {
		item.ErrorCode = "node-network-changed"
		return item
	}
	var result dataplane.NodeConnectivityResult
	err = a.Nodes.WithSecret(checkCtx, id, func(raw []byte) error {
		if err := guard(checkCtx, "", netip.Addr{}); err != nil {
			return err
		}
		var e error
		result, e = checker.CheckConnectivity(checkCtx, dataplane.NodeConnectivityRequest{NodeID: id, NetworkProfile: profile, Outbound: raw})
		return e
	})
	item.CheckedAt = time.Now().UTC()
	item.ExpiresAt = item.CheckedAt.Add(dataplane.NodeConnectivityTTL)
	item.Stage, item.DirectControl, item.ProbeID = result.Stage, result.DirectControl, result.ProbeID
	if err == nil {
		err = guard(checkCtx, "", netip.Addr{})
	}
	if err == nil {
		observed, e := a.freshNetworkProfile(checkCtx)
		if e != nil || observed != profile {
			err = dataplane.ErrExactNodeNetworkChanged
		}
	}
	if err == nil && result.NodeID == id && result.Engine == engine && result.NetworkProfile == profile && !result.CheckedAt.After(item.CheckedAt) &&
		result.ExpiresAt.After(item.CheckedAt) && result.ExpiresAt.Sub(result.CheckedAt) <= dataplane.NodeConnectivityTTL {
		item.CheckedAt, item.ExpiresAt = result.CheckedAt, result.ExpiresAt
		item.CleanupVerified = result.CleanupVerified
		item.ConnectivityReady = result.Ready && result.CleanupVerified && result.Verdict == "PASS" && result.Stage == "connectivity" && result.HTTPStatus == 204 && result.DirectControl == "measured" && result.ProbeID != ""
		item.Verdict, item.ErrorCode, item.Message = string(result.Verdict), result.ErrorCode, result.Message
		item.DurationMS = result.DurationMS
		item.DirectEgressError = closedNodeEgressError(result.DirectEgressError)
		item.ProxyEgressError = closedNodeEgressError(result.ProxyEgressError)
		item.Stages = closedNodeCheckStages(result.Stages)
	} else {
		item.ErrorCode = nodeCheckFailureCode(err)
		item.Message = nodeCheckFailureMessage(err)
	}
	if result.Stage == "cleanup" || result.ErrorCode == "node-cleanup-failed" {
		item.ConnectivityReady, item.CleanupVerified = false, false
		item.Verdict, item.ErrorCode = "INCONCLUSIVE", "node-cleanup-failed"
	}
	return item
}

func (a *App) rememberNodeConnectivityLocked(item nodeCheckItem) {
	if item.NodeID == "" || item.CheckedAt.IsZero() || item.TestLevel != "connectivity" {
		return
	}
	item.Available = false
	if !item.CleanupVerified {
		item.ConnectivityReady = false
	}
	if a.nodeChecks.connectivity == nil {
		a.nodeChecks.connectivity = map[string]nodeCheckItem{}
	}
	if _, ok := a.nodeChecks.connectivity[item.NodeID]; !ok && len(a.nodeChecks.connectivity) >= nodestore.MaxNodes {
		oldest := ""
		for id, old := range a.nodeChecks.connectivity {
			if oldest == "" || old.CheckedAt.Before(a.nodeChecks.connectivity[oldest].CheckedAt) {
				oldest = id
			}
		}
		delete(a.nodeChecks.connectivity, oldest)
	}
	a.nodeChecks.connectivity[item.NodeID] = item
	a.rememberNodeConnectivityTransportLocked(item)
}

func (a *App) rememberNodeConnectivityTransportLocked(item nodeCheckItem) {
	key := item.NodeID + "\x00" + item.Engine + "\x00" + item.NetworkProfile
	if item.ConnectivityReady && item.CleanupVerified {
		delete(a.nodeChecks.connectivityTransportFailures, key)
		return
	}
	if item.ErrorCode != "node-transport-failed" || item.Stage != "transport" || !item.CleanupVerified || item.Engine == "" || item.ProbeID == "" || item.DirectControl != "not_run" {
		return
	}
	if a.nodeChecks.connectivityTransportFailures == nil {
		a.nodeChecks.connectivityTransportFailures = map[string][]nodeCheckItem{}
	}
	for k, rows := range a.nodeChecks.connectivityTransportFailures {
		if len(rows) == 0 || item.CheckedAt.Sub(rows[len(rows)-1].CheckedAt) > dataplane.NodeConnectivityTTL {
			delete(a.nodeChecks.connectivityTransportFailures, k)
		}
	}
	rows := a.nodeChecks.connectivityTransportFailures[key]
	for _, old := range rows {
		if old.ProbeID == item.ProbeID {
			return
		}
	}
	rows = append(rows, item)
	if len(rows) > 2 {
		rows = rows[len(rows)-2:]
	}
	a.nodeChecks.connectivityTransportFailures[key] = rows
	if len(a.nodeChecks.connectivityTransportFailures) > nodestore.MaxNodes {
		oldest := ""
		for k, v := range a.nodeChecks.connectivityTransportFailures {
			if oldest == "" || v[len(v)-1].CheckedAt.Before(a.nodeChecks.connectivityTransportFailures[oldest][len(a.nodeChecks.connectivityTransportFailures[oldest])-1].CheckedAt) {
				oldest = k
			}
		}
		delete(a.nodeChecks.connectivityTransportFailures, oldest)
	}
}

func (a *App) nodeConnectivitySnapshotLocked(now time.Time) []nodeCheckItem {
	rows := []nodeCheckItem{}
	for id, item := range a.nodeChecks.connectivity {
		if item.CheckedAt.After(now) || !item.ExpiresAt.After(now) || item.ExpiresAt.Sub(item.CheckedAt) > dataplane.NodeConnectivityTTL {
			delete(a.nodeChecks.connectivity, id)
			continue
		}
		rows = append(rows, item)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].NodeID < rows[j].NodeID })
	return rows
}
