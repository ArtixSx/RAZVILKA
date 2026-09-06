package nodestore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

const (
	MaxGroupNodes   = 32
	defaultHoldDown = 30 * time.Minute
	minimumHoldDown = time.Minute
	maximumHoldDown = 24 * time.Hour
)

type NodeGroup struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Mode            string    `json:"mode"` // manual or fallback
	NodeIDs         []string  `json:"node_ids"`
	PreferredNodeID string    `json:"preferred_node_id,omitempty"`
	HoldDownSeconds int       `json:"hold_down_seconds"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type ResolvedRoute struct {
	Route  string
	NodeID string
	Reason string
}

func (s *Store) CreateGroup(ctx context.Context, name, mode string, nodeIDs []string, preferred string, holdDown time.Duration, now time.Time) (NodeGroup, error) {
	if now.IsZero() {
		return NodeGroup{}, ErrGroup
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return NodeGroup{}, ErrStore
	}
	group := NodeGroup{ID: "group-" + hex.EncodeToString(idBytes), Name: name, Mode: mode, NodeIDs: append([]string(nil), nodeIDs...), PreferredNodeID: preferred,
		HoldDownSeconds: int(holdDown.Seconds()), CreatedAt: now.UTC(), UpdatedAt: now.UTC()}
	if holdDown == 0 {
		group.HoldDownSeconds = int(defaultHoldDown.Seconds())
	}
	return s.writeGroup(ctx, group, false)
}

func (s *Store) UpdateGroup(ctx context.Context, group NodeGroup, now time.Time) (NodeGroup, error) {
	if now.IsZero() {
		return NodeGroup{}, ErrGroup
	}
	group.UpdatedAt = now.UTC()
	return s.writeGroup(ctx, group, true)
}

func (s *Store) writeGroup(ctx context.Context, group NodeGroup, update bool) (NodeGroup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, before, err := s.load(ctx)
	if err != nil {
		return NodeGroup{}, err
	}
	index := -1
	for i := range doc.Groups {
		if doc.Groups[i].ID == group.ID {
			index = i
			break
		}
	}
	if update != (index >= 0) {
		if update {
			return NodeGroup{}, ErrNotFound
		}
		return NodeGroup{}, ErrGroup
	}
	if len(doc.Groups) >= MaxGroups && !update {
		return NodeGroup{}, ErrCapacity
	}
	if update {
		group.CreatedAt = doc.Groups[index].CreatedAt
	}
	group.NodeIDs = sortedUniqueIDs(group.NodeIDs)
	if !validGroup(group, nodeIDSet(doc)) {
		return NodeGroup{}, ErrGroup
	}
	if update {
		if groupsEqual(doc.Groups[index], group) {
			return doc.Groups[index], nil
		}
		doc.Groups[index] = group
	} else {
		doc.Groups = append(doc.Groups, group)
	}
	if err := s.commitDocument(ctx, &doc, before); err != nil {
		return NodeGroup{}, err
	}
	return group, nil
}

func (s *Store) DeleteGroup(ctx context.Context, id string, now time.Time) error {
	if !validGroupID(id) || now.IsZero() {
		return ErrGroup
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, before, err := s.load(ctx)
	if err != nil {
		return err
	}
	index := -1
	for i := range doc.Groups {
		if doc.Groups[i].ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return ErrNotFound
	}
	doc.Groups = append(doc.Groups[:index], doc.Groups[index+1:]...)
	return s.commitDocument(ctx, &doc, before)
}

// ResolveRoute proves a direct node or group reference for exactly one service
// and network. previousNode is the last committed effective node. A healthy
// previous node remains selected, preventing latency jitter from causing route
// churn; it is replaced only after its exact proof expires or fails.
func (s *Store) ResolveRoute(ctx context.Context, target, serviceID, networkProfile, previousNode string, previousSince, now time.Time) (ResolvedRoute, error) {
	if !sourcePattern.MatchString(serviceID) || !checkTokenPattern.MatchString(networkProfile) || now.IsZero() {
		return ResolvedRoute{}, ErrRouteProof
	}
	now = now.UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, _, err := s.load(ctx)
	if err != nil {
		return ResolvedRoute{}, err
	}
	if validNodeID(target) {
		index := nodeIndex(doc, target)
		binding := RouteBinding{ServiceID: serviceID, NodeID: target, NetworkProfile: networkProfile}
		if index < 0 || doc.Nodes[index].Disabled || !originFresh(doc.Nodes[index], now) || !nodeHasRouteProof(doc.Nodes[index], binding, now) {
			return ResolvedRoute{}, ErrRouteProof
		}
		return ResolvedRoute{Route: "sing-box:" + target, NodeID: target, Reason: "exact-node"}, nil
	}
	group, ok := findGroup(doc.Groups, target)
	if !ok {
		return ResolvedRoute{}, ErrRouteProof
	}
	usable := map[string]int64{}
	for _, id := range group.NodeIDs {
		index := nodeIndex(doc, id)
		if index < 0 || doc.Nodes[index].Disabled || !originFresh(doc.Nodes[index], now) {
			continue
		}
		if latency, ok := nodeRouteLatency(doc.Nodes[index], serviceID, networkProfile, now); ok {
			usable[id] = latency
		}
	}
	if len(usable) == 0 {
		return ResolvedRoute{}, ErrRouteProof
	}
	if group.Mode == "manual" {
		if _, ok := usable[group.PreferredNodeID]; !ok {
			return ResolvedRoute{}, ErrRouteProof
		}
		return ResolvedRoute{Route: "sing-box:" + group.PreferredNodeID, NodeID: group.PreferredNodeID, Reason: "manual-preferred"}, nil
	}
	if _, ok := usable[previousNode]; ok {
		reason := "last-known-good"
		if !previousSince.IsZero() && now.Sub(previousSince) < time.Duration(group.HoldDownSeconds)*time.Second {
			reason = "hysteresis-hold"
		}
		return ResolvedRoute{Route: "sing-box:" + previousNode, NodeID: previousNode, Reason: reason}, nil
	}
	if _, ok := usable[group.PreferredNodeID]; ok {
		return ResolvedRoute{Route: "sing-box:" + group.PreferredNodeID, NodeID: group.PreferredNodeID, Reason: "preferred-fallback"}, nil
	}
	ids := make([]string, 0, len(usable))
	for id := range usable {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		if usable[ids[i]] == usable[ids[j]] {
			return ids[i] < ids[j]
		}
		return usable[ids[i]] < usable[ids[j]]
	})
	return ResolvedRoute{Route: "sing-box:" + ids[0], NodeID: ids[0], Reason: "healthy-fallback"}, nil
}

func (s *Store) GroupServices(ctx context.Context, groupID, profile string, now time.Time) ([]string, error) {
	if !validGroupID(groupID) || !checkTokenPattern.MatchString(profile) || now.IsZero() {
		return nil, ErrGroup
	}
	snapshot, err := s.Snapshot(ctx, now)
	if err != nil {
		return nil, err
	}
	var group NodeGroup
	found := false
	for _, candidate := range snapshot.Groups {
		if candidate.ID == groupID {
			group, found = candidate, true
			break
		}
	}
	if !found {
		return nil, ErrNotFound
	}
	services := map[string]int{}
	for _, nodeID := range group.NodeIDs {
		available, routeErr := s.RouteServices(ctx, nodeID, profile, now)
		if routeErr != nil {
			continue
		}
		for _, service := range available {
			services[service]++
		}
	}
	out := []string{}
	for service, count := range services {
		if group.Mode == "fallback" && count > 0 || group.Mode == "manual" && serviceAvailableOnPreferred(snapshot, group, service, profile, now) {
			out = append(out, service)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (s *Store) commitDocument(ctx context.Context, doc *document, before restorejournal.Image) error {
	if doc.Generation == ^uint64(0) {
		return ErrCapacity
	}
	doc.Schema = schema
	doc.Generation++
	if validate(*doc) != nil {
		return ErrStore
	}
	data, err := json.Marshal(doc)
	if err != nil || len(data) > maxBytes {
		return ErrCapacity
	}
	if before.Exists && bytes.Equal(before.Data, data) {
		return nil
	}
	if err := s.target.CompareAndSwap(ctx, before, restorejournal.Image{Exists: true, Data: data}); err != nil {
		if errors.Is(err, restorejournal.ErrRecovery) {
			s.fenced = true
			return ErrRecovery
		}
		return ErrStore
	}
	return nil
}

func validGroup(group NodeGroup, nodes map[string]bool) bool {
	if !validGroupID(group.ID) || group.Name == "" || !validAlias(group.Name) || len(group.NodeIDs) == 0 || len(group.NodeIDs) > MaxGroupNodes ||
		group.CreatedAt.IsZero() || group.UpdatedAt.Before(group.CreatedAt) || group.HoldDownSeconds < int(minimumHoldDown.Seconds()) || group.HoldDownSeconds > int(maximumHoldDown.Seconds()) {
		return false
	}
	if group.Mode != "manual" && group.Mode != "fallback" {
		return false
	}
	preferred := group.PreferredNodeID == ""
	for _, id := range group.NodeIDs {
		if !validNodeID(id) || !nodes[id] {
			return false
		}
		if id == group.PreferredNodeID {
			preferred = true
		}
	}
	return preferred && (group.Mode != "manual" || group.PreferredNodeID != "")
}

func validGroupID(id string) bool {
	if !strings.HasPrefix(id, "group-") || len(id) != len("group-")+32 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(id, "group-"))
	return err == nil
}

func nodeIDSet(doc document) map[string]bool {
	out := make(map[string]bool, len(doc.Nodes))
	for _, node := range doc.Nodes {
		out[node.ID] = true
	}
	return out
}

func sortedUniqueIDs(values []string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		if validNodeID(value) {
			seen[value] = true
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func findGroup(groups []NodeGroup, id string) (NodeGroup, bool) {
	for _, group := range groups {
		if group.ID == id {
			return group, true
		}
	}
	return NodeGroup{}, false
}

func nodeRouteLatency(node storedNode, service, profile string, now time.Time) (int64, bool) {
	check, ok := latestRouteCheck(node, service, profile)
	if !ok || !routeCheckUsable(check, node.ID, service, profile, now) {
		return 0, false
	}
	return check.LatencyMS, true
}

func groupsEqual(left, right NodeGroup) bool {
	left.UpdatedAt, right.UpdatedAt = time.Time{}, time.Time{}
	left.NodeIDs, right.NodeIDs = append([]string(nil), left.NodeIDs...), append([]string(nil), right.NodeIDs...)
	return string(mustJSON(left)) == string(mustJSON(right))
}

func mustJSON(value any) []byte {
	data, _ := json.Marshal(value)
	return data
}

func serviceAvailableOnPreferred(snapshot Snapshot, group NodeGroup, service, profile string, now time.Time) bool {
	for _, node := range snapshot.Nodes {
		if node.ID != group.PreferredNodeID || node.Disabled {
			continue
		}
		for _, check := range node.Health.History {
			if check.ServiceID == service && check.NetworkProfile == profile && check.RoutePathID == "sing-box:"+node.ID && check.TestLevel == "service" {
				return routeCheckUsable(check, node.ID, service, profile, now)
			}
		}
	}
	return false
}
