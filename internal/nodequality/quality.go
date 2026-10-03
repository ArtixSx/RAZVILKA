// Package nodequality contains bounded diagnostic observations. It never grants
// route authority. Observations are process-local; persisted NodeStore history
// keeps its existing schema and legacy latency meaning for safe downgrades.
package nodequality

import (
	"sort"
	"strings"
	"sync"
	"time"
)

const Version = 1
const MaxObservations = 1024
const Retention = 24 * time.Hour

// Observation deliberately has no Available/PASS field, address, URL or secret.
// A zero measured duration is valid (<1 ms); nil means it was not measured.
// ProxyResponseMS measures request-to-response headers of the final exact
// service probe, NOT ICMP, total test runtime, bandwidth or RTT to the server.
type Observation struct {
	Version         int       `json:"version"`
	NodeID          string    `json:"node_id"`
	ServiceID       string    `json:"service_id"`
	NetworkProfile  string    `json:"network_profile"`
	RoutePathID     string    `json:"route_path_id"`
	ProbeID         string    `json:"probe_id"`
	CheckedAt       time.Time `json:"checked_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	TCPConnectMS    *int64    `json:"tcp_connect_ms,omitempty"`
	ProxyResponseMS *int64    `json:"proxy_response_ms,omitempty"`
	TotalCheckMS    *int64    `json:"total_check_ms,omitempty"`
}

func scalar(s string) bool {
	if len(s) == 0 || len(s) > 160 {
		return false
	}
	for _, c := range s {
		if c != '-' && c != '_' && c != ':' && !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func validDuration(p *int64) bool {
	return p == nil || *p >= 0 && *p <= int64((10*time.Minute)/time.Millisecond)
}
func (o Observation) Valid(now time.Time) bool {
	return o.Version == Version && scalar(o.NodeID) && scalar(o.ServiceID) && scalar(o.NetworkProfile) && scalar(o.RoutePathID) && scalar(o.ProbeID) &&
		!o.CheckedAt.IsZero() && !o.CheckedAt.After(now) && o.ExpiresAt.After(o.CheckedAt) && o.ExpiresAt.Sub(o.CheckedAt) <= Retention &&
		validDuration(o.TCPConnectMS) && validDuration(o.ProxyResponseMS) && validDuration(o.TotalCheckMS)
}
func copyDuration(p *int64) *int64 {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
func clone(o Observation) Observation {
	o.TCPConnectMS = copyDuration(o.TCPConnectMS)
	o.ProxyResponseMS = copyDuration(o.ProxyResponseMS)
	o.TotalCheckMS = copyDuration(o.TotalCheckMS)
	return o
}
func key(o Observation) string { return o.NodeID + "\x00" + o.ServiceID + "\x00" + o.RoutePathID }

// Cache is safe for concurrent readers. The limit is fixed, even with many
// services or network changes. No background goroutine or flash write is used.
type Cache struct {
	mu      sync.Mutex
	entries map[string]Observation
}

func (c *Cache) Put(o Observation, now time.Time) bool {
	if c == nil || !o.Valid(now) {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[string]Observation)
	}
	k := key(o)
	if old, ok := c.entries[k]; ok && old.CheckedAt.After(o.CheckedAt) {
		return false
	}
	if _, ok := c.entries[k]; !ok && len(c.entries) >= MaxObservations {
		var oldest string
		for id, v := range c.entries {
			if oldest == "" || v.CheckedAt.Before(c.entries[oldest].CheckedAt) || v.CheckedAt.Equal(c.entries[oldest].CheckedAt) && id < oldest {
				oldest = id
			}
		}
		delete(c.entries, oldest)
	}
	c.entries[k] = clone(o)
	return true
}
func (c *Cache) Snapshot(now time.Time) []Observation {
	if c == nil {
		return []Observation{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Observation, 0, len(c.entries))
	for k, v := range c.entries {
		if now.Sub(v.CheckedAt) > Retention {
			delete(c.entries, k)
			continue
		}
		out = append(out, clone(v))
	}
	sort.Slice(out, func(i, j int) bool { return key(out[i]) < key(out[j]) })
	return out
}

// Match only the exact already-recorded check. Diagnostic memory cannot extend
// a proof TTL, promote an old network, or substitute a different executor.
func ResponseMS(o Observation, node, service, network, route, probe string, now time.Time) (int64, bool) {
	if !o.Valid(now) || !now.Before(o.ExpiresAt) || o.NodeID != node || o.ServiceID != service || o.NetworkProfile != network || o.RoutePathID != route || o.ProbeID != probe || o.ProxyResponseMS == nil {
		return 0, false
	}
	return *o.ProxyResponseMS, true
}

// ServiceFailure is conservative. ERROR is a checker/runtime/measurement error,
// not a remote failure. MISROUTED and direct-leak require repair/containment, not
// reputation poisoning of every mirror. PARTIAL without cause is inconclusive.
// Eligibility for Apply remains the existing exact-evidence contract.
func ServiceFailure(verdict, level, stage, code string, directLeak bool) bool {
	if directLeak || level != "service" || stage != "service" {
		return false
	}
	if strings.HasPrefix(code, "node-") || strings.HasPrefix(code, "route-") {
		return false
	}
	return verdict == "BLOCKED"
}
