package nodestore

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/providerprofile"
)

// extract accepts ONLY a config rebuilt by providerprofile, never caller JSON.
func extract(config []byte) ([]json.RawMessage, error) {
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	decoder := json.NewDecoder(bytes.NewReader(config))
	decoder.UseNumber()
	if decoder.Decode(&doc) != nil {
		return nil, ErrImport
	}
	var nodes []json.RawMessage
	for _, outbound := range doc.Outbounds {
		switch outbound["type"] {
		case "direct", "block", "selector", "urltest":
			continue
		case "vless", "hysteria2", "tuic", "shadowsocks":
		default:
			return nil, ErrImport
		}
		if tls, ok := outbound["tls"].(map[string]any); ok && tls["insecure"] == true {
			return nil, ErrImport
		}
		delete(outbound, "tag")
		data, err := json.Marshal(outbound)
		if err != nil {
			return nil, ErrImport
		}
		nodes = append(nodes, data)
	}
	return nodes, nil
}

func validate(doc document) error {
	if (doc.Schema != legacySchema && doc.Schema != metadataSchema && doc.Schema != schema) || doc.Owner != "razvilka-nodes" || doc.Generation == 0 || len(doc.IdentityKey) != 32 ||
		len(doc.Nodes) == 0 || len(doc.Nodes) > MaxNodes || len(doc.Sources) == 0 || len(doc.Sources) > MaxSources || len(doc.Secrets) != len(doc.Nodes) {
		return ErrStore
	}
	sources := map[string]bool{}
	for _, s := range doc.Sources {
		if !validSource(s) || sources[s.ID] {
			return ErrStore
		}
		sources[s.ID] = true
	}
	secrets := map[string]json.RawMessage{}
	for _, s := range doc.Secrets {
		if secrets[s.Ref] != nil || len(s.Outbound) == 0 {
			return ErrStore
		}
		// Re-normalization forbids persisted inbounds/routing/unsupported fields.
		result, err := providerprofile.ParseProfile("[" + string(s.Outbound) + "]")
		if err != nil || result.Preview.NodeCount != 1 || len(result.Preview.Rejected) > 0 {
			return ErrStore
		}
		materials, err := extract(result.Config)
		if err != nil || len(materials) != 1 || !bytes.Equal(materials[0], s.Outbound) {
			return ErrStore
		}
		secrets[s.Ref] = s.Outbound
	}
	ids := map[string]bool{}
	for _, n := range doc.Nodes {
		if !validAlias(n.Alias) || (doc.Schema == legacySchema && (n.Alias != "" || n.Disabled || len(n.Checks) != 0)) || (doc.Schema == metadataSchema && len(n.Checks) != 0) {
			return ErrStore
		}
		material := secrets[n.SecretRef]
		if material == nil || n.SecretRef != "secret-"+n.ID || n.ID != identity(doc.IdentityKey, material) || ids[n.ID] ||
			n.AddedAt.IsZero() || len(n.Origins) == 0 || len(n.Origins) > MaxSources {
			return ErrStore
		}
		ids[n.ID] = true
		seen := map[string]bool{}
		for _, origin := range n.Origins {
			ttl := origin.ExpiresAt.Sub(origin.ReceivedAt)
			if !sources[origin.SourceID] || seen[origin.SourceID] || origin.ReceivedAt.IsZero() ||
				origin.ReceivedAt.Before(n.AddedAt) || ttl <= 0 || ttl > maxTTL {
				return ErrStore
			}
			seen[origin.SourceID] = true
		}
		if len(n.Checks) > MaxCheckHistory {
			return ErrStore
		}
		checkIDs := map[string]bool{}
		lastCheck := time.Time{}
		for _, check := range n.Checks {
			if !validCheckRecord(check, n.ID) || checkIDs[check.ProbeID] || !lastCheck.IsZero() && check.CheckedAt.Before(lastCheck) {
				return ErrStore
			}
			checkIDs[check.ProbeID] = true
			lastCheck = check.CheckedAt
		}
	}
	return nil
}

func snapshot(doc document, now time.Time) Snapshot {
	out := Snapshot{Generation: doc.Generation, Sources: append([]Source{}, doc.Sources...), Nodes: []Node{}}
	kinds := map[string]string{}
	for _, s := range doc.Sources {
		kinds[s.ID] = s.Kind
	}
	secrets := map[string]json.RawMessage{}
	for _, s := range doc.Secrets {
		secrets[s.Ref] = s.Outbound
	}
	for _, n := range doc.Nodes {
		// Document has already been validated. Display fields are fixed/generated;
		// aliases, hostnames, SNI and arbitrary URI parameters are not public DTOs.
		var material struct {
			Type string `json:"type"`
			Port int    `json:"server_port"`
			TLS  struct {
				Enabled bool `json:"enabled"`
			} `json:"tls"`
			Transport struct {
				Type string `json:"type"`
			} `json:"transport"`
		}
		_ = json.Unmarshal(secrets[n.SecretRef], &material)
		state, trust := "expired", "user-supplied"
		for _, o := range n.Origins {
			if !now.Before(o.ReceivedAt) && now.Before(o.ExpiresAt) {
				state = "quarantined"
			}
			if kinds[o.SourceID] == "community" || kinds[o.SourceID] == "subscription" {
				trust = "untrusted"
			}
		}
		health := Health{State: "not_checked"}
		if len(n.Checks) > 0 {
			latest := n.Checks[len(n.Checks)-1]
			health = Health{
				State: latest.State, TestLevel: latest.TestLevel, Verdict: latest.Verdict, ServiceID: latest.ServiceID,
				NetworkProfile: latest.NetworkProfile, CheckedAt: latest.CheckedAt, ExpiresAt: latest.ExpiresAt,
				LatencyMS: latest.LatencyMS, EgressIP: latest.EgressIP, HTTPStatus: latest.HTTPStatus,
				ErrorCode: latest.ErrorCode, Message: latest.Message, RoutePathID: latest.RoutePathID,
				DirectLeak: latest.DirectLeak, History: reverseChecks(n.Checks),
			}
			if !now.Before(latest.ExpiresAt) {
				health.State = "stale"
				if state != "expired" {
					state = "stale"
				}
			} else if state != "expired" {
				if latest.State == "available" {
					state = "available"
				} else {
					state = "degraded"
				}
			}
		}
		if n.Disabled {
			state = "disabled"
		}
		name := n.Alias
		if name == "" {
			name = "Узел " + n.ID[5:13]
		}
		out.Nodes = append(out.Nodes, Node{ID: n.ID, Name: name, Protocol: strings.ToUpper(material.Type),
			Transport: material.Transport.Type, TLS: material.TLS.Enabled, Host: "***", Port: material.Port,
			State: state, Trust: trust, AddedAt: n.AddedAt, Origins: append([]Origin{}, n.Origins...), Health: health, Disabled: n.Disabled})
	}
	return out
}

func reverseChecks(checks []CheckRecord) []CheckRecord {
	out := make([]CheckRecord, len(checks))
	for index := range checks {
		out[len(checks)-1-index] = checks[index]
	}
	return out
}

// Reject duplicate keys, trailing documents, unknown schema fields and deep
// envelopes. Never return a JSON decoder error containing private input.
func decodeStrict(data []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 32 {
			return ErrStore
		}
		token, err := d.Token()
		if err != nil {
			return ErrStore
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, err := d.Token()
					name, ok := key.(string)
					if err != nil || !ok || seen[name] {
						return ErrStore
					}
					seen[name] = true
					if walk(depth+1) != nil {
						return ErrStore
					}
				}
			case '[':
				for d.More() {
					if walk(depth+1) != nil {
						return ErrStore
					}
				}
			default:
				return ErrStore
			}
			if _, err := d.Token(); err != nil {
				return ErrStore
			}
		}
		return nil
	}
	if walk(0) != nil {
		return ErrStore
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrStore
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrStore
	}
	return nil
}
