package app

import (
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ArtixSx/razvilka/internal/nodestore"
)

const panelNodeBrowsePath = "/api/v1/panel/nodes"

// Historical display metadata only. Never retain host/port, secrets, source
// catalogues, groups, health, checks, generation or an executable node DTO.
type panelSavedNode struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Protocol  string `json:"protocol"`
	Transport string `json:"transport"`
}

var panelNodeID = regexp.MustCompile(`^node-[a-f0-9]{64}$`)

// Called only after nodeList's existing admitted private read succeeds. There
// is deliberately no startup/ticker collector and no additional store read.
func (a *App) capturePanelNodeBrowse(snapshot nodestore.Snapshot, now time.Time) bool {
	base := a.panelSnapshots.latest.Load()
	if base == nil || len(base.InstanceID) != 32 || now.IsZero() || len(snapshot.Nodes) > nodestore.MaxNodes {
		return false
	}
	nodes := make([]panelSavedNode, 0, len(snapshot.Nodes))
	for _, node := range snapshot.Nodes {
		if !panelNodeID.MatchString(node.ID) || !utf8.ValidString(node.Name) || len(node.Name) == 0 || len(node.Name) > 320 || len(node.Protocol) > 32 || len(node.Transport) > 32 {
			return false
		}
		// These are fixed parser-produced tokens, not a host or arbitrary URI.
		for _, token := range []string{node.Protocol, node.Transport} {
			if strings.IndexFunc(token, func(r rune) bool {
				return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_')
			}) >= 0 {
				return false
			}
		}
		nodes = append(nodes, panelSavedNode{node.ID, node.Name, node.Protocol, node.Transport})
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	for i := 1; i < len(nodes); i++ {
		if nodes[i-1].ID == nodes[i].ID {
			return false
		}
	}
	encoded, err := json.Marshal(struct {
		Nodes []panelSavedNode `json:"nodes"`
	}{nodes})
	if err != nil || len(encoded) > maxPanelSnapshotBytes {
		return false
	}
	for {
		previous := a.panelSnapshots.nodes.Load()
		revision := uint64(1)
		if previous != nil {
			if now.Before(previous.Generated) || previous.Revision == ^uint64(0) {
				return false
			}
			revision = previous.Revision + 1
		}
		if a.panelSnapshots.nodes.CompareAndSwap(previous, &panelSavedPublication{base.InstanceID, revision, now.UTC(), encoded}) {
			return true
		}
	}
}

func (a *App) panelNodeBrowseAt(now time.Time) panelDeviceBrowseResponse {
	value := panelDeviceBrowseResponse{Schema: 1, ObservedAt: now.UTC(), MaxAgeSeconds: 900, State: "empty", Dataplane: "not-checked"}
	if saved := a.panelSnapshots.nodes.Load(); saved != nil {
		value.InstanceID, value.Revision = saved.InstanceID, saved.Revision
		generated := saved.Generated
		value.GeneratedAt = &generated
		age := now.Sub(generated)
		value.DataAgeMS = max(0, age.Milliseconds())
		// Even a just-received catalogue contains no live health authority.
		value.State = "retained"
		if age >= panelSnapshotLifetime || age < -time.Second {
			value.State = "expired"
		} else {
			value.Data = saved.Data
		}
	}
	return value
}

func (a *App) panelNodeBrowse(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, a.panelNodeBrowseAt(time.Now()))
	}
}
