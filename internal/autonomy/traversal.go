package autonomy

import "time"

// Traversal is scheduling metadata in the existing runtime journal. It never
// grants node proof or Apply authority. Cursor counts consumed entries without
// wrapping; version binds the ordering to consent, service, scope and WAN.
type Traversal struct {
	Version             string    `json:"version"`
	Ordered             []string  `json:"ordered"`
	Cursor              int       `json:"cursor"`
	Exhausted           bool      `json:"exhausted"`
	Halted              bool      `json:"halted,omitempty"`
	RetryAt             time.Time `json:"retry_at"`
	StandardRoutesTried bool      `json:"standard_routes_tried,omitempty"`
}
