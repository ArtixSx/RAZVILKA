package operationgate

// Snapshot contains admission metadata only. It does not read Stores, acquire
// admission, certify a route, or grant permission to change the network.
// The gate mutex is held only for copying a few fields; workers never retain
// that mutex while running a probe, a command, or a restore transaction.
type Snapshot struct {
	State     string `json:"state"`
	Active    uint64 `json:"active"`
	Exclusive bool   `json:"exclusive"`
	Fenced    bool   `json:"fenced"`
}

func (g *Gate) Snapshot() Snapshot {
	g.mu.Lock()
	defer g.mu.Unlock()
	s := Snapshot{State: "idle", Active: g.active, Exclusive: g.exclusive, Fenced: g.fenced}
	switch {
	case g.fenced:
		s.State = "recovery-required"
	case g.exclusive:
		s.State = "busy"
	case g.active != 0:
		s.State = "shared"
	}
	return s
}
