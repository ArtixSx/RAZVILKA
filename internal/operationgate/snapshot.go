package operationgate

import "time"

// Snapshot contains admission metadata only. It does not read Stores, acquire
// admission, certify a route, or grant permission to change the network.
// It reads the last committed in-memory gate state without taking the admission
// mutex, which may be held by a durable guard. An idle snapshot does not promise
// that a new admission will pass that guard or avoid waiting for it.
type Snapshot struct {
	State     string `json:"state"`
	Active    uint64 `json:"active"`
	Exclusive bool   `json:"exclusive"`
	Fenced    bool   `json:"fenced"`
	// Operation names what makes the gate busy, when its owner labeled it.
	Operation        string    `json:"operation,omitempty"`
	OperationSeconds int64     `json:"operation_seconds,omitempty"`
	Progress         *Progress `json:"progress,omitempty"`
}

// gateView is immutable after publication. The selected holder is copied, not
// the mutable holders map. Its optional progress tracker has its own immutable
// atomic step, so stage updates and elapsed time remain live while admission
// is waiting for storage. Neither this view nor a Snapshot grants a capability.
type gateView struct {
	active    uint64
	exclusive bool
	fenced    bool
	holderID  uint64
	holder    holder
}

// Every admission-state transition publishes before returning to its caller.
// Authority remains exclusively in the original fields protected by g.mu.
func (g *Gate) publishViewLocked() {
	id, selected, _ := g.presentationHolderLocked()
	g.view.Store(&gateView{
		active: g.active, exclusive: g.exclusive, fenced: g.fenced,
		holderID: id, holder: selected,
	})
}

func (g *Gate) Snapshot() Snapshot {
	return g.snapshotAt(time.Now())
}

func (g *Gate) snapshotAt(now time.Time) Snapshot {
	view := g.view.Load()
	if view == nil {
		return Snapshot{State: "idle"} // The ready-to-use zero value has no holder.
	}
	s := Snapshot{State: "idle", Active: view.active, Exclusive: view.exclusive, Fenced: view.fenced}
	h := view.holder
	if h.label != "" {
		s.Operation, s.OperationSeconds = h.label, max(0, int64(now.Sub(h.since)/time.Second))
	}
	s.Progress = h.progress.snapshot(view.holderID, h.since, now)
	switch {
	case view.fenced:
		s.State = "recovery-required"
	case view.exclusive:
		s.State = "busy"
	case view.active != 0:
		s.State = "shared"
	}
	return s
}
