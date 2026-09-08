package telemetry

import (
	"sort"
	"sync"
	"time"
)

type Connection struct {
	ID              string    `json:"id"`
	ServiceID       string    `json:"service_id,omitempty"`
	ServiceName     string    `json:"service_name,omitempty"`
	Host            string    `json:"host,omitempty"`
	DestinationIP   string    `json:"destination_ip,omitempty"`
	DestinationPort string    `json:"destination_port,omitempty"`
	Protocol        string    `json:"protocol,omitempty"`
	SourceIP        string    `json:"source_ip,omitempty"`
	SourceName      string    `json:"source_name,omitempty"`
	Route           string    `json:"route"`
	Chain           []string  `json:"chain,omitempty"`
	Upload          uint64    `json:"upload"`
	Download        uint64    `json:"download"`
	StartedAt       time.Time `json:"started_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	Active          bool      `json:"active"`
	Evidence        string    `json:"evidence,omitempty"`
}

type Store struct {
	mu          sync.RWMutex
	active      map[string]Connection
	closed      map[string]Connection
	subscribers map[chan struct{}]struct{}
	maxClosed   int
	live        bool
	producer    string
	reason      string
}

func NewStore() *Store {
	return &Store{
		active: map[string]Connection{}, closed: map[string]Connection{},
		subscribers: map[chan struct{}]struct{}{}, maxClosed: 500,
		reason: "no dataplane telemetry producer is connected",
	}
}

type Status struct {
	Live     bool   `json:"live"`
	Producer string `json:"producer,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// SetProducer records whether a real dataplane telemetry source is currently
// feeding the store. A Store existing in memory is not itself live evidence.
func (s *Store) SetProducer(live bool, producer, reason string) {
	s.mu.Lock()
	s.live = live
	s.producer = producer
	s.reason = reason
	if live && s.reason == "" {
		s.reason = "dataplane telemetry producer is connected"
	}
	s.notifyLocked()
	s.mu.Unlock()
}

func (s *Store) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Status{Live: s.live, Producer: s.producer, Reason: s.reason}
}

func (s *Store) Upsert(c Connection) {
	if c.ID == "" {
		return
	}
	now := time.Now().UTC()
	if c.StartedAt.IsZero() {
		c.StartedAt = now
	}
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = now
	}
	c.Active = true
	c.Chain = append([]string(nil), c.Chain...)
	s.mu.Lock()
	if current, exists := s.active[c.ID]; exists && !current.StartedAt.IsZero() {
		c.StartedAt = current.StartedAt
	}
	if !s.live {
		s.live = true
		if s.producer == "" {
			s.producer = "dataplane-adapter"
		}
		s.reason = "dataplane adapter published route evidence"
	}
	s.active[c.ID] = c
	delete(s.closed, c.ID)
	s.notifyLocked()
	s.mu.Unlock()
}

// ReplaceActive atomically reconciles a complete snapshot from a real
// producer. Missing rows become bounded closed history and existing rows keep
// their original start time.
func (s *Store) ReplaceActive(producer string, rows []Connection) {
	now := time.Now().UTC()
	next := make(map[string]Connection, len(rows))
	s.mu.Lock()
	for _, connection := range rows {
		if connection.ID == "" {
			continue
		}
		if current, exists := s.active[connection.ID]; exists && !current.StartedAt.IsZero() {
			connection.StartedAt = current.StartedAt
		}
		if connection.StartedAt.IsZero() {
			connection.StartedAt = now
		}
		if connection.UpdatedAt.IsZero() {
			connection.UpdatedAt = now
		}
		connection.Active = true
		connection.Chain = append([]string(nil), connection.Chain...)
		next[connection.ID] = connection
		delete(s.closed, connection.ID)
	}
	for id, connection := range s.active {
		if _, exists := next[id]; exists {
			continue
		}
		connection.Active = false
		connection.UpdatedAt = now
		s.closed[id] = connection
	}
	s.active = next
	s.live = true
	s.producer = producer
	s.reason = "kernel telemetry snapshot is current"
	s.trimClosedLocked()
	s.notifyLocked()
	s.mu.Unlock()
}

func (s *Store) Close(id string) {
	if id == "" {
		return
	}
	s.mu.Lock()
	c, ok := s.active[id]
	if ok {
		delete(s.active, id)
		c.Active = false
		c.UpdatedAt = time.Now().UTC()
		s.closed[id] = c
		s.trimClosedLocked()
		s.notifyLocked()
	}
	s.mu.Unlock()
}

func (s *Store) Snapshot(includeClosed bool) []Connection {
	s.mu.RLock()
	out := make([]Connection, 0, len(s.active)+len(s.closed))
	for _, c := range s.active {
		c.Chain = append([]string(nil), c.Chain...)
		out = append(out, c)
	}
	if includeClosed {
		for _, c := range s.closed {
			c.Chain = append([]string(nil), c.Chain...)
			out = append(out, c)
		}
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Active != out[j].Active {
			return out[i].Active
		}
		return out[i].UpdatedAt.After(out[j].UpdatedAt)
	})
	return out
}

func (s *Store) Counts() (active, closed int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.active), len(s.closed)
}

func (s *Store) Subscribe() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	s.mu.Lock()
	s.subscribers[ch] = struct{}{}
	s.mu.Unlock()
	cancel := func() {
		s.mu.Lock()
		if _, ok := s.subscribers[ch]; ok {
			delete(s.subscribers, ch)
			close(ch)
		}
		s.mu.Unlock()
	}
	return ch, cancel
}

func (s *Store) notifyLocked() {
	for ch := range s.subscribers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (s *Store) trimClosedLocked() {
	if len(s.closed) <= s.maxClosed {
		return
	}
	type kv struct {
		id string
		t  time.Time
	}
	rows := make([]kv, 0, len(s.closed))
	for id, c := range s.closed {
		rows = append(rows, kv{id: id, t: c.UpdatedAt})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].t.Before(rows[j].t) })
	for i := 0; i < len(rows)-s.maxClosed; i++ {
		delete(s.closed, rows[i].id)
	}
}
