package routerstats

import (
	"sort"
	"time"
)

type TrafficPeriod struct {
	ID              string    `json:"id"`
	Label           string    `json:"label"`
	DurationSeconds int64     `json:"duration_seconds"`
	RXBytes         uint64    `json:"rx_bytes"`
	TXBytes         uint64    `json:"tx_bytes"`
	Samples         int       `json:"samples"`
	Discontinuities int       `json:"discontinuities"`
	WANInterfaces   []string  `json:"wan_interfaces"`
	From            time.Time `json:"from,omitempty"`
	To              time.Time `json:"to,omitempty"`
	Complete        bool      `json:"complete"`
}

// MergeHistory combines flash-friendly and short in-memory samples without
// double-counting timestamps. The bounded result is suitable for traffic
// totals and never invents samples between gaps.
func MergeHistory(groups ...[]Snapshot) []Snapshot {
	byTimestamp := make(map[int64]Snapshot)
	for _, group := range groups {
		for _, sample := range group {
			if sample.Timestamp.IsZero() {
				continue
			}
			byTimestamp[sample.Timestamp.UnixNano()] = sample
		}
	}
	out := make([]Snapshot, 0, len(byTimestamp))
	for _, sample := range byTimestamp {
		out = append(out, sample)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Timestamp.Before(out[j].Timestamp) })
	return out
}

func TrafficPeriods(samples []Snapshot, now time.Time) []TrafficPeriod {
	now = now.UTC()
	definitions := []struct {
		id       string
		label    string
		duration time.Duration
	}{
		{id: "hour", label: "За час", duration: time.Hour},
		{id: "day", label: "За сутки", duration: 24 * time.Hour},
		{id: "week", label: "За неделю", duration: 7 * 24 * time.Hour},
	}
	result := make([]TrafficPeriod, 0, len(definitions))
	for _, definition := range definitions {
		result = append(result, trafficPeriod(samples, now, definition.id, definition.label, definition.duration))
	}
	return result
}

func trafficPeriod(samples []Snapshot, now time.Time, id, label string, duration time.Duration) TrafficPeriod {
	period := TrafficPeriod{ID: id, Label: label, DurationSeconds: int64(duration.Seconds()), WANInterfaces: []string{}}
	cutoff := now.Add(-duration)
	interfaces := map[string]bool{}
	var previous Snapshot
	for _, sample := range samples {
		if sample.Timestamp.Before(cutoff) || sample.Timestamp.After(now.Add(time.Minute)) {
			continue
		}
		if period.From.IsZero() {
			period.From = sample.Timestamp
		}
		period.To = sample.Timestamp
		period.Samples++
		if sample.WANInterface != "" {
			interfaces[sample.WANInterface] = true
		}
		if previous.Timestamp.IsZero() {
			previous = sample
			continue
		}
		if sample.CounterReset || sample.WANInterface == "" || sample.WANInterface != previous.WANInterface || sample.RXBytes < previous.RXBytes || sample.TXBytes < previous.TXBytes {
			period.Discontinuities++
			previous = sample
			continue
		}
		period.RXBytes += sample.RXBytes - previous.RXBytes
		period.TXBytes += sample.TXBytes - previous.TXBytes
		previous = sample
	}
	for name := range interfaces {
		period.WANInterfaces = append(period.WANInterfaces, name)
	}
	sort.Strings(period.WANInterfaces)
	// A period is complete only when the oldest retained sample reaches its
	// boundary with at most one persistent-sample interval of tolerance.
	period.Complete = period.Samples >= 2 && !period.From.After(cutoff.Add(6*time.Minute))
	return period
}
