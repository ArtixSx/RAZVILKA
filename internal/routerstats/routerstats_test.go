package routerstats

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCollectorReadsLinuxMetricsWithoutInventingTraffic(t *testing.T) {
	root := t.TempDir()
	writeMetric(t, root, "proc/stat", "cpu  100 0 20 300 10 0 0 0\n")
	writeMetric(t, root, "proc/loadavg", "0.12 0.25 0.50 1/100 10\n")
	writeMetric(t, root, "proc/meminfo", "MemTotal: 1000000 kB\nMemAvailable: 600000 kB\nSwapTotal: 1000 kB\nSwapFree: 500 kB\n")
	writeMetric(t, root, "proc/uptime", "123.5 100.0\n")
	writeMetric(t, root, "sys/class/thermal/thermal_zone0/temp", "67534\n")
	writeMetric(t, root, "sys/class/net/eth3/statistics/rx_bytes", "10000\n")
	writeMetric(t, root, "sys/class/net/eth3/statistics/tx_bytes", "2000\n")
	collector := Collector{Root: root, WANDetector: func() string { return "eth3" }, DiskProbe: func(string) (uint64, uint64, error) { return 1000, 700, nil }, Now: func() time.Time { return time.Unix(100, 0) }}
	raw := collector.Read()
	if raw.MemoryTotalKB != 1000000 || raw.MemoryAvailableKB != 600000 || raw.TemperatureC != 67.53 || raw.RXBytes != 10000 || raw.TXBytes != 2000 {
		t.Fatalf("unexpected raw metrics: %+v", raw)
	}
	snapshot := snapshotFrom(raw, Raw{})
	if snapshot.CPUReady || snapshot.TrafficReady {
		t.Fatalf("first sample invented rates: %+v", snapshot)
	}
	if snapshot.MemoryUsedPercent != 40 || snapshot.DiskUsedPercent != 30 {
		t.Fatalf("unexpected percentages: %+v", snapshot)
	}
}

func TestSamplerCalculatesDeltasAndDetectsCounterReset(t *testing.T) {
	first := Raw{Timestamp: time.Unix(100, 0), CPUCounters: CPUCounters{Total: 1000, Idle: 700}, WANInterface: "eth3", RXBytes: 1000, TXBytes: 500}
	second := Raw{Timestamp: time.Unix(105, 0), CPUCounters: CPUCounters{Total: 1200, Idle: 800}, WANInterface: "eth3", RXBytes: 6000, TXBytes: 1500}
	snapshot := snapshotFrom(second, first)
	if !snapshot.CPUReady || snapshot.CPUPercent != 50 || !snapshot.TrafficReady || snapshot.RXBytesPerSecond != 1000 || snapshot.TXBytesPerSecond != 200 {
		t.Fatalf("unexpected delta: %+v", snapshot)
	}
	reset := snapshotFrom(Raw{Timestamp: time.Unix(110, 0), WANInterface: "eth3", RXBytes: 10, TXBytes: 5}, second)
	if !reset.CounterReset || reset.TrafficReady {
		t.Fatalf("counter reset was not detected: %+v", reset)
	}
}

func TestHistoryIsBoundedAndCopied(t *testing.T) {
	now := time.Unix(100, 0)
	s := New(Collector{Now: func() time.Time { now = now.Add(time.Second); return now }})
	s.Limit = 2
	s.Sample()
	s.Sample()
	s.Sample()
	history := s.History(10)
	if len(history) != 2 {
		t.Fatalf("history length=%d", len(history))
	}
	history[0].Load1 = 99
	if s.History(10)[0].Load1 == 99 {
		t.Fatal("history returned internal storage")
	}
}

func TestAssessCapacity(t *testing.T) {
	high := Assess(Snapshot{
		MemoryTotalBytes: 512 << 20,
		MemoryFreeBytes:  256 << 20,
		DiskTotalBytes:   1024 << 20,
		DiskFreeBytes:    512 << 20,
		TemperatureC:     55,
		CPUReady:         true,
		CPUPercent:       20,
	})
	if high.Level != "high" || !high.AllowsLight || !high.AllowsMedium {
		t.Fatalf("unexpected high capacity: %+v", high)
	}
	critical := Assess(Snapshot{MemoryTotalBytes: 128 << 20, MemoryFreeBytes: 32 << 20, DiskTotalBytes: 512 << 20, DiskFreeBytes: 256 << 20})
	if critical.Level != "critical" || critical.AllowsLight {
		t.Fatalf("unexpected critical capacity: %+v", critical)
	}
}

func TestPersistentHistoryIsRateLimitedReloadedAndBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics", "history.jsonl")
	now := time.Unix(100, 0).UTC()
	s := New(Collector{Now: func() time.Time { return now }})
	s.PersistEvery = 5 * time.Minute
	s.PersistLimit = 2
	if err := s.EnablePersistence(path); err != nil {
		t.Fatal(err)
	}
	s.Sample()
	now = now.Add(time.Minute)
	s.Sample()
	if got := len(s.PersistentHistory(10)); got != 1 {
		t.Fatalf("rate limit ignored: history=%d", got)
	}
	now = now.Add(5 * time.Minute)
	s.Sample()
	now = now.Add(5 * time.Minute)
	s.Sample()
	if got := len(s.PersistentHistory(10)); got != 2 {
		t.Fatalf("persistent history not bounded: %d", got)
	}

	reloaded := New(Collector{})
	reloaded.PersistLimit = 2
	if err := reloaded.EnablePersistence(path); err != nil {
		t.Fatal(err)
	}
	loaded := reloaded.PersistentHistory(10)
	if len(loaded) != 2 || !loaded[1].Timestamp.Equal(now) {
		t.Fatalf("unexpected reloaded history: %+v", loaded)
	}
}

func TestTrafficPeriodsIgnoreCounterResetsAndWANChanges(t *testing.T) {
	now := time.Date(2026, 8, 21, 20, 0, 0, 0, time.UTC)
	samples := []Snapshot{
		{Timestamp: now.Add(-50 * time.Minute), WANInterface: "eth0", RXBytes: 100, TXBytes: 50},
		{Timestamp: now.Add(-40 * time.Minute), WANInterface: "eth0", RXBytes: 300, TXBytes: 100},
		{Timestamp: now.Add(-30 * time.Minute), WANInterface: "eth0", RXBytes: 10, TXBytes: 5, CounterReset: true},
		{Timestamp: now.Add(-20 * time.Minute), WANInterface: "eth0", RXBytes: 60, TXBytes: 25},
		{Timestamp: now.Add(-10 * time.Minute), WANInterface: "ppp0", RXBytes: 500, TXBytes: 200},
		{Timestamp: now, WANInterface: "ppp0", RXBytes: 620, TXBytes: 260},
	}
	periods := TrafficPeriods(samples, now)
	if len(periods) != 3 {
		t.Fatalf("periods=%d", len(periods))
	}
	hour := periods[0]
	if hour.RXBytes != 370 || hour.TXBytes != 130 {
		t.Fatalf("reset or WAN change was counted: %+v", hour)
	}
	if hour.Discontinuities != 2 || len(hour.WANInterfaces) != 2 || hour.Complete {
		t.Fatalf("missing discontinuity metadata: %+v", hour)
	}
}

func TestMergeHistoryDeduplicatesAndSorts(t *testing.T) {
	first := time.Unix(100, 0).UTC()
	merged := MergeHistory(
		[]Snapshot{{Timestamp: first.Add(time.Minute), RXBytes: 2}, {Timestamp: first, RXBytes: 1}},
		[]Snapshot{{Timestamp: first.Add(time.Minute), RXBytes: 3}},
	)
	if len(merged) != 2 || !merged[0].Timestamp.Equal(first) || merged[1].RXBytes != 3 {
		t.Fatalf("unexpected merged history: %+v", merged)
	}
}

func writeMetric(t *testing.T, root, relative, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
