package routerstats

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const DefaultHistoryLimit = 720
const DefaultPersistentHistoryLimit = 2016

type CPUCounters struct {
	Total uint64
	Idle  uint64
}

type Raw struct {
	Timestamp         time.Time
	CPUCounters       CPUCounters
	Load1             float64
	Load5             float64
	Load15            float64
	MemoryTotalKB     uint64
	MemoryAvailableKB uint64
	SwapTotalKB       uint64
	SwapFreeKB        uint64
	DiskTotalBytes    uint64
	DiskFreeBytes     uint64
	TemperatureC      float64
	UptimeSeconds     float64
	WANInterface      string
	RXBytes           uint64
	TXBytes           uint64
}

type Snapshot struct {
	Timestamp         time.Time `json:"timestamp"`
	CPUPercent        float64   `json:"cpu_percent"`
	CPUReady          bool      `json:"cpu_ready"`
	Load1             float64   `json:"load_1"`
	Load5             float64   `json:"load_5"`
	Load15            float64   `json:"load_15"`
	MemoryTotalBytes  uint64    `json:"memory_total_bytes"`
	MemoryFreeBytes   uint64    `json:"memory_available_bytes"`
	MemoryUsedPercent float64   `json:"memory_used_percent"`
	SwapTotalBytes    uint64    `json:"swap_total_bytes"`
	SwapFreeBytes     uint64    `json:"swap_free_bytes"`
	DiskTotalBytes    uint64    `json:"disk_total_bytes"`
	DiskFreeBytes     uint64    `json:"disk_free_bytes"`
	DiskUsedPercent   float64   `json:"disk_used_percent"`
	TemperatureC      float64   `json:"temperature_c,omitempty"`
	UptimeSeconds     float64   `json:"uptime_seconds"`
	WANInterface      string    `json:"wan_interface,omitempty"`
	RXBytes           uint64    `json:"rx_bytes"`
	TXBytes           uint64    `json:"tx_bytes"`
	RXBytesPerSecond  float64   `json:"rx_bytes_per_second"`
	TXBytesPerSecond  float64   `json:"tx_bytes_per_second"`
	TrafficReady      bool      `json:"traffic_ready"`
	CounterReset      bool      `json:"counter_reset"`
}

type Capacity struct {
	Level        string   `json:"level"`
	AllowsLight  bool     `json:"allows_light"`
	AllowsMedium bool     `json:"allows_medium"`
	Reasons      []string `json:"reasons"`
}

func Assess(snapshot Snapshot) Capacity {
	capacity := Capacity{Level: "unknown", Reasons: []string{}}
	if snapshot.MemoryTotalBytes == 0 || snapshot.DiskTotalBytes == 0 {
		capacity.Reasons = append(capacity.Reasons, "Недостаточно данных о RAM или накопителе")
		return capacity
	}
	freeRAMMiB := snapshot.MemoryFreeBytes >> 20
	freeDiskMiB := snapshot.DiskFreeBytes >> 20
	capacity.AllowsLight = freeRAMMiB >= 96 && freeDiskMiB >= 96 && snapshot.TemperatureC < 85
	capacity.AllowsMedium = freeRAMMiB >= 192 && freeDiskMiB >= 192 && snapshot.TemperatureC < 80
	switch {
	case freeRAMMiB < 64:
		capacity.Level = "critical"
		capacity.Reasons = append(capacity.Reasons, "Свободно меньше 64 МиБ RAM")
	case freeDiskMiB < 64:
		capacity.Level = "critical"
		capacity.Reasons = append(capacity.Reasons, "Свободно меньше 64 МиБ на Entware")
	case snapshot.TemperatureC >= 85:
		capacity.Level = "critical"
		capacity.Reasons = append(capacity.Reasons, "Температура достигла 85 °C")
	case snapshot.CPUReady && snapshot.CPUPercent >= 85:
		capacity.Level = "low"
		capacity.Reasons = append(capacity.Reasons, "Текущая загрузка CPU выше 85%")
	case capacity.AllowsMedium:
		capacity.Level = "high"
		capacity.Reasons = append(capacity.Reasons, "Достаточный запас RAM, Entware и температуры")
	case capacity.AllowsLight:
		capacity.Level = "medium"
		capacity.Reasons = append(capacity.Reasons, "Можно устанавливать только лёгкие компоненты")
	default:
		capacity.Level = "low"
		capacity.Reasons = append(capacity.Reasons, "Запас ресурсов ограничен")
	}
	return capacity
}

type Collector struct {
	Root        string
	OptPath     string
	WANDetector func() string
	DiskProbe   func(string) (uint64, uint64, error)
	Now         func() time.Time
}

func (c Collector) Read() Raw {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	raw := Raw{Timestamp: now().UTC()}
	raw.CPUCounters = readCPU(c.path("/proc/stat"))
	raw.Load1, raw.Load5, raw.Load15 = readLoad(c.path("/proc/loadavg"))
	raw.MemoryTotalKB, raw.MemoryAvailableKB, raw.SwapTotalKB, raw.SwapFreeKB = readMemory(c.path("/proc/meminfo"))
	raw.TemperatureC = readTemperature(c.path("/sys/class/thermal"))
	raw.UptimeSeconds = readFirstFloat(c.path("/proc/uptime"))
	opt := c.OptPath
	if strings.TrimSpace(opt) == "" {
		opt = c.path("/opt")
	}
	diskProbe := c.DiskProbe
	if diskProbe == nil {
		diskProbe = diskUsage
	}
	if total, free, err := diskProbe(opt); err == nil {
		raw.DiskTotalBytes, raw.DiskFreeBytes = total, free
	}
	if c.WANDetector != nil {
		raw.WANInterface = strings.TrimSpace(c.WANDetector())
	}
	if validInterface.MatchString(raw.WANInterface) {
		base := c.path("/sys/class/net/" + raw.WANInterface + "/statistics")
		raw.RXBytes = readUint(filepath.Join(base, "rx_bytes"))
		raw.TXBytes = readUint(filepath.Join(base, "tx_bytes"))
	}
	return raw
}

func (c Collector) path(absolute string) string {
	if strings.TrimSpace(c.Root) == "" {
		return absolute
	}
	clean := strings.TrimLeft(filepath.ToSlash(absolute), "/")
	return filepath.Join(c.Root, filepath.FromSlash(clean))
}

var validInterface = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,32}$`)

type Sampler struct {
	Collector    Collector
	Interval     time.Duration
	Limit        int
	PersistEvery time.Duration
	PersistLimit int

	mu           sync.RWMutex
	latest       Snapshot
	history      []Snapshot
	lastRaw      Raw
	persistPath  string
	persisted    []Snapshot
	lastPersist  time.Time
	persistError string
}

func New(collector Collector) *Sampler {
	return &Sampler{Collector: collector, Interval: 5 * time.Second, Limit: DefaultHistoryLimit, PersistEvery: 5 * time.Minute, PersistLimit: DefaultPersistentHistoryLimit}
}

func (s *Sampler) EnablePersistence(path string) error {
	if s == nil {
		return errors.New("nil metrics sampler")
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("metrics history path is empty")
	}
	loaded, err := readPersistentHistory(path, s.persistLimit())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	s.mu.Lock()
	s.persistPath = path
	s.persisted = loaded
	if len(loaded) > 0 {
		s.lastPersist = loaded[len(loaded)-1].Timestamp
	}
	s.persistError = ""
	s.mu.Unlock()
	return nil
}

func (s *Sampler) Start(ctx context.Context) {
	if s == nil {
		return
	}
	s.Sample()
	interval := s.Interval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.Sample()
			}
		}
	}()
}

func (s *Sampler) Sample() Snapshot {
	if s == nil {
		return Snapshot{}
	}
	raw := s.Collector.Read()
	s.mu.Lock()
	snapshot := snapshotFrom(raw, s.lastRaw)
	s.lastRaw = raw
	s.latest = snapshot
	limit := s.Limit
	if limit <= 0 {
		limit = DefaultHistoryLimit
	}
	s.history = append(s.history, snapshot)
	if len(s.history) > limit {
		copy(s.history, s.history[len(s.history)-limit:])
		s.history = s.history[:limit]
	}
	persistPath := s.persistPath
	persist := persistPath != "" && (s.lastPersist.IsZero() || snapshot.Timestamp.Sub(s.lastPersist) >= s.persistEvery())
	rewrite := false
	var persisted []Snapshot
	if persist {
		s.lastPersist = snapshot.Timestamp
		s.persisted = append(s.persisted, snapshot)
		persistLimit := s.persistLimit()
		if len(s.persisted) > persistLimit {
			s.persisted = append([]Snapshot(nil), s.persisted[len(s.persisted)-persistLimit:]...)
			rewrite = true
		}
		persisted = append([]Snapshot(nil), s.persisted...)
	}
	s.mu.Unlock()
	if persist {
		err := appendPersistentSnapshot(persistPath, snapshot, rewrite, persisted)
		s.mu.Lock()
		if err != nil {
			s.persistError = err.Error()
		} else {
			s.persistError = ""
		}
		s.mu.Unlock()
	}
	return snapshot
}

func (s *Sampler) Latest() Snapshot {
	if s == nil {
		return Snapshot{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.latest
}

func (s *Sampler) History(limit int) []Snapshot {
	if s == nil {
		return []Snapshot{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > len(s.history) {
		limit = len(s.history)
	}
	start := len(s.history) - limit
	out := make([]Snapshot, limit)
	copy(out, s.history[start:])
	return out
}

func (s *Sampler) PersistentHistory(limit int) []Snapshot {
	if s == nil {
		return []Snapshot{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > len(s.persisted) {
		limit = len(s.persisted)
	}
	out := make([]Snapshot, limit)
	copy(out, s.persisted[len(s.persisted)-limit:])
	return out
}

func (s *Sampler) PersistenceStatus() (enabled bool, lastError string) {
	if s == nil {
		return false, ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.persistPath != "", s.persistError
}

func (s *Sampler) persistEvery() time.Duration {
	if s.PersistEvery <= 0 {
		return 5 * time.Minute
	}
	return s.PersistEvery
}

func (s *Sampler) persistLimit() int {
	if s.PersistLimit <= 0 {
		return DefaultPersistentHistoryLimit
	}
	return s.PersistLimit
}

func readPersistentHistory(path string, limit int) ([]Snapshot, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	entries := make([]Snapshot, 0, limit)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		var snapshot Snapshot
		if err := json.Unmarshal(scanner.Bytes(), &snapshot); err != nil || snapshot.Timestamp.IsZero() {
			continue
		}
		entries = append(entries, snapshot)
		if len(entries) > limit {
			copy(entries, entries[len(entries)-limit:])
			entries = entries[:limit]
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read metrics history: %w", err)
	}
	return entries, nil
}

func appendPersistentSnapshot(path string, snapshot Snapshot, rewrite bool, history []Snapshot) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create metrics state directory: %w", err)
	}
	if rewrite {
		temporary := path + ".tmp"
		file, err := os.OpenFile(temporary, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(file)
		for _, item := range history {
			if err := encoder.Encode(item); err != nil {
				_ = file.Close()
				_ = os.Remove(temporary)
				return err
			}
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			_ = os.Remove(temporary)
			return err
		}
		if err := file.Close(); err != nil {
			_ = os.Remove(temporary)
			return err
		}
		if err := os.Rename(temporary, path); err != nil {
			_ = os.Remove(temporary)
			return err
		}
		return nil
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	err = json.NewEncoder(file).Encode(snapshot)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	return err
}

func snapshotFrom(raw, previous Raw) Snapshot {
	s := Snapshot{
		Timestamp: raw.Timestamp, Load1: raw.Load1, Load5: raw.Load5, Load15: raw.Load15,
		MemoryTotalBytes: raw.MemoryTotalKB << 10, MemoryFreeBytes: raw.MemoryAvailableKB << 10,
		SwapTotalBytes: raw.SwapTotalKB << 10, SwapFreeBytes: raw.SwapFreeKB << 10,
		DiskTotalBytes: raw.DiskTotalBytes, DiskFreeBytes: raw.DiskFreeBytes,
		TemperatureC: raw.TemperatureC, UptimeSeconds: raw.UptimeSeconds,
		WANInterface: raw.WANInterface, RXBytes: raw.RXBytes, TXBytes: raw.TXBytes,
	}
	s.MemoryUsedPercent = usedPercent(s.MemoryTotalBytes, s.MemoryFreeBytes)
	s.DiskUsedPercent = usedPercent(s.DiskTotalBytes, s.DiskFreeBytes)
	if !previous.Timestamp.IsZero() && raw.CPUCounters.Total >= previous.CPUCounters.Total && raw.CPUCounters.Idle >= previous.CPUCounters.Idle {
		totalDelta := raw.CPUCounters.Total - previous.CPUCounters.Total
		idleDelta := raw.CPUCounters.Idle - previous.CPUCounters.Idle
		if totalDelta > 0 && idleDelta <= totalDelta {
			s.CPUReady = true
			s.CPUPercent = round2(100 * float64(totalDelta-idleDelta) / float64(totalDelta))
		}
	}
	seconds := raw.Timestamp.Sub(previous.Timestamp).Seconds()
	if !previous.Timestamp.IsZero() && seconds > 0 && raw.WANInterface != "" && raw.WANInterface == previous.WANInterface {
		if raw.RXBytes >= previous.RXBytes && raw.TXBytes >= previous.TXBytes {
			s.TrafficReady = true
			s.RXBytesPerSecond = round2(float64(raw.RXBytes-previous.RXBytes) / seconds)
			s.TXBytesPerSecond = round2(float64(raw.TXBytes-previous.TXBytes) / seconds)
		} else {
			s.CounterReset = true
		}
	}
	return s
}

func usedPercent(total, free uint64) float64 {
	if total == 0 || free > total {
		return 0
	}
	return round2(100 * float64(total-free) / float64(total))
}

func round2(value float64) float64 { return math.Round(value*100) / 100 }

func readCPU(path string) CPUCounters {
	data, err := os.ReadFile(path)
	if err != nil {
		return CPUCounters{}
	}
	line := strings.SplitN(string(data), "\n", 2)[0]
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return CPUCounters{}
	}
	values := make([]uint64, 0, len(fields)-1)
	for _, field := range fields[1:] {
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return CPUCounters{}
		}
		values = append(values, value)
	}
	var total uint64
	for _, value := range values {
		total += value
	}
	idle := values[3]
	if len(values) > 4 {
		idle += values[4]
	}
	return CPUCounters{Total: total, Idle: idle}
}

func readLoad(path string) (float64, float64, float64) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return 0, 0, 0
	}
	return parseFloat(fields[0]), parseFloat(fields[1]), parseFloat(fields[2])
}

func readMemory(path string) (total, available, swapTotal, swapFree uint64) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, 0, 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, _ := strconv.ParseUint(fields[1], 10, 64)
		switch strings.TrimSuffix(fields[0], ":") {
		case "MemTotal":
			total = value
		case "MemAvailable":
			available = value
		case "SwapTotal":
			swapTotal = value
		case "SwapFree":
			swapFree = value
		}
	}
	return
}

func readTemperature(root string) float64 {
	paths, _ := filepath.Glob(filepath.Join(root, "thermal_zone*", "temp"))
	max := float64(0)
	for _, path := range paths {
		value := readFirstFloat(path)
		if value > 1000 {
			value /= 1000
		}
		if value > max && value < 200 {
			max = value
		}
	}
	return round2(max)
}

func readFirstFloat(path string) float64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	return parseFloat(fields[0])
}

func parseFloat(value string) float64 {
	parsed, _ := strconv.ParseFloat(value, 64)
	return parsed
}

func readUint(path string) uint64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	value, _ := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	return value
}

var errDiskUnsupported = errors.New("disk usage is unsupported on this platform")
