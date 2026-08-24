package strategylab

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	MinAvailableMemoryKB      = 32 * 1024
	MinAvailableMemoryPercent = 8
	MaxLoadPerCPU             = 2.0
	ProbeTimeout              = 15 * time.Second
)

// ResourceBudget is a read-only gate for the temporary NFQWS2 process used by
// Strategy Lab. Missing metrics do not block a probe, but known unsafe values
// do. That keeps desktop development usable while protecting Entware routers.
type ResourceBudget struct {
	Observed               bool    `json:"observed"`
	Allowed                bool    `json:"allowed"`
	Reason                 string  `json:"reason"`
	MemoryTotalKB          uint64  `json:"memory_total_kb,omitempty"`
	MemoryAvailableKB      uint64  `json:"memory_available_kb,omitempty"`
	MemoryAvailablePercent int     `json:"memory_available_percent,omitempty"`
	Load1                  float64 `json:"load_1,omitempty"`
	CPUCount               int     `json:"cpu_count,omitempty"`
	TimeoutMS              int64   `json:"timeout_ms"`
}

type ResourceInspector interface {
	Inspect() ResourceBudget
}

type SystemResourceInspector struct {
	MeminfoPath string
	LoadavgPath string
}

func (s SystemResourceInspector) Inspect() ResourceBudget {
	meminfoPath := s.MeminfoPath
	if meminfoPath == "" {
		meminfoPath = "/proc/meminfo"
	}
	loadavgPath := s.LoadavgPath
	if loadavgPath == "" {
		loadavgPath = "/proc/loadavg"
	}
	budget := ResourceBudget{Allowed: true, CPUCount: runtime.NumCPU(), TimeoutMS: ProbeTimeout.Milliseconds()}
	if data, err := os.ReadFile(meminfoPath); err == nil {
		budget.MemoryTotalKB, budget.MemoryAvailableKB = parseMemory(string(data))
		budget.Observed = budget.MemoryTotalKB > 0 || budget.MemoryAvailableKB > 0
		if budget.MemoryTotalKB > 0 {
			budget.MemoryAvailablePercent = int(budget.MemoryAvailableKB * 100 / budget.MemoryTotalKB)
		}
	}
	if data, err := os.ReadFile(loadavgPath); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			if value, parseErr := strconv.ParseFloat(fields[0], 64); parseErr == nil {
				budget.Load1 = value
				budget.Observed = true
			}
		}
	}
	return evaluateResourceBudget(budget)
}

func parseMemory(raw string) (total, available uint64) {
	for _, line := range strings.Split(raw, "\n") {
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
		}
	}
	return
}

func evaluateResourceBudget(budget ResourceBudget) ResourceBudget {
	budget.Allowed = true
	if budget.TimeoutMS <= 0 {
		budget.TimeoutMS = ProbeTimeout.Milliseconds()
	}
	if budget.MemoryTotalKB > 0 {
		budget.MemoryAvailablePercent = int(budget.MemoryAvailableKB * 100 / budget.MemoryTotalKB)
	}
	if !budget.Observed {
		budget.Reason = "Метрики ресурсов недоступны; действует строгий лимит времени."
		return budget
	}
	if budget.MemoryAvailableKB > 0 && budget.MemoryAvailableKB < MinAvailableMemoryKB {
		budget.Allowed = false
		budget.Reason = "Недостаточно свободной RAM для временного процесса NFQWS2."
		return budget
	}
	if budget.MemoryTotalKB > 0 && budget.MemoryAvailablePercent < MinAvailableMemoryPercent {
		budget.Allowed = false
		budget.Reason = "Свободно менее 8% RAM; дождитесь снижения нагрузки."
		return budget
	}
	if budget.CPUCount > 0 && budget.Load1 > float64(budget.CPUCount)*MaxLoadPerCPU {
		budget.Allowed = false
		budget.Reason = "Системная нагрузка слишком высока для изолированного подбора."
		return budget
	}
	budget.Reason = "Ресурсов достаточно; тест ограничен по времени и выполняется последовательно."
	return budget
}
