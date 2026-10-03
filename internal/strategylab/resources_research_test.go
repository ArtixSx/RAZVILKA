package strategylab

import "testing"

func TestResearchMemoryFallbackForOldKernels(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       uint64
	}{
		{"old kernel", "MemTotal: 131072 kB\nMemFree: 49152 kB\nBuffers: 999999 kB\nCached: 999999 kB\n", 49152},
		{"modern", "MemTotal: 131072 kB\nMemFree: 49152 kB\nMemAvailable: 80000 kB\n", 80000},
		{"observed zero", "MemTotal: 131072 kB\nMemFree: 49152 kB\nMemAvailable: 0 kB\n", 0},
		{"malformed available", "MemTotal: 131072 kB\nMemFree: 49152 kB\nMemAvailable: bad kB\n", 49152},
	} {
		t.Run(tc.name, func(t *testing.T) {
			total, avail := parseMemory(tc.body)
			if total != 131072 || avail != tc.want {
				t.Fatal(total, avail)
			}
		})
	}
}
func TestResearchFallbackDoesNotRelaxOOMGuard(t *testing.T) {
	total, avail := parseMemory("MemTotal: 131072 kB\nMemFree: 2048 kB\n")
	b := evaluateResourceBudget(ResourceBudget{Observed: true, MemoryTotalKB: total, MemoryAvailableKB: avail, CPUCount: 2})
	if b.Allowed {
		t.Fatal("low memory allowed")
	}
	total, avail = parseMemory("MemTotal: 131072 kB\nMemFree: 49152 kB\n")
	b = evaluateResourceBudget(ResourceBudget{Observed: true, MemoryTotalKB: total, MemoryAvailableKB: avail, CPUCount: 2})
	if !b.Allowed {
		t.Fatal("old-kernel missing MemAvailable incorrectly denies probe")
	}
}
