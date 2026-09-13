package awgprofile

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Capabilities struct {
	Backend             string `json:"backend"`
	Kernel              string `json:"kernel"`
	LoadedModuleVersion string `json:"loaded_module_version"`
	ToolPath            string `json:"tool_path"`
	ToolVersion         string `json:"tool_version"`
	ModuleLoaded        bool   `json:"module_loaded"`
	SupportsAWG31       bool   `json:"supports_awg31"`
	// None of these inventory facts is network or model/firmware HIL evidence.
	HardwareVerified bool   `json:"hardware_verified"`
	Note             string `json:"note"`
}

// Detect performs bounded read-only inspection. It never insmods a .ko or runs
// a downloaded installer. Installed-on-disk is deliberately not loaded-ready.
func Detect(ctx context.Context) Capabilities {
	return detectTools(ctx, []string{"/opt/sbin/awg", "/opt/bin/awg", "/opt/usr/bin/awg", "/usr/bin/awg", "awg"})
}

// DetectTool checks the exact CLI selected by the adapter, including an
// explicit installation override. Another installed awg cannot vouch for it.
func DetectTool(ctx context.Context, tool string) Capabilities {
	return detectTools(ctx, []string{tool})
}

func detectTools(ctx context.Context, tools []string) Capabilities {
	c := Capabilities{Backend: "kernel", Note: "Проверяются загруженный amneziawg и локальный awg. Пакеты и модули не устанавливаются; испытание роутера требуется отдельно."}
	c.Kernel = readVersion("/proc/sys/kernel/osrelease")
	c.LoadedModuleVersion = readVersion("/sys/module/amneziawg/version")
	c.ModuleLoaded = c.LoadedModuleVersion != ""
	for _, path := range tools {
		p, e := exec.LookPath(path)
		if e != nil {
			continue
		}
		c.ToolPath = p
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		var b cappedBuffer
		cmd := exec.CommandContext(ctx, p, "--version")
		cmd.Stdout = &b
		cmd.Stderr = &b
		err := cmd.Run()
		cancel()
		if err == nil {
			c.ToolVersion = safeVersion(b.text.String())
		}
		break
	}
	c.SupportsAWG31 = atLeast(c.LoadedModuleVersion, 3, 1) && atLeast(c.ToolVersion, 3, 1)
	return c
}

type cappedBuffer struct{ text strings.Builder }

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.text.Len()+len(p) > 4096 {
		return 0, fmt.Errorf("version output limit")
	}
	return b.text.Write(p)
}
func readVersion(path string) string {
	f, e := os.Open(path)
	if e != nil {
		return ""
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 4097))
	if e != nil || len(b) > 4096 {
		return ""
	}
	return safeVersion(string(b))
}
func safeVersion(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 160 || strings.ContainsAny(s, "\r\n\x00") {
		return ""
	}
	return s
}

var versionPattern = regexp.MustCompile(`(?:^|[v\s])([0-9]+)\.([0-9]+)(?:\.|$|\s)`)

func version(s string) (int, int, bool) {
	m := versionPattern.FindStringSubmatch(s)
	if len(m) < 3 {
		return 0, 0, false
	}
	a, e := strconv.Atoi(m[1])
	b, f := strconv.Atoi(m[2])
	return a, b, e == nil && f == nil
}
func atLeast(s string, major, minor int) bool {
	a, b, ok := version(s)
	return ok && (a > major || a == major && b >= minor)
}

// Check uses *both* actually loaded module and parsing tool for advanced
// profiles. A displayed/shipped version never authorizes unsupported keys.
func Check(p Preview, c Capabilities) []Issue {
	issues := []Issue{}
	if c.ToolPath == "" {
		issues = append(issues, Issue{"AWG_TOOL_MISSING", "", "Не найдена утилита awg. Установка AWG Manager целиком не выполняется."})
	}
	if p.MinimumMajor < 3 {
		return issues
	}
	if c.Backend != "kernel" {
		issues = append(issues, Issue{"AWG_BACKEND_UNSUPPORTED", "", "Этот кандидат поддерживает AWG 3.x только через нативный kernel backend."})
	}
	if !c.ModuleLoaded || !atLeast(c.LoadedModuleVersion, p.MinimumMajor, p.MinimumMinor) {
		issues = append(issues, Issue{"AWG_MODULE_UNSUPPORTED", "", "Нужен загруженный совместимый amneziawg. Файл новой версии на диске недостаточен."})
	}
	if !atLeast(c.ToolVersion, p.MinimumMajor, p.MinimumMinor) {
		issues = append(issues, Issue{"AWG_TOOL_UNSUPPORTED", "", "Версия awg не подтверждает поддержку всех параметров профиля."})
	}
	return issues
}
