package awgprofile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const maxToolBytes = 64 << 20

var awgToolIdentity = regexp.MustCompile(`^amneziawg-tools v[0-9]+\.[0-9]+\.[0-9]+(?: - https://amnezia\.org)?$`)

// kbuild has a 25-byte srcversion buffer. Versions using snprintf with
// sizeof(srcversion)-1 emit 23 hex characters; older emitters use 24.
// This is only a format bound: the loaded and installed values must still match.
var moduleSourceIdentity = regexp.MustCompile(`^[A-Fa-f0-9]{23,24}$`)
var moduleVersionIdentity = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
var kernelReleaseIdentity = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,159}$`)
var kernelTaintIdentity = regexp.MustCompile(`^[0-9]{1,20}$`)
var toolDigestIdentity = regexp.MustCompile(`^[a-f0-9]{64}$`)

type runtimeInspector struct {
	read func(string) string
	look func(string) (string, error)
	run  func(context.Context, string, ...string) (string, error)
	hash func(context.Context, string) (string, error)
}

func nativeRuntimeInspector() runtimeInspector {
	return runtimeInspector{read: readVersion, look: resolveToolPath, hash: hashTool, run: func(ctx context.Context, tool string, args ...string) (string, error) {
		commandCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		var output cappedBuffer
		command := exec.CommandContext(commandCtx, tool, args...)
		command.Stdout, command.Stderr = &output, &output
		if err := command.Run(); err != nil {
			return "", errors.New("AWG read-only command failed")
		}
		return output.text.String(), commandCtx.Err()
	}}
}

func resolveToolPath(tool string) (string, error) {
	path, err := exec.LookPath(tool)
	if err != nil {
		return "", err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(path)
}

func hashTool(ctx context.Context, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("AWG executable is unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxToolBytes {
		return "", errors.New("AWG executable is not a bounded regular file")
	}
	hash := sha256.New()
	buffer := make([]byte, 32<<10)
	reader := io.LimitReader(f, maxToolBytes+1)
	total := 0
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, err := reader.Read(buffer)
		total += n
		if total > maxToolBytes {
			return "", errors.New("AWG executable exceeds bound")
		}
		_, _ = hash.Write(buffer[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", errors.New("AWG executable inspection failed")
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

type loadedRuntime struct {
	kernel, version, source, initState, moduleTaint, kernelTaint string
}

func readLoadedRuntime(read func(string) string) loadedRuntime {
	return loadedRuntime{read("/proc/sys/kernel/osrelease"), read("/sys/module/amneziawg/version"), read("/sys/module/amneziawg/srcversion"), read("/sys/module/amneziawg/initstate"), read("/sys/module/amneziawg/taint"), read("/proc/sys/kernel/tainted")}
}

func inspectRuntime(parent context.Context, tools []string, inspect runtimeInspector) Capabilities {
	ctx, cancel := context.WithTimeout(parent, 7*time.Second)
	defer cancel()
	c := Capabilities{Backend: "kernel", Note: "Read-only проверка CLI и загруженного модуля по srcversion/vermagic текущего ядра. Модули не загружаются; сервер и роутер требуют отдельного испытания."}
	loaded := readLoadedRuntime(inspect.read)
	c.Kernel, c.LoadedModuleVersion, c.LoadedSourceVersion = loaded.kernel, loaded.version, loaded.source
	c.ModuleInitState, c.ModuleTaint, c.KernelTaint = loaded.initState, loaded.moduleTaint, loaded.kernelTaint
	c.ModuleLoaded = loaded.version != "" && loaded.initState == "live"
	for _, tool := range tools {
		path, err := inspect.look(tool)
		if err != nil {
			continue
		}
		c.ToolPath = path
		c.ToolSHA256, err = inspect.hash(ctx, path)
		if err == nil {
			if output, err := inspect.run(ctx, path, "--version"); err == nil {
				c.ToolVersion = safeVersion(output)
			}
		}
		break
	}
	if modinfo, err := inspect.look("modinfo"); err == nil {
		if output, err := inspect.run(ctx, modinfo, "amneziawg"); err == nil {
			if values, err := parseModuleInfo(output); err == nil {
				c.ModuleName, c.ModuleVersion = values["name"], values["version"]
				c.ModuleSourceVersion, c.ModuleVermagic = values["srcversion"], values["vermagic"]
			}
		}
	}
	if loaded != readLoadedRuntime(inspect.read) {
		c.ModuleLoaded = false
		c.Note = "AWG runtime изменился во время read-only проверки; нужна новая проверка."
	}
	if c.ToolPath != "" {
		if current, err := inspect.hash(ctx, c.ToolPath); err != nil || current != c.ToolSHA256 {
			c.ToolSHA256 = ""
		}
	}
	c.CompatibilityVerified = ctx.Err() == nil && len(CheckRuntime(Preview{MinimumMajor: 1}, c)) == 0
	c.SupportsAWG31 = ctx.Err() == nil && len(CheckRuntime(Preview{MinimumMajor: 3, MinimumMinor: 1}, c)) == 0
	return c
}

func parseModuleInfo(output string) (map[string]string, error) {
	if len(output) > 4096 || strings.ContainsRune(output, 0) {
		return nil, errors.New("AWG module metadata exceeds bound")
	}
	values := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || (key != "name" && key != "version" && key != "srcversion" && key != "vermagic") {
			continue
		}
		if _, duplicate := values[key]; duplicate {
			return nil, errors.New("AWG module metadata is ambiguous")
		}
		values[key] = safeVersion(value)
	}
	return values, nil
}

// CheckRuntime is the stricter admission gate for every AWG profile, including
// older profiles. Check remains the existing version-only preview API; callers
// must not infer runtime readiness from it or from SupportsAWG31 alone.
func CheckRuntime(p Preview, c Capabilities) []Issue {
	issues := Check(p, c)
	if p.MinimumMajor < 3 {
		if c.Backend != "kernel" || !c.ModuleLoaded || !atLeast(c.LoadedModuleVersion, p.MinimumMajor, p.MinimumMinor) || !atLeast(c.ToolVersion, p.MinimumMajor, p.MinimumMinor) {
			issues = append(issues, Issue{"AWG_RUNTIME_UNSUPPORTED", "", "Не подтверждена версия загруженного kernel backend и CLI для этого AWG профиля."})
		}
	}
	if !filepath.IsAbs(c.ToolPath) || !awgToolIdentity.MatchString(c.ToolVersion) || !toolDigestIdentity.MatchString(c.ToolSHA256) {
		issues = append(issues, Issue{"AWG_TOOL_IDENTITY_UNVERIFIED", "", "Не подтверждены точный awg CLI и SHA256 его файла."})
	}
	if !c.ModuleLoaded || c.ModuleInitState != "live" || c.ModuleName != "amneziawg" || !moduleVersionIdentity.MatchString(c.LoadedModuleVersion) || c.ModuleVersion != c.LoadedModuleVersion || !moduleSourceIdentity.MatchString(c.LoadedSourceVersion) || c.LoadedSourceVersion != c.ModuleSourceVersion {
		issues = append(issues, Issue{"AWG_MODULE_IDENTITY_UNVERIFIED", "", "modinfo не совпадает с реально загруженным amneziawg по version/srcversion/initstate."})
	}
	vermagic := strings.Fields(c.ModuleVermagic)
	taint, err := strconv.ParseUint(c.KernelTaint, 10, 64)
	if !kernelReleaseIdentity.MatchString(c.Kernel) || len(vermagic) < 2 || vermagic[0] != c.Kernel || !kernelTaintIdentity.MatchString(c.KernelTaint) || err != nil || taint&(2|8) != 0 || strings.ContainsAny(c.ModuleTaint, "FR") {
		issues = append(issues, Issue{"AWG_KERNEL_ABI_UNVERIFIED", "", "Не подтверждена связь loaded module с текущим ядром либо обнаружена принудительная загрузка/выгрузка модуля."})
	}
	return issues
}

// VerifyTool rechecks the exact executable immediately before adapter effects.
// No profile material is supplied to the executable during this inspection.
func VerifyTool(ctx context.Context, c Capabilities, selected string) (string, error) {
	path, err := resolveToolPath(selected)
	if err != nil || path != c.ToolPath || !toolDigestIdentity.MatchString(c.ToolSHA256) {
		return "", errors.New("AWG capability receipt belongs to another or unavailable executable")
	}
	digest, err := hashTool(ctx, path)
	if err != nil || digest != c.ToolSHA256 {
		return "", errors.New("AWG executable changed since capability inspection")
	}
	return path, ctx.Err()
}
