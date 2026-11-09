//go:build linux && razvilka_native_fixture

package startuptools

import (
	"context"
	"fmt"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// Diagnostic only, after the real acquisition has already refused and closed.
// Never inspect Error text, paths, command output or arbitrary stage strings.
func nativeFixtureAcquireDiagnostic(err error) {
	fmt.Printf("actual_native_tools_acquire failed=true stages=%s\n", nativeFixtureAcquireStages(err))
}

func nativeFixtureAcquireStages(err error) string {
	labels := []string{}
	pending := []error{err}
	add := func(label string) {
		if len(labels) < 16 && !slices.Contains(labels, label) {
			labels = append(labels, label)
		}
	}
	visited := 0
	for len(pending) > 0 && visited < 64 && len(labels) < 16 {
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		visited++
		if current == nil {
			continue
		}
		if f, ok := current.(*failure); ok {
			if f == nil {
				continue
			}
			add(nativeFixtureAcquireStage(f.stage))
		}
		if exited, ok := current.(*exec.ExitError); ok && exited != nil {
			if code := exited.ExitCode(); code >= 0 && code <= 255 {
				add("EXIT_RC_" + strconv.Itoa(code))
			} else {
				add("EXIT_SIGNAL_OR_UNKNOWN")
			}
		}
		switch current {
		case context.Canceled:
			add("CANCELED")
		case context.DeadlineExceeded:
			add("DEADLINE")
		case ErrUnknown:
			add("TOOLS_UNKNOWN")
		case netidentity.ErrUnknown:
			add("NET_IDENTITY_UNKNOWN")
		case syscall.ENOENT:
			add("ENOENT")
		case syscall.EACCES:
			add("EACCES")
		case syscall.EPERM:
			add("EPERM")
		case syscall.EBADF:
			add("EBADF")
		case syscall.EIO:
			add("EIO")
		}
		remaining := 64 - len(pending)
		switch wrapped := current.(type) {
		case interface{ Unwrap() []error }:
			children := wrapped.Unwrap()
			n := min(len(children), remaining)
			for i := n - 1; i >= 0; i-- {
				pending = append(pending, children[i])
			}
			if n < len(children) {
				add("TRUNCATED")
			}
		case interface{ Unwrap() error }:
			if remaining > 0 {
				pending = append(pending, wrapped.Unwrap())
			}
		}
	}
	if len(pending) > 0 {
		add("TRUNCATED")
	}
	if len(labels) == 0 {
		return "UNCLASSIFIED"
	}
	return strings.Join(labels, "/")
}

func nativeFixtureAcquireStage(stage string) string {
	switch stage {
	case "ACQUIRE", "ACQUIRE_PLATFORM", "ACQUIRE_IDENTITY", "CHECK_CONTEXT", "CHECK_PATH", "CHECK_LINK", "CHECK_ABSENCE", "CHECK_HELD_FILE", "CHECK_BYTES", "CHECK_EXTENSIONS", "CHECK_EXTENSION_SET", "CHECK_DIRECTORY_PATH", "CHECK_IDENTITY",
		"PATH_LINK", "PATH_CHANGED", "PATH_COUNT", "PATH_FORM", "PATH_LINK_COUNT", "PATH_PARENT", "ABSENCE_PARENT", "ABSENCE_CHANGED", "ABSENCE_COUNT",
		"IMAGE_EDGES", "IMAGE_LIBRARY_ROOT", "IMAGE_COUNT", "IMAGE_BOUNDS", "IMAGE_OPEN", "IMAGE_OPEN_CHANGED", "IMAGE_EXECUTABLE", "IMAGE_ELF", "ENTRY_LOADER", "ENTRY_LOADER_IMAGE", "DEPENDENCY_LOOKUP", "DEPENDENCY_MISSING", "DEPENDENCY_IMAGE", "LIBRARY_DIRECTORY", "LOADER_VARIANT", "MAIN_PATH", "MAIN_PIN", "BACKEND_PIN", "IP_MAIN_PATH", "IP_MAIN_PIN", "EXTENSION_DIRECTORY", "EXTENSION_OPEN", "EXTENSION_COUNT", "EXTENSION_FORM", "EXTENSION_IMAGE", "LOADER_PRELOAD", "DIRECTORY_OPEN", "DIRECTORY_CHANGED",
		"VERSION", "VERSION_RESULT", "BACKEND_VERSION", "IP_VERSION", "IP_VERSION_RESULT", "COMMAND_SCOPE", "COMMAND_RESULT", "COMMAND_STDOUT_LIMIT", "COMMAND_STDERR_LIMIT", "COMMAND_STDERR_NONEMPTY":
		return stage
	}
	for _, category := range []string{"ROOT", "OPT", "OPT_ETC", "ETC", "IP_NAMES_ROOT", "TOOL_PARENT", "LIBRARY_ROOT", "EXTENSION_ROOT", "XTABLES_ENTRY", "IP_ENTRY", "LOADER_ENTRY", "EXTENSION_PATH", "LIBRARY_PATH", "OTHER_PROTECTED_PATH"} {
		for _, reason := range []string{"STAT", "MISSING", "UID", "WRITE_MODE", "SETID"} {
			if stage == "PATH_OWNER_"+category+"_"+reason {
				return stage
			}
		}
	}
	return "TOOLS_STAGE_UNCLASSIFIED"
}
