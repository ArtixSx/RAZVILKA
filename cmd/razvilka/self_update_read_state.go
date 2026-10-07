package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

var errSelfUpdateJournalState = errors.New("retained self update journal compatibility is unavailable; preserve retained files")

// These coordinates come from the fixed deployment, never public flags or
// environment overrides. Tests pass private fixture coordinates explicitly.
type selfUpdateJournalRoots struct {
	installation, helper, files string
}

func productionSelfUpdateJournalRoots() selfUpdateJournalRoots {
	return selfUpdateJournalRoots{
		installation: selfUpdateDefaultPath("/opt"),
		helper:       selfUpdateDefaultPath("/opt/var/lib/razvilka/self-update"),
		files:        selfUpdateDefaultPath("/opt/var/lib/razvilka/self-update-files"),
	}
}

// This checks only retained formats/images. It grants no Start, replacement,
// settlement or Resume authority and never probes a controller executable.
func checkSelfUpdateJournalState(ctx context.Context, roots selfUpdateJournalRoots, reader int) error {
	if ctx == nil || ctx.Err() != nil || reader < 1 || reader > updatecheck.SelfUpdateReadVersion {
		return errSelfUpdateJournalState
	}
	for _, root := range []string{roots.installation, roots.helper, roots.files} {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == filepath.VolumeName(root)+string(filepath.Separator) {
			return errSelfUpdateJournalState
		}
	}
	required, err := updatecheck.RequiredSelfUpdateJournalReadVersion(ctx, roots.installation, roots.helper, roots.files)
	if err != nil || required < 1 || required > reader || ctx.Err() != nil {
		return errSelfUpdateJournalState
	}
	return nil
}

func boundedSelfUpdateJournalState(ctx context.Context, roots selfUpdateJournalRoots) error {
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return checkSelfUpdateJournalState(bounded, roots, updatecheck.SelfUpdateReadVersion)
}

func allowSelfUpdateJournalCommand(roots selfUpdateJournalRoots) bool {
	if boundedSelfUpdateJournalState(context.Background(), roots) != nil {
		fmt.Fprintln(os.Stderr, errSelfUpdateJournalState)
		return false
	}
	return true
}

// Exact standalone metadata is handled before any startup/helper gate. A
// scanner or retained controller calling this immutable flag cannot recurse
// into the scanner, acquire admission, open a Store or clear durable Stop.
func runSelfUpdateJournalReadCommand(args []string, roots selfUpdateJournalRoots) (bool, int) {
	command := ""
	for _, arg := range args {
		name, _, _ := strings.Cut(arg, "=")
		if strings.HasPrefix(name, "--") {
			name = strings.TrimPrefix(name, "-")
		}
		if name == "-self-update-read-version" || name == "-check-self-update-state" {
			command = name
		}
	}
	if command == "" {
		return false, 0
	}
	if len(args) != 1 || args[0] != command {
		fmt.Fprintln(os.Stderr, "self update reader command requires its exact standalone flag")
		return true, 2
	}
	if command == "-self-update-read-version" {
		fmt.Println(updatecheck.SelfUpdateReadVersion)
		return true, 0
	}
	if !allowSelfUpdateJournalCommand(roots) {
		return true, 3
	}
	fmt.Println(`{"ok":true}`)
	return true, 0
}
