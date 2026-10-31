package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/ArtixSx/razvilka/internal/dataplane"
)

// Metadata is handled before every store, startup/helper gate or initializer.
func runExecutionReadCommand(args []string) (bool, int) {
	const flag = "-dataplane-execution-read-version"
	found := false
	for _, arg := range args {
		name, _, _ := strings.Cut(arg, "=")
		if strings.TrimPrefix(name, "-") == strings.TrimPrefix(flag, "-") || name == "-"+flag {
			found = true
		}
	}
	if !found {
		return false, 0
	}
	if len(args) != 1 || args[0] != flag {
		fmt.Fprintln(os.Stderr, "execution reader requires its exact standalone flag")
		return true, 2
	}
	fmt.Println(dataplane.ExecutionReadVersion)
	return true, 0
}
