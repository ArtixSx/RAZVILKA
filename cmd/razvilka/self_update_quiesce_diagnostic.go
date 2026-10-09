package main

import (
	"fmt"
	"os"

	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

func refuseSelfUpdateRuntimeQuiesce(stage string) int {
	fmt.Fprintln(os.Stderr, updatecheck.RuntimeQuiesceFailureOutput(stage))
	return 3
}
