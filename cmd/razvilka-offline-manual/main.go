// razvilka-offline-manual is a single-purpose, incident-bound operator tool.
// It has no daemon entry point and never installs itself or starts the panel.
package main

import (
	"context"
	"encoding/json"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var sourceCommit = "development"

func main() {
	result := newResult()
	code := 3
	if len(os.Args) != 2 || os.Args[1] != "save-manual" {
		result.Stage = "exact-save-manual-command-required"
	} else if nativeOperatorPlatform() != nil {
		result.Stage = "linux-arm64-root-required"
	} else {
		parent, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		ctx, cancel := context.WithTimeout(parent, 90*time.Second)
		var err error
		result, err = runOperator(ctx, productionPaths(), productionIncident(), nil)
		cancel()
		stop()
		if err == nil {
			code = 0
		}
	}
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		code = 3
	}
	os.Exit(code)
}
