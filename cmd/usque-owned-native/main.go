package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/ArtixSx/razvilka/internal/usquediag/nativeaccept"
)

// Pending concrete CORE original-execution factory. There is deliberately no
// ambient controller, mutable registration hook or flag/receipt-based issuer.
func retainedCOREIssuer() nativeaccept.Issuer { return nil }

func execute(ctx context.Context, args []string, output io.Writer) int {
	r, err := nativeaccept.ParseArguments(args)
	if errors.Is(err, flag.ErrHelp) {
		_, _ = fmt.Fprint(output, nativeaccept.Usage)
		return 0
	}
	var result nativeaccept.Result
	if err != nil {
		code := "arguments-invalid"
		if err.Error() == "opt-in-required" {
			code = "opt-in-required"
		}
		result = nativeaccept.Result{Status: "failed", Code: code, Settlement: "not-acquired", SecretCleanup: "not-staged"}
	} else {
		result = nativeaccept.Run(ctx, r, retainedCOREIssuer())
	}
	if json.NewEncoder(output).Encode(result) != nil {
		return 1
	}
	return result.ExitCode()
}

func main() {
	ctx, done := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer done()
	os.Exit(execute(ctx, os.Args[1:], os.Stdout))
}
