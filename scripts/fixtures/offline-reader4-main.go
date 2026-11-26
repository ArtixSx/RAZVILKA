//go:build razvilka_historical_reader_fixture

// Copy this fixture entry point into the pinned historical checkout, then
// compile against that checkout's UNMODIFIED selfupdatejournal package.
// It is a library compatibility probe, not the historical application main.
// The immutable archive reader is explicitly modeled; real receipt formats,
// pointer decoding, retained images and required-version scanning are used.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

func main() { os.Exit(run()) }

func run() int {
	if len(os.Args) != 4 || selfupdatejournal.ReadVersion != 4 {
		return 2
	}
	mode, installation, journal := os.Args[1], os.Args[2], os.Args[3]
	if (mode != "paired4" && mode != "pending5") || !filepath.IsAbs(installation) || !filepath.IsAbs(journal) || filepath.Clean(installation) != installation || filepath.Clean(journal) != journal {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	store, err := selfupdatejournal.OpenWithPairedEvidence(installation, journal, func(c context.Context, r selfupdatejournal.Receipt, pending string, formatOnly bool) error {
		if c != ctx || r.Schema != 4 || r.Paired == nil || pending != "" || !formatOnly {
			return selfupdatejournal.ErrMismatch
		}
		return c.Err()
	})
	if err != nil {
		return 3
	}
	defer store.Close()
	receipt, present, currentErr := store.Current()
	required, requiredErr := store.RequiredReadVersion(ctx)
	if ctx.Err() != nil {
		return 4
	}
	if mode == "paired4" {
		if currentErr != nil || !present || receipt.Schema != 4 || requiredErr != nil || required != 4 {
			return 4
		}
		fmt.Println("historical-library-reader4 paired4 readable")
	} else {
		if !errors.Is(currentErr, selfupdatejournal.ErrMismatch) || !errors.Is(requiredErr, selfupdatejournal.ErrMismatch) {
			return 4
		}
		fmt.Println("historical-library-reader4 pending5 refused")
	}
	return 0
}
