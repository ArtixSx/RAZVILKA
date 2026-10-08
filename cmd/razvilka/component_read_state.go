package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/app"
	"github.com/ArtixSx/razvilka/internal/components"
)

const productionComponentStateDirectory = "/opt/var/lib/razvilka/components"

var errComponentReadState = errors.New("retained component state is unreadable; preserve journals, receipts and generations")

func checkComponentReadState(ctx context.Context, state string, reader int) error {
	if ctx == nil || reader < 1 || reader > app.ManagedComponentReadVersion {
		return errComponentReadState
	}
	required, err := components.RequiredRetainedManagedUpdateReadVersion(ctx, state)
	if err != nil || required > reader || ctx.Err() != nil {
		return errors.Join(errComponentReadState, err, ctx.Err())
	}
	return nil
}

// Exact standalone metadata cannot recurse into retained-controller probes or
// open application stores. The state command reads fixed deployment coordinates
// before any normal startup and never initializes or repairs missing files.
func runComponentReadCommand(args []string, state string) (bool, int) {
	command := ""
	for _, arg := range args {
		name, _, _ := strings.Cut(arg, "=")
		if strings.HasPrefix(name, "--") {
			name = strings.TrimPrefix(name, "-")
		}
		if name == "-component-update-schema" || name == "-check-component-update-state" {
			command = name
		}
	}
	if command == "" {
		return false, 0
	}
	if len(args) != 1 || args[0] != command {
		fmt.Fprintln(os.Stderr, "component reader command requires its exact standalone flag")
		return true, 2
	}
	if command == "-component-update-schema" {
		fmt.Println(app.ManagedComponentReadVersion)
		return true, 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if checkComponentReadState(ctx, state, app.ManagedComponentReadVersion) != nil {
		fmt.Fprintln(os.Stderr, errComponentReadState)
		return true, 3
	}
	fmt.Println(`{"ok":true}`)
	return true, 0
}
