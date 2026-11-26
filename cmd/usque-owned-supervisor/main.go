package main

import (
	"github.com/ArtixSx/razvilka/internal/usquediag/nativeowner"
	"os"
)

func main() {
	if len(os.Args) != 1 {
		os.Exit(125)
	}
	os.Exit(nativeowner.RunSupervisor())
}
