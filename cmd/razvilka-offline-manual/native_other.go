//go:build !linux

package main

import (
	"context"
	"os"
)

func nativeOperatorPlatform() error            { return errRefused }
func ownerOK(os.FileInfo) bool                 { return false }
func readOnlyFileFlags() int                   { return os.O_RDONLY }
func checkOperatorPaths(paths) error           { return errRefused }
func panelAbsent(context.Context, paths) error { return errRefused }
