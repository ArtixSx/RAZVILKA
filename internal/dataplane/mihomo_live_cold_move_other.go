//go:build !linux

package dataplane

import "os"

func mihomoColdRenameNoReplace(*os.File, *os.File) error { return ErrMihomoLiveRetirement }
