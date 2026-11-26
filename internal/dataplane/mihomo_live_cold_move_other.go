//go:build !linux

package dataplane

import "os"

func mihomoColdRenameNoReplace(*os.File, *os.File) error { return ErrMihomoLiveRetirement }

func mihomoColdPublishNew(*os.Root, string, string) (bool, error) {
	return false, ErrMihomoLiveRetirement
}
