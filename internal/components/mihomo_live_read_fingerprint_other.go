//go:build !linux

package components

import "os"

func mihomoLiveReadFileFingerprint(*os.File) (mihomoLiveReadFileID, error) {
	return mihomoLiveReadFileID{}, ErrMihomoLiveOwner
}
