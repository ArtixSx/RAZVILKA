//go:build !linux

package dataplane

import "os"

func readMihomoColdFile(*os.Root, string) ([]byte, error) { return nil, ErrMihomoLiveRetirement }
func readMihomoColdFileAt(*os.Root, string, os.FileInfo) ([]byte, error) {
	return nil, ErrMihomoLiveRetirement
}
func openMihomoColdFile(*os.Root, string) (*os.File, error) { return nil, ErrMihomoLiveRetirement }
