//go:build windows

package routerstats

func diskUsage(string) (uint64, uint64, error) {
	return 0, 0, errDiskUnsupported
}
