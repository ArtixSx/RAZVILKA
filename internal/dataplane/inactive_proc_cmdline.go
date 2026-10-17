package dataplane

import "strings"

// Linux exposes mutable argv memory through procfs; a rewritten process title
// may end at EOF without a NUL. Remove only an actual final delimiter and keep
// every byte of a final argument for managed binary/configuration detection.
// Empty cmdline (kernel threads) is handled separately by the caller.
func inactiveProcArguments(image []byte) ([]string, bool) {
	if len(image) == 0 || len(image) > 64<<10 {
		return nil, false
	}
	if image[len(image)-1] == 0 {
		image = image[:len(image)-1]
	}
	args := strings.Split(string(image), "\x00")
	return args, len(args) <= 256 && args[0] != ""
}
