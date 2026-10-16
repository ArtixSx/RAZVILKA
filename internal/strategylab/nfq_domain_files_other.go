//go:build !linux

package strategylab

import "os"

func nfqDomainReadFlags() int { return os.O_RDONLY }
