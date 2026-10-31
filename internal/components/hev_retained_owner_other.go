//go:build !linux

package components

import "os"

const hevRetainedReadFlags = os.O_RDONLY

func hevRetainedOwner(os.FileInfo, bool) (string, bool) { return "", false }
