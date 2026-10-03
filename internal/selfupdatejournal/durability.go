package selfupdatejournal

import (
	"os"
	"runtime"
)

func syncDirectory(root *os.Root, directory string) error {
	// Windows fault tests cover process termination, not storage power loss.
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := root.Open(directory)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
