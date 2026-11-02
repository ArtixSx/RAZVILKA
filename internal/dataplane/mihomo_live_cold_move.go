package dataplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
)

// Both roots are the offline operation's held originals. The only move is the
// fixed startup runtime directory into its fixed archive child. Nothing from
// serialized filenames is passed to Rename; an existing destination is never
// replaced. Resumption recognizes the entire original inode/content inventory.
func moveMihomoColdRuntime(state, archive *os.Root, a *ProxyTunnelAdapter, expected mihomoColdRuntimeArchive, current func() error, fault func(string) error) error {
	if state == nil || archive == nil || a == nil || current == nil {
		return ErrMihomoLiveRetirement
	}
	check := func() (bool, error) {
		if err := current(); err != nil {
			return false, err
		}
		from, err := readMihomoColdRuntime(state, "mihomo", a)
		if err != nil {
			return false, err
		}
		to, err := readMihomoColdRuntime(archive, "runtime", a)
		if err != nil {
			return false, err
		}
		if !expected.Present {
			if from.Present || to.Present {
				return false, ErrMihomoLiveRetirement
			}
			return false, current()
		}
		if from.Present == to.Present {
			return false, ErrMihomoLiveRetirement
		}
		actual := from
		if to.Present {
			actual = to
		}
		left, e1 := json.Marshal(expected)
		right, e2 := json.Marshal(actual)
		if e1 != nil || e2 != nil || !bytes.Equal(left, right) {
			return false, ErrMihomoLiveRetirement
		}
		return from.Present, current()
	}
	move, err := check()
	if err != nil {
		return err
	}
	if move {
		from, err := state.Open(".")
		if err != nil {
			return err
		}
		defer from.Close()
		to, err := archive.Open(".")
		if err != nil {
			return err
		}
		defer to.Close()
		if _, err := check(); err != nil {
			return err
		}
		if err := mihomoColdRenameNoReplace(from, to); err != nil {
			return err
		}
		if fault != nil {
			if err := fault("runtime-renamed"); err != nil {
				return err
			}
		}
	}
	if expected.Present {
		if err := syncBootRetirementDirectory(state, "."); err != nil {
			return err
		}
		if err := syncBootRetirementDirectory(archive, "."); err != nil {
			return err
		}
		if fault != nil {
			if err := fault("runtime-directory-ack"); err != nil {
				return err
			}
		}
	}
	remaining, err := check()
	if remaining {
		return errors.Join(ErrMihomoLiveRetirement, err)
	}
	return err
}
