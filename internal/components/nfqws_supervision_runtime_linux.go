//go:build linux

package components

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ReadNFQWSRuntimeProcessIdentity samples identity on both sides of exe/argv
// readback. No /proc error is converted to proof of absence by this function.
func ReadNFQWSRuntimeProcessIdentity(pid int) (NFQWSRuntimeProcessIdentity, error) {
	var identity NFQWSRuntimeProcessIdentity
	if pid <= 1 {
		return identity, ErrNFQWSSupervisionUnknown
	}
	identity.PID = pid
	boot, err := bootIdentity()
	if err != nil {
		return identity, errors.Join(ErrNFQWSSupervisionUnknown, err)
	}
	read := func(leaf string, limit int64) ([]byte, error) {
		file, err := os.Open(fmt.Sprintf("/proc/%d/%s", pid, leaf))
		if err != nil {
			return nil, err
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, limit+1))
		if err != nil || int64(len(data)) > limit {
			return nil, ErrNFQWSSupervisionUnknown
		}
		return data, nil
	}
	before, err := read("stat", 8192)
	if err != nil {
		return identity, errors.Join(ErrNFQWSSupervisionUnknown, err)
	}
	identity.Start, identity.ParentPID, identity.Group, err = nfqwsRuntimeStatIdentity(before)
	if err != nil {
		return identity, err
	}
	executable, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil || !filepath.IsAbs(executable) || filepath.Clean(executable) != executable {
		return identity, errors.Join(ErrNFQWSSupervisionUnknown, err)
	}
	args, err := read("cmdline", 32768)
	if err != nil || len(args) == 0 || args[len(args)-1] != 0 {
		return identity, errors.Join(ErrNFQWSSupervisionUnknown, err)
	}
	after, err := read("stat", 8192)
	start, parent, group, statErr := nfqwsRuntimeStatIdentity(after)
	currentExecutable, exeErr := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	currentArgs, argsErr := read("cmdline", 32768)
	currentBoot, bootErr := bootIdentity()
	if err != nil || statErr != nil || exeErr != nil || argsErr != nil || bootErr != nil || start != identity.Start || parent != identity.ParentPID || group != identity.Group || executable != currentExecutable || !bytes.Equal(args, currentArgs) || boot != currentBoot {
		return identity, errors.Join(ErrNFQWSSupervisionUnknown, err, statErr, exeErr, argsErr, bootErr)
	}
	digest := sha256.Sum256(args)
	identity.BootID, identity.Executable, identity.ArgumentsSHA256 = boot, executable, hex.EncodeToString(digest[:])
	return identity, nil
}
