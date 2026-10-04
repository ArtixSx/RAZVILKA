package components

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// NFQWSRuntimeProcessIdentity is readback of a particular kernel process,
// not launch permission or proof of inactivity. The producer must bind it to
// the immutable reviewed command and the dedicated supervisor's child PID.
type NFQWSRuntimeProcessIdentity struct {
	BootID, Start, Executable, ArgumentsSHA256 string
	PID, ParentPID, Group                      int
}

func NFQWSRuntimeArgumentsSHA256(program string, args []string) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(program))
	_, _ = hash.Write([]byte{0})
	for _, arg := range args {
		_, _ = hash.Write([]byte(arg))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func nfqwsRuntimeStatIdentity(data []byte) (start string, parent, group int, err error) {
	end := strings.LastIndex(string(data), ")")
	if end < 0 {
		return "", 0, 0, ErrNFQWSSupervisionUnknown
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) < 20 || len(fields[0]) != 1 || !strings.Contains("RSDTtKWPI", fields[0]) {
		return "", 0, 0, ErrNFQWSSupervisionUnknown
	}
	parent, err = strconv.Atoi(fields[1])
	if err != nil || parent <= 0 || strconv.Itoa(parent) != fields[1] {
		return "", 0, 0, ErrNFQWSSupervisionUnknown
	}
	group, err = strconv.Atoi(fields[2])
	if err != nil || group <= 0 || strconv.Itoa(group) != fields[2] {
		return "", 0, 0, ErrNFQWSSupervisionUnknown
	}
	birth, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || birth == 0 || strconv.FormatUint(birth, 10) != fields[19] {
		return "", 0, 0, ErrNFQWSSupervisionUnknown
	}
	return fields[19], parent, group, nil
}
