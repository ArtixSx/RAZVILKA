package dataplane

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

// VerifyRollback only observes the restored instance. It never restarts a
// process, consumes a draft, or treats a web probe as proof of rollback.
func (a *NFQWS2Adapter) VerifyRollback(ctx context.Context, _ Plan, root string) (bool, error) {
	snapshot, err := readNFQWS2Snapshot(root)
	if err != nil {
		return false, err
	}
	unlock, err := a.lockResources()
	if err != nil {
		return false, err
	}
	defer unlock()
	lease, err := a.readLease()
	if err != nil || !reflect.DeepEqual(lease, snapshot.Lease) {
		return false, errors.New("NFQWS2 rollback ownership differs from its snapshot")
	}
	for _, file := range []struct {
		path   string
		data   []byte
		exists bool
	}{
		{a.ConfigPath, snapshot.Config, snapshot.ConfigExisted},
		{a.UserListPath, snapshot.UserList, snapshot.UserListExisted},
		{a.IPSetListPath, snapshot.IPSetList, snapshot.IPSetListExisted},
	} {
		data, exists, err := nfqws2Read(file.path)
		if err != nil || exists != file.exists || !bytes.Equal(data, file.data) {
			return false, errors.New("NFQWS2 rollback files differ from their snapshot")
		}
	}
	// A pre-existing external service has no instance manifest to prove its
	// runtime. Keep that result explicitly unconfirmed, including stopped cases.
	if lease == nil {
		return false, nil
	}
	if _, err := a.verifyOwnedLists(false); err != nil {
		return false, err
	}
	queue, ok := nfqws2LiteralQueue(snapshot.Config)
	if !ok {
		return false, errors.New("NFQWS2 rollback queue cannot be determined without executing configuration")
	}
	output, statusErr := a.run(ctx, a.InitPath, "status")
	running := statusErr == nil && runningOutput(string(output))
	stopped := !runningOutput(string(output)) && strings.Contains(strings.ToLower(string(output)), "not running")
	if snapshot.WasRunning && !running || !snapshot.WasRunning && !stopped {
		return false, errors.New("NFQWS2 rollback process state is not confirmed")
	}
	command := a.IPTablesSave
	if command == "" {
		command = findExecutable("/opt/sbin/iptables-save", "/opt/bin/iptables-save", "iptables-save")
	}
	if command == "" {
		return false, errors.New("iptables-save is unavailable for NFQWS2 rollback verification")
	}
	output, err = a.run(ctx, command)
	if err != nil {
		return false, fmt.Errorf("read NFQWS2 rollback rules: %w", err)
	}
	if nfqws2QueueRule(output, queue) != snapshot.WasRunning {
		return false, errors.New("NFQWS2 rollback queue rules are not confirmed")
	}
	return ctx.Err() == nil, ctx.Err()
}

var nfqws2QueueAssignment = regexp.MustCompile(`^(?:export\s+)?NFQUEUE_NUM\s*=\s*(?:"([0-9]+)"|'([0-9]+)'|([0-9]+))\s*(?:#.*)?$`)

func nfqws2LiteralQueue(config []byte) (string, bool) {
	queue := "300" // The installed NFQWS2 service's default.
	for _, raw := range strings.Split(string(config), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "#") || !strings.Contains(line, "NFQUEUE_NUM") {
			continue
		}
		match := nfqws2QueueAssignment.FindStringSubmatch(line)
		if match == nil {
			return "", false
		}
		for _, value := range match[1:] {
			if value == "" {
				continue
			}
			n, err := strconv.Atoi(value)
			if err != nil || n < 1 || n > 65535 {
				return "", false
			}
			queue = strconv.Itoa(n)
		}
	}
	return queue, true
}

func nfqws2QueueRule(data []byte, queue string) bool {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[0] != "-A" || !strings.HasPrefix(strings.ToLower(fields[1]), "nfqws") {
			continue
		}
		target, number := false, false
		for i := 2; i+1 < len(fields); i++ {
			target = target || fields[i] == "-j" && fields[i+1] == "NFQUEUE"
			number = number || fields[i] == "--queue-num" && fields[i+1] == queue
		}
		if target && number {
			return true
		}
	}
	return false
}
