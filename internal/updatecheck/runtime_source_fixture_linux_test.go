//go:build linux && amd64 && razvilka_native_fixture

package updatecheck

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func TestNativeRuntimeCommandForwardingRefusesUnrelated(t *testing.T) {
	t.Setenv("RAZVILKA_RUNTIME_NATIVE_REVIEW", filepath.Join(t.TempDir(), "runtime-native-tool-review.json"))
	t.Setenv("RAZVILKA_RUNTIME_NATIVE_OUTER_NET_FD", "3")
	id := "0123456789abcdef0123456789abcdef"
	for _, change := range []string{"path", "command", "id", "argv", "duplicate-env", "extra-fd", "cancel"} {
		t.Run(change, func(t *testing.T) {
			command := "prepare-private-state"
			cmd := exec.Command(filepath.Join(productionUpdateRoot, id, "control.bin"), "self-update-command-helper", id, command)
			cmd.Env = commandEnvironment()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch change {
			case "path":
				cmd.Path = "/bin/true"
			case "command":
				command = "start-candidate-panel"
				cmd.Args[3] = command
			case "id":
				cmd.Args[2] = "foreign"
			case "argv":
				cmd.Args = append(cmd.Args, "extra")
			case "duplicate-env":
				cmd.Env = append(cmd.Env, "RAZVILKA_RUNTIME_NATIVE_REVIEW=foreign")
			case "extra-fd":
				cmd.ExtraFiles = []*os.File{os.Stdin}
			case "cancel":
				cancel()
			}
			beforeEnv, beforeFDs := append([]string(nil), cmd.Env...), append([]*os.File(nil), cmd.ExtraFiles...)
			closeSource, err := bindNativeRuntimeCommand(ctx, cmd, id, command)
			closeSource()
			if err == nil || !reflect.DeepEqual(cmd.Env, beforeEnv) || !reflect.DeepEqual(cmd.ExtraFiles, beforeFDs) {
				t.Fatal("unrelated command inherited native coordinates", err)
			}
		})
	}
}
