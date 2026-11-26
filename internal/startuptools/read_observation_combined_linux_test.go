//go:build linux && (amd64 || arm64)

package startuptools

import (
	"os"
	"os/exec"
	"testing"
)

// Command-shape comparison only. This model does not issue a native Lease,
// original Provider/scope or Start admission. The tagged test exercises them.
func TestObservedReadCombinedOutputRemainsLiteralAndBounded(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "image")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	image := &heldImage{file: f}
	l := &Lease{profile: profile{aliases: [2]string{"/held/iptables", "/held/ip6tables"}, ipAlias: "/held/ip"}, review: &heldReview{entry: [2]*heldImage{image, image}, ipEntry: image}}
	for _, test := range []struct {
		name     string
		args     []string
		limit    int
		separate bool
		want     bool
	}{
		{"/held/ip", []string{"-4", "-N", "rule", "show"}, maxOutputBytes, false, true},
		{"/held/ip", []string{"-6", "-N", "rule", "show"}, maxOutputBytes, false, true},
		{"/held/iptables", []string{"-t", "mangle", "-S"}, maxOutputBytes, false, true},
		{"/held/ip6tables", []string{"-t", "filter", "-S"}, maxOutputBytes, false, true},
		{"/held/ip", []string{"-4", "-N", "rule", "show"}, maxOutputBytes + 1, false, false},
		{"/held/ip", []string{"-4", "-N", "rule", "show"}, maxOutputBytes, true, false},
		{"/held/ip", []string{"-4", "rule", "del", "priority", "207"}, maxOutputBytes, false, false},
		{"/held/iptables", []string{"-t", "mangle", "-F"}, maxOutputBytes, false, false},
		{"/held/ip", []string{"-Version"}, maxOutputBytes, false, false},
		{"/held/iptables", []string{"--version"}, maxOutputBytes, false, false},
	} {
		out := &output{limit: test.limit}
		stderr := out
		if test.separate {
			stderr = &output{limit: test.limit}
		}
		command := &exec.Cmd{Path: "/proc/self/fd/3", Args: append([]string{test.name}, test.args...), ExtraFiles: []*os.File{f}, Env: l.profile.environment(), Dir: "/", Stdout: out, Stderr: stderr}
		if got := l.observedReadCommand(command); got != test.want {
			t.Fatal("combined literal read classification", test.name, test.args, got)
		}
	}
	for _, streams := range [][2]*output{{nil, nil}, {nil, {limit: 4096}}, {{limit: maxOutputBytes}, nil}} {
		command := &exec.Cmd{Path: "/proc/self/fd/3", Args: []string{"/held/ip", "-4", "-N", "rule", "show"}, ExtraFiles: []*os.File{f}, Env: l.profile.environment(), Dir: "/", Stdout: streams[0], Stderr: streams[1]}
		if l.observedReadCommand(command) {
			t.Fatal("typed nil collector accepted")
		}
	}
}
