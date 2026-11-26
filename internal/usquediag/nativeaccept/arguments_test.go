package nativeaccept

import (
	"errors"
	"flag"
	"strings"
	"testing"
)

func arguments(r Request) []string {
	mode := "h2"
	if r.Transport == "QUIC" {
		mode = "quic"
	}
	return []string{"--run-existing-account", "--mode", mode, "--binary", r.Binary, "--binary-sha256", r.BinarySHA256,
		"--account", r.Account, "--account-sha256", r.AccountSHA256, "--work-parent", r.WorkParent}
}

func TestArgumentsNoImplicitModeNoRegistrationNoPrivateEcho(t *testing.T) {
	f := newFixture(t, "HTTP/2")
	args := arguments(f.r)
	r, err := ParseArguments(args)
	if err != nil || r != f.r {
		t.Fatalf("parse %v, %v", r, err)
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"no-opt-in", args[1:]},
		{"duplicate", append(append([]string(nil), args...), "--mode=quic")},
		{"registration", append(append([]string(nil), args...), "--register="+testPrivate)},
		{"imported-receipt", append(append([]string(nil), args...), "--receipt="+testPrivate)},
		{"unbounded-check", append(append([]string(nil), args...), "--timeout=31s")},
		{"unbounded-cleanup", append(append([]string(nil), args...), "--cleanup-timeout=6s")},
		{"privileged-listener", append(append([]string(nil), args...), "--socks-port=80")},
		{"wrapped-port", append(append([]string(nil), args...), "--socks-port=65536")},
		{"extra-private-positional", append(append([]string(nil), args...), testPrivate)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseArguments(tc.args)
			if err == nil || strings.Contains(err.Error(), testPrivate) || strings.Contains(err.Error(), f.r.Account) {
				t.Fatalf("invalid/private arguments accepted or echoed: %v", err)
			}
		})
	}
	for _, mode := range []string{"auto", "h3", "", "HTTP/2"} {
		copy := append([]string(nil), args...)
		copy[2] = mode
		if _, err := ParseArguments(copy); err == nil {
			t.Fatalf("implicit/unsupported mode %q accepted", mode)
		}
	}
	if _, err := ParseArguments([]string{"--help"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatal("help refused")
	}
}
