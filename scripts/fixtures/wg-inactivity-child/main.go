// Command wg-inactivity-child is a private test helper, never a real IP tool.
// Build separately (also with -race) so the tested package stays instrumented
// without copying its whole test executable into the 16MiB tool-image fixture.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"
)

func main() {
	switch filepath.Base(os.Args[0]) {
	case "wg-kernel-link-metadata-ip":
		if len(os.Args) != 2 || os.Args[1] != "-Version" {
			os.Exit(99)
		}
		fmt.Fprint(os.Stdout, "ip utility, iproute2-6.19.0, libbpf 1.6.3\n")
	case "wg-kernel-link-metadata-iptables", "wg-kernel-link-metadata-ip6tables":
		if len(os.Args) != 2 || os.Args[1] != "--version" {
			os.Exit(99)
		}
		name := "iptables"
		if filepath.Base(os.Args[0]) == "wg-kernel-link-metadata-ip6tables" {
			name = "ip6tables"
		}
		fmt.Fprintf(os.Stdout, "%s v1.8.11 (legacy)\n", name)
	case "wg-inactivity-read-child":
		diagnostic()
	default:
		os.Exit(99)
	}
}

func diagnostic() {
	if len(os.Args) != 8 || !slices.Equal(os.Args[1:7], []string{"-N", "-6", "-j", "route", "show", "table"}) ||
		!slices.Contains([]string{"205", "206", "207"}, os.Args[7]) {
		os.Exit(99)
	}
	root := filepath.Dir(os.Getenv("XTABLES_LIBDIR"))
	if os.WriteFile(filepath.Join(root, "started"), []byte("actual child"), 0600) != nil {
		os.Exit(98)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(root, "release")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			os.Exit(97)
		}
		time.Sleep(5 * time.Millisecond)
	}
	fmt.Fprint(os.Stdout, "[]\n")
	if os.Args[7] != "205" {
		fmt.Fprint(os.Stderr, "Error: unexpected readonly failure.\n")
		if os.Args[7] == "207" {
			os.Exit(0)
		}
		os.Exit(3)
	}
	fmt.Fprint(os.Stderr, "Error: ipv6: FIB table does not exist.\nDump terminated\n")
	os.Exit(2)
}
