//go:build linux && (amd64 || arm64)

package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestSelfUpdateRuntimePlatformMetadataStrictParsing(t *testing.T) {
	for _, data := range []string{"ID=ubuntu\nVERSION_ID=26.04\n", "PRETTY_NAME=\"Ubuntu 26.04.1 LTS\"\nVERSION_ID=\"26.04\"\nID=ubuntu\n"} {
		id, version, err := parseSelfUpdateUbuntuRelease([]byte(data))
		if err != nil || id != "ubuntu" || version != "26.04" {
			t.Fatal("actual metadata syntax refused")
		}
	}
	for _, data := range []string{"", "ID=ubuntu\n", "VERSION_ID=26.04\n", "ID=ubuntu\nID=ubuntu\nVERSION_ID=26.04\n",
		"ID=ubuntu\nVERSION_ID=26.04\nVERSION_ID=26.04\n", "ID='ubuntu'\nVERSION_ID=26.04\n", "ID=\"ubuntu\nVERSION_ID=26.04\n",
		"ID=$(uname)\nVERSION_ID=26.04\n", "ID=ubuntu\r\nVERSION_ID=26.04\n", "ID=ubuntu\x00\nVERSION_ID=26.04\n", strings.Repeat("x", (16<<10)+1)} {
		if _, _, err := parseSelfUpdateUbuntuRelease([]byte(data)); err == nil {
			t.Fatal("missing/duplicate/executable/unbounded metadata accepted")
		}
	}
	for _, raw := range [][]byte{nil, []byte(""), []byte("Linux"), []byte("\x00"), []byte("Linux\n\x00"), []byte("Linux/other\x00"), {0xff, 0}} {
		if _, err := selfUpdateRuntimeUnameScalar(raw); err == nil {
			t.Fatal("invalid uname scalar accepted")
		}
	}
	if value, err := selfUpdateRuntimeUnameScalar([]byte("7.0.0-38-generic\x00")); err != nil || value != "7.0.0-38-generic" {
		t.Fatal("actual kernel scalar refused")
	}
}

func TestSelfUpdateRuntimePlatformMetadataRejectsForeignWritableOrReplacedNodes(t *testing.T) {
	file := unix.Stat_t{Mode: unix.S_IFREG | 0644, Uid: 0, Gid: 0, Dev: 1, Ino: 2, Size: 31}
	for _, mutate := range []func(*unix.Stat_t){func(s *unix.Stat_t) { s.Uid = 1001 }, func(s *unix.Stat_t) { s.Mode |= 0020 },
		func(s *unix.Stat_t) { s.Mode = unix.S_IFLNK | 0644 }, func(s *unix.Stat_t) { s.Ino++ },
		func(s *unix.Stat_t) { s.Size++ }, func(s *unix.Stat_t) { s.Ctim.Nsec++ }, func(s *unix.Stat_t) { s.Gid++ }} {
		changed := file
		mutate(&changed)
		if selfUpdateRuntimeSameNode(file, changed, false) {
			t.Fatal("foreign/writable/replaced/changed metadata issued selection")
		}
	}
	if !selfUpdateRuntimeSameNode(file, file, false) || selfUpdateRuntimeProtectedNode(file, true) {
		t.Fatal("metadata type comparison invalid")
	}
}

// The opt-in chooses the expected test outcome only. Production selection reads
// actual uname/metadata and its original factories; no native facts are faked.
func TestSelfUpdateRuntimeSourceNativeReviewedAssembly(t *testing.T) {
	mode := os.Getenv("RAZVILKA_SELF_UPDATE_RUNTIME_SOURCE_NATIVE")
	if mode == "" {
		t.Skip("Root native runtime-source assembly opt-in disabled")
	}
	want := selfUpdateRuntimeUbuntu70
	if mode == "stock-nc1812" {
		want = selfUpdateRuntimeStockNC1812
	} else if mode != "ubuntu70" {
		t.Fatal("unsupported native expectation")
	}
	if os.Geteuid() != 0 {
		t.Fatal("native source assembly requires root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	facts, err := observeSelfUpdateRuntimePlatform(ctx)
	if err != nil {
		t.Fatal("actual platform observation refused")
	}
	selected, err := selectSelfUpdateRuntimePlatform(facts)
	if err != nil || selected != want {
		t.Fatal("actual platform does not match expected reviewed assembly")
	}
	manager, closeSource, err := selfUpdateRuntimeManagerBound(ctx)
	if err != nil {
		t.Fatalf("actual source assembly refused: category=%s canceled=%t deadline=%t", selfUpdateRuntimeManagerFailureStage(err), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded))
	}
	if manager == nil || closeSource == nil {
		t.Fatal("source construction lacks its original manager/closure")
	}
	defer func() {
		if closeSource() != nil {
			t.Error("actual retained source closure refused")
		}
	}()
	closing, err := observeSelfUpdateRuntimePlatform(ctx)
	if err != nil || closing != facts {
		t.Fatal("actual platform changed across source assembly")
	}
	// Successful BindRuntimeInactivitySources includes the actual NFQ source's
	// complete inventory Read and fresh identity bookends. No installer roles,
	// inactive runtime, replacement, routing or update PASS are claimed here.
	if closeSource() != nil {
		t.Fatal("actual source closure refused")
	}
	t.Log("actual reviewed source bound with complete inventory and joined closure; no update or inactivity grant")
}
