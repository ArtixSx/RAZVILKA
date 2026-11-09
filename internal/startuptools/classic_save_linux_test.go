//go:build linux && (amd64 || arm64)

package startuptools

import (
	"context"
	"encoding/hex"
	"os"
	"os/exec"
	"sync"
	"testing"
)

func TestClassicSaveSharedOutputBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := &classicSaveBudget{remaining: 9, cancel: cancel}
	first, stderr, next := &output{limit: 9}, &output{limit: 9}, &output{limit: 9}
	if n, err := (&classicSaveOutput{first, b}).Write([]byte("1234")); n != 4 || err != nil {
		t.Fatal(n, err)
	}
	var wg sync.WaitGroup
	for _, sink := range []*output{stderr, next} {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = (&classicSaveOutput{sink, b}).Write([]byte("5678")) }()
	}
	wg.Wait()
	if !b.overflow || ctx.Err() != context.Canceled || len(first.data)+len(stderr.data)+len(next.data) != 8 || b.remaining != 1 {
		t.Fatal("streams or siblings exceeded common budget")
	}
}

func TestClassicSaveUnsupportedHasNoRead(t *testing.T) {
	for _, p := range []profile{stockProfile(), {}} {
		l := &Lease{profile: p}
		raw, supported, err := l.ReadBoundedClassicInventory(nil, l.identity, "", p.aliases, 1, [2][]string{})
		if supported || err != nil || len(raw[0])+len(raw[1]) != 0 {
			t.Fatal("unsupported profile attempted source/lock access")
		}
	}
}

// Shape tests do not fabricate an original source, lock or Start permission.
func TestClassicSaveAppletCannotUseGenericReadGrant(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "image")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	p := ubuntuProfile()
	image := &heldImage{file: f, path: p.main}
	p.mainSHA = hex.EncodeToString(image.hash[:])
	l := &Lease{profile: p, review: &heldReview{entry: [2]*heldImage{image, image}, images: map[string]*heldImage{p.main: image}}}
	for family := range 2 {
		name, _ := l.classicSaveImage(family)
		command := &exec.Cmd{Path: "/proc/self/fd/3", Args: []string{name}, ExtraFiles: []*os.File{f}, Env: p.environment(), Dir: "/", Stdout: &output{limit: 128}, Stderr: &output{limit: 128}}
		if l.observedReadCommand(command) || l.observedClassicSaveCommand(context.Background(), command) {
			t.Fatal("save applet admitted without original lock/leaf")
		}
		s := &classicSaveScope{lease: l, command: command, family: family, active: false}
		ctx := context.WithValue(context.Background(), classicSaveScopeKey{}, s)
		s.ctx = ctx
		if l.observedClassicSaveCommand(ctx, command) {
			t.Fatal("expired marker admitted")
		}
	}
}
