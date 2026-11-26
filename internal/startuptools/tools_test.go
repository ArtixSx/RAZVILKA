package startuptools

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

func unitLease(t *testing.T) *Lease {
	t.Helper()
	lifetime, cancel := context.WithCancel(context.Background())
	l := &Lease{provider: netidentity.NewProcProvider(), identity: netidentity.Identity{Version: 1, Kind: netidentity.ProcNetInode, BootID: "12345678-1234-1234-1234-123456789abc", Inode: 123}, profile: ubuntuProfile(), review: &heldReview{images: map[string]*heldImage{}}, digest: strings.Repeat("a", 64), lifetime: lifetime, cancel: cancel, gate: make(chan struct{}, 1), closeDone: make(chan struct{})}
	l.gate <- struct{}{}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func TestZeroAndClosedLeaseCannotIssueEvidence(t *testing.T) {
	for _, l := range []*Lease{nil, {}} {
		if _, err := l.InventoryTools(); !errors.Is(err, ErrUnknown) {
			t.Fatal("unissued lease returned inventory tools", err)
		}
		if err := l.Check(context.Background(), netidentity.Identity{}); !errors.Is(err, ErrUnknown) {
			t.Fatal("unissued lease passed Check", err)
		}
	}
	l := unitLease(t)
	tools, err := l.InventoryTools()
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := l.InventoryTools(); !errors.Is(err, ErrUnknown) {
		t.Fatal("closed lease returned tools", err)
	}
	if err := tools.Check(context.Background(), l.identity); !errors.Is(err, ErrUnknown) {
		t.Fatal("retained descriptor survived Close", err)
	}
	c, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if out, err := tools.Runner.Run(c, tools.IPTables, "-t", "mangle", "-S"); err == nil || len(out) != 0 {
		t.Fatal("retained runner survived Close", err)
	}
}

func TestCloseCancelsAndWaitsForHeldCallbackBeforeClosingFiles(t *testing.T) {
	l := unitLease(t)
	file, err := os.CreateTemp(t.TempDir(), "held-image")
	if err != nil {
		t.Fatal(err)
	}
	l.review.images[file.Name()] = &heldImage{file: file}
	if err := l.lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- l.Close() }()
	select {
	case <-l.lifetime.Done():
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel callback lifetime")
	}
	select {
	case <-done:
		t.Fatal("Close released a file while a callback retained it")
	default:
	}
	second := make(chan error, 1)
	go func() { second <- l.Close() }()
	select {
	case <-second:
		t.Fatal("second Close returned before the first joined its callback")
	default:
	}
	if _, err := file.Stat(); err != nil {
		t.Fatal("held descriptor closed before callback joined", err)
	}
	l.unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close failed to join callback")
	}
	if _, err := file.Stat(); err == nil {
		t.Fatal("Close leaked held descriptor")
	}
	if err := <-second; err != nil {
		t.Fatal(err)
	}
}

func TestOriginalLifetimeAndReadABI(t *testing.T) {
	l := unitLease(t)
	l.cancel()
	if _, err := l.InventoryTools(); !errors.Is(err, ErrUnknown) {
		t.Fatal("cancelled original context did not revoke lease", err)
	}
	for _, args := range [][]string{{"-t", "mangle", "-A"}, {"-t", "mangle", "-S", "extra"}, {"-t", "unreviewed table", "-S"}, {"--version"}, {"-t", "mangle\n", "-S"}, {"-t", "-table", "-S"}, {"-t", strings.Repeat("a", 32), "-S"}} {
		if readArguments(args) {
			t.Fatal("non-read command entered inventory ABI", args)
		}
	}
	for _, table := range []string{"filter", "nat", "mangle", "raw", "security", "custom_registered_table"} {
		if !readArguments([]string{"-t", table, "-S"}) {
			t.Fatal("collector read ABI refused", table)
		}
	}
}

func TestHashAndOutputBoundNeverReturnTruncatedEvidence(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "hash")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.WriteString("actual held bytes"); err != nil {
		t.Fatal(err)
	}
	if _, err := hashImage(context.Background(), file, 5); err == nil {
		t.Fatal("prefix hash accepted an oversized image")
	}
	c, cancel := context.WithCancel(context.Background())
	w := &output{limit: 8, cancel: cancel}
	if _, err := w.Write([]byte("12345678")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("9")); err == nil || !w.overflow || c.Err() == nil || len(w.data) != 8 {
		t.Fatal("overflow did not cancel without growing allocation")
	}
}

func TestBoundedLeafReadAcceptsLongCaptureButNeverExtendsOriginalContext(t *testing.T) {
	for _, duration := range []time.Duration{16 * time.Second, 100 * time.Millisecond} {
		original, cancelOriginal := context.WithTimeout(context.Background(), duration)
		leaf, cancelLeaf, err := boundedReadContext(original)
		if err != nil {
			cancelOriginal()
			t.Fatal(err)
		}
		originalDeadline, _ := original.Deadline()
		leafDeadline, _ := leaf.Deadline()
		if leafDeadline.After(originalDeadline) || time.Until(leafDeadline) > operationTimeout {
			t.Fatal("leaf extended original or internal cap")
		}
		cancelOriginal()
		if leaf.Err() == nil {
			t.Fatal("leaf detached original cancellation")
		}
		cancelLeaf()
	}
	if _, _, err := boundedReadContext(context.Background()); err == nil {
		t.Fatal("unbounded original read admitted")
	}
}
