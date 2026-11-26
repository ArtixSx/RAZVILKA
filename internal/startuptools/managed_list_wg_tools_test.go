package startuptools

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/netidentity"
)

// These tests use real private alias files/absence, the original lease gate,
// cancellation and Close joins. ONLY the Provider/full-image/version reader
// is an explicit model; these bytes are never executed or native tool proof.
func TestManagedListWGToolsProjectsBothEnginesInOneOriginalObservation(t *testing.T) {
	for _, present := range [][2]bool{{false, false}, {true, false}, {false, true}, {true, true}} {
		l := managedListDescriptorFixture(t, present)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		calls := 0
		tools, err := l.managedListWGCommandTools(ctx, l.identity, func(c context.Context, expected netidentity.Identity, use func(context.Context) error) error {
			calls++
			if expected != l.identity || len(l.gate) != 0 {
				t.Fatal("projection escaped original identity or held tool owner")
			}
			originalDeadline, _ := ctx.Deadline()
			deadline, bounded := c.Deadline()
			if !bounded || deadline.After(originalDeadline) {
				t.Fatal("observation extended original caller window")
			}
			return use(c)
		})
		cancel()
		if err != nil || calls != 1 || len(tools) != managedWGPresentCount(present) {
			t.Fatal("optional engines caused repeated observations or refused same cohort", present, calls, tools, err)
		}
		for i, engine := range []string{"wireguard", "amneziawg"} {
			tool, found := tools[engine]
			if found != present[i] {
				t.Fatal("missing primary was promoted", engine, found)
			}
			if found {
				original, err := l.WGCommandTools(engine)
				if err != nil || tool.EngineID != original.EngineID || tool.WG != original.WG || tool.AWG != original.AWG || tool.IP != original.IP || tool.IPTables != original.IPTables || tool.IP6Tables != original.IP6Tables || tool.ReviewSHA256 != l.digest || tool.Provider != l.provider || tool.Identity != l.identity || tool.Runner.(*wgRunner).lease != l {
					t.Fatal("batch substituted the original tool descriptor", engine, err)
				}
			}
		}
	}
}

func managedWGPresentCount(values [2]bool) int {
	count := 0
	for _, value := range values {
		if value {
			count++
		}
	}
	return count
}

func TestManagedListWGToolsNeverCachesOptionalAbsenceBetweenCalls(t *testing.T) {
	l := managedListDescriptorFixture(t, [2]bool{true, false})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	calls := 0
	observe := func(c context.Context, _ netidentity.Identity, use func(context.Context) error) error {
		calls++
		return use(c)
	}
	tools, err := l.managedListWGCommandTools(ctx, l.identity, observe)
	if err != nil || len(tools) != 1 {
		t.Fatal("original optional absence refused", err)
	}
	if err := os.WriteFile(l.profile.wgAliases[1], []byte("new unreviewed occupant"), 0600); err != nil {
		t.Fatal(err)
	}
	tools, err = l.managedListWGCommandTools(ctx, l.identity, observe)
	if err == nil || tools != nil || calls != 2 {
		t.Fatal("previous descriptor or optional absence was cached", err, calls)
	}
}

func TestManagedListWGToolsDiscardsEveryPartialOrExpiredClosingResult(t *testing.T) {
	refusal := errors.New("model original reader refusal")
	for _, mode := range []string{"opening", "closing", "caller-cancel", "alias-appears", "unissued-absence"} {
		t.Run(mode, func(t *testing.T) {
			l := managedListDescriptorFixture(t, [2]bool{true, false})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if mode == "unissued-absence" {
				delete(l.review.absent, l.profile.wgAliases[1])
			}
			projected := false
			tools, err := l.managedListWGCommandTools(ctx, l.identity, func(c context.Context, _ netidentity.Identity, use func(context.Context) error) error {
				if mode == "opening" {
					return refusal
				}
				useErr := use(c)
				projected = useErr == nil
				switch mode {
				case "closing":
					return errors.Join(useErr, refusal)
				case "caller-cancel":
					cancel()
					return useErr // Even a model ignoring cancellation cannot publish.
				case "alias-appears":
					if err := os.WriteFile(l.profile.wgAliases[1], []byte("new unreviewed occupant"), 0600); err != nil {
						t.Fatal(err)
					}
					return errors.Join(useErr, l.review.wgAbsencesCurrent(c))
				}
				return useErr
			})
			if tools != nil || err == nil {
				t.Fatal("partial or expired closing returned a descriptor", mode, tools, err)
			}
			if (mode == "opening" || mode == "unissued-absence") == projected {
				t.Fatal("reader refusal happened at wrong boundary", mode, projected)
			}
			if (mode == "opening" || mode == "closing") && !errors.Is(err, refusal) {
				t.Fatal("original reader refusal was lost", err)
			}
		})
	}
}

func TestManagedListWGToolsCloseCancelsAndJoinsOriginalObservation(t *testing.T) {
	l := managedListDescriptorFixture(t, [2]bool{true, true})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	entered, proceed := make(chan struct{}), make(chan struct{})
	observed := make(chan error, 1)
	go func() {
		tools, err := l.managedListWGCommandTools(ctx, l.identity, func(c context.Context, _ netidentity.Identity, use func(context.Context) error) error {
			if err := use(c); err != nil {
				return err
			}
			close(entered)
			<-proceed // Explicit closing-reader model; owner must join it.
			return nil
		})
		if tools != nil || err == nil {
			observed <- errors.New("closed original lease published partial descriptors")
			return
		}
		observed <- nil
	}()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- l.Close() }()
	<-l.lifetime.Done()
	select {
	case <-closed:
		t.Fatal("Close released held files before observation joined")
	case <-time.After(20 * time.Millisecond):
	}
	for _, image := range l.review.wgEntry {
		if _, err := image.file.Stat(); err != nil {
			t.Fatal("Close released original entry before closing reader joined", err)
		}
	}
	close(proceed)
	if err := <-observed; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}

func TestManagedListWGToolsRefusesForeignUnboundedAndProductionModelOwners(t *testing.T) {
	for _, mode := range []string{"unbounded", "wrong-identity", "wrong-profile", "closed"} {
		t.Run(mode, func(t *testing.T) {
			l := managedListDescriptorFixture(t, [2]bool{false, false})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			expected := l.identity
			switch mode {
			case "unbounded":
				ctx = context.Background()
			case "wrong-identity":
				expected.Inode++
			case "wrong-profile":
				l.review.profile.wgEngine = "wireguard"
			case "closed":
				if err := l.Close(); err != nil {
					t.Fatal(err)
				}
			}
			called := false
			tools, err := l.managedListWGCommandTools(ctx, expected, func(context.Context, netidentity.Identity, func(context.Context) error) error {
				called = true
				return nil
			})
			if err == nil || tools != nil || called {
				t.Fatal("invalid owner reached original observation", mode, err, called)
			}
		})
	}
	// Real production dispatch cannot use these intent/model descriptors to
	// replace its actual stock Provider and original full held-image reader.
	l := managedListDescriptorFixture(t, [2]bool{true, true})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	tools, err := l.ManagedListWGCommandTools(ctx, l.identity)
	if err == nil || tools != nil {
		t.Fatal("private model replaced production original reader", tools, err)
	}
	var f *failure
	if !errors.As(err, &f) || f.stage != "WG_STARTUP_OBSERVATION" {
		t.Fatal("fixed observation substage was lost", err)
	}
	for _, empty := range []*Lease{nil, {}} {
		tools, err := empty.ManagedListWGCommandTools(ctx, l.identity)
		if tools != nil || !errors.Is(err, ErrUnknown) {
			t.Fatal("unissued original lease returned a descriptor", err)
		}
	}
}
