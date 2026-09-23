package systemprobe

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

var ErrNetworkUnavailable = errors.New("current network epoch is unavailable")

const networkSnapshotTimeout = 3 * time.Second

// ValidWANProfileID accepts only a known session token. The unknown sentinel
// and legacy arbitrary profile labels must never grant route authority.
func ValidWANProfileID(id string) bool {
	if len(id) != 16 || !strings.HasPrefix(id, "wan-") {
		return false
	}
	for _, c := range id[4:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// FreshWANProfile observes the underlay without the passive ten-second cache.
// The token changes on relevant observed events, observation failure, changed
// snapshot, reboot or observer restart. It does not identify hidden upstream
// changes inside a router DNS forwarder or reconnects not reported by its OS.
func FreshWANProfile(ctx context.Context) (WANProfile, error) { return wanEpoch.fresh(ctx) }

type epochSnapshot struct {
	bootID       string
	wanInterface string
	parts        []string
	interfaces   map[uint32]bool
}

type epochSource interface {
	Snapshot(context.Context) (epochSnapshot, error)
	Drain(context.Context, map[uint32]bool) (bool, error)
	Close()
}

type cachedWAN struct {
	profile    WANProfile
	at         time.Time
	diagnostic NetworkEpochDiagnostic
}

// NetworkEpochDiagnostic contains only fixed reason labels and counters. It
// never contains source addresses, DNS contents, interface names or keys.
type NetworkEpochDiagnostic struct {
	Generation          uint64 `json:"generation"`
	Reason              string `json:"reason"`
	ChangedAt           string `json:"changed_at,omitempty"`
	ObservedAt          string `json:"observed_at,omitempty"`
	CallerCancellations uint64 `json:"caller_cancellations"`
	LastFailureReason   string `json:"last_failure_reason,omitempty"`
	LastFailureAt       string `json:"last_failure_at,omitempty"`
	LastFailureDetail   string `json:"last_failure_detail,omitempty"`
	ObserverRestarts    uint64 `json:"observer_restarts"`
}

func NetworkEpochStatus() NetworkEpochDiagnostic { return wanEpoch.diagnostic() }

func (d *epochDetector) diagnostic() NetworkEpochDiagnostic {
	result := NetworkEpochDiagnostic{Reason: "not-observed"}
	if cached := d.cache.Load(); cached != nil {
		result = cached.diagnostic
	}
	result.CallerCancellations = d.callerCancellations.Load()
	return result
}

type epochDetector struct {
	gate                chan struct{}
	factory             func(context.Context) (epochSource, error)
	entropy             io.Reader
	now                 func() time.Time
	source              epochSource
	seed                uint64
	seeded              bool
	generation          uint64
	lastDigest          [32]byte
	lastParts           []string
	lastReason          string
	lastChanged         time.Time
	lastFailureReason   string
	lastFailureAt       time.Time
	lastFailureDetail   string
	observerRestarts    uint64
	lastKnown           bool
	interfaces          map[uint32]bool
	cache               atomic.Pointer[cachedWAN]
	callerCancellations atomic.Uint64
}

var wanEpoch = newEpochDetector(newPlatformEpochSource, rand.Reader, time.Now)

func validEpochDNSConfig(data []byte) bool {
	servers := 0
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "nameserver" {
			continue
		}
		if len(fields) < 2 {
			return false
		}
		if _, err := netip.ParseAddr(fields[1]); err != nil {
			return false
		}
		servers++
	}
	return servers > 0
}

func newEpochDetector(factory func(context.Context) (epochSource, error), entropy io.Reader, now func() time.Time) *epochDetector {
	return &epochDetector{gate: make(chan struct{}, 1), factory: factory, entropy: entropy, now: now}
}

func (d *epochDetector) cached() WANProfile {
	if cached := d.cache.Load(); cached != nil && d.now().Sub(cached.at) >= 0 && d.now().Sub(cached.at) < 10*time.Second {
		return cached.profile
	}
	profile, _ := d.fresh(context.Background())
	return profile
}

func (d *epochDetector) fresh(parent context.Context) (WANProfile, error) {
	admission, cancelAdmission := context.WithTimeout(parent, networkSnapshotTimeout)
	defer cancelAdmission()
	select {
	case d.gate <- struct{}{}:
		defer func() { <-d.gate }()
	case <-admission.Done():
		if parent.Err() != nil {
			d.callerCancellations.Add(1)
		}
		return WANProfile{ID: "network-unknown"}, admission.Err()
	}
	// A canceled waiter has not observed the network and cannot invalidate the
	// shared observer. Once admitted, finish one bounded observation even if
	// that caller goes away: draining only half an event batch would lose ABA.
	if err := parent.Err(); err != nil {
		d.callerCancellations.Add(1)
		return WANProfile{ID: "network-unknown"}, err
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), networkSnapshotTimeout)
	defer cancel()
	phase := "initialization"
	publish := func(profile WANProfile) {
		now := d.now()
		diagnostic := NetworkEpochDiagnostic{Generation: d.generation, Reason: d.lastReason, ChangedAt: d.lastChanged.UTC().Format(time.RFC3339Nano), ObservedAt: now.UTC().Format(time.RFC3339Nano), LastFailureReason: d.lastFailureReason, LastFailureDetail: d.lastFailureDetail, ObserverRestarts: d.observerRestarts}
		if !d.lastFailureAt.IsZero() {
			diagnostic.LastFailureAt = d.lastFailureAt.UTC().Format(time.RFC3339Nano)
		}
		d.cache.Store(&cachedWAN{profile: profile, at: now, diagnostic: diagnostic})
	}
	fail := func(err error) (WANProfile, error) {
		d.lastKnown = false
		d.generation++
		if d.source != nil {
			d.source.Close()
			d.source = nil
		}
		profile := WANProfile{ID: "network-unknown"}
		d.lastReason, d.lastChanged = "observation-failed-"+phase, d.now()
		d.lastFailureReason, d.lastFailureAt = d.lastReason, d.lastChanged
		d.lastFailureDetail = epochFailureDetail(err)
		publish(profile)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return profile, err
		}
		return profile, ErrNetworkUnavailable
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if !d.seeded {
		var seed [8]byte
		if _, err := io.ReadFull(d.entropy, seed[:]); err != nil {
			return fail(err)
		}
		d.seed, d.seeded = binary.BigEndian.Uint64(seed[:])&((1<<48)-1), true
	}
	if d.source == nil {
		phase = "observer-start"
		d.observerRestarts++
		var err error
		d.source, err = d.factory(ctx)
		if err != nil || d.source == nil {
			return fail(err)
		}
	}
	phase = "event-drain"
	changed, err := d.source.Drain(ctx, d.interfaces)
	if err != nil {
		return fail(err)
	}
	var snapshot epochSnapshot
	for attempt := 0; attempt < 2; attempt++ {
		phase = "snapshot"
		snapshot, err = d.source.Snapshot(ctx)
		if err != nil || snapshot.bootID == "" || snapshot.wanInterface == "" || len(snapshot.parts) == 0 || len(snapshot.interfaces) == 0 {
			return fail(err)
		}
		// Watch both the previous and current underlay while it transitions.
		watched := make(map[uint32]bool, len(d.interfaces)+len(snapshot.interfaces))
		for index := range d.interfaces {
			watched[index] = true
		}
		for index := range snapshot.interfaces {
			watched[index] = true
		}
		phase = "event-drain"
		during, drainErr := d.source.Drain(ctx, watched)
		if drainErr != nil {
			return fail(drainErr)
		}
		changed = changed || during
		if !during {
			break
		}
		if attempt == 1 {
			return fail(ErrNetworkUnavailable)
		}
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	parts := append([]string{"boot=" + snapshot.bootID}, snapshot.parts...)
	sort.Strings(parts)
	digest := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	if changed || !d.lastKnown || d.lastDigest != digest {
		d.generation++
		d.lastChanged = d.now()
		d.lastReason = snapshotChangeReason(d.lastParts, parts)
		if !d.lastKnown {
			d.lastReason = "observer-start"
		} else if changed {
			d.lastReason = "observed-event"
			if source, ok := d.source.(interface{ ChangeReason() string }); ok {
				d.lastReason = source.ChangeReason()
			}
		}
	}
	// Addition modulo 2^48 is injective during this observer lifetime; unlike
	// truncating a hash, it cannot collide with an earlier local generation.
	if d.generation >= 1<<48 {
		return fail(ErrNetworkUnavailable)
	}
	id := fmt.Sprintf("wan-%012x", (d.seed+d.generation)&((1<<48)-1))
	profile := WANProfile{ID: id, WANInterface: snapshot.wanInterface}
	d.lastDigest, d.lastKnown, d.interfaces = digest, true, snapshot.interfaces
	d.lastParts = parts
	publish(profile)
	if err := parent.Err(); err != nil {
		d.callerCancellations.Add(1)
		return WANProfile{ID: "network-unknown"}, err
	}
	return profile, nil
}

// Fixed categories retain the cause of a lost observation without publishing
// addresses, filenames, DNS contents, kernel packets or arbitrary error text.
type epochObservationFailure struct {
	code  string
	cause error
}

func (e epochObservationFailure) Error() string { return e.code }
func (e epochObservationFailure) Unwrap() error { return e.cause }
func epochFailureDetail(err error) string {
	var failure epochObservationFailure
	if errors.As(err, &failure) {
		return failure.code
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	return "observation-unavailable"
}

func snapshotChangeReason(previous, current []string) string {
	for _, group := range []struct{ prefix, label string }{{"boot=", "boot"}, {"default=", "default-route"}, {"link=", "link"}, {"addr=", "address"}, {"dns=", "dns"}} {
		selectParts := func(parts []string) string {
			var selected []string
			for _, part := range parts {
				if strings.HasPrefix(part, group.prefix) {
					selected = append(selected, part)
				}
			}
			sort.Strings(selected)
			return strings.Join(selected, "\n")
		}
		if selectParts(previous) != selectParts(current) {
			return "snapshot-" + group.label
		}
	}
	return "snapshot-other"
}
