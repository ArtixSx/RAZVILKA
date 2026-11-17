package dataplane

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/dnscontrol"
)

type acceptedPrefixTestOwner struct {
	DomainPolicyTCPCaptureOwner
	calls int
}

func (o *acceptedPrefixTestOwner) AdmitTCP(context.Context, DomainPolicyTCPSocket) (DomainPolicyTCPFlowLease, error) {
	o.calls++
	return nil, ErrDomainPolicyTCPConsumer
}

type acceptedPrefixTestLease struct{ DomainPolicyTCPFlowLease }

func acceptedPrefixTestResult() domainTCPAcceptedPrefix {
	a := &domainAcceptedTCP{}
	a.self = a
	a.open.Store(true)
	return domainTCPAcceptedPrefix{accepted: a, lease: &acceptedPrefixTestLease{}}
}

func TestDomainAcceptedPrefixInitialFailureCannotAdmit(t *testing.T) {
	owner := &acceptedPrefixTestOwner{}
	c := &DomainPolicyTCPCapture{owner: owner}
	c.self = c
	m := &DomainPolicyTCPCaptureMapping{capture: c, source: &dnscontrol.SyntheticDNSMapping{}, ctx: context.Background()}
	m.self = m
	out, err := c.acceptedPrefix(context.Background(), &net.TCPConn{}, DomainPolicyTCPSocket{}, m.source, m, domainTCPAcceptedPrefixInput{owner: owner})
	if err == nil || out.accepted != nil || out.lease != nil || owner.calls != 0 {
		t.Fatal("failed initial mapping issued admission", err, owner.calls)
	}
}

func TestDomainAcceptedPrefixObservedLifetime(t *testing.T) {
	sentinel := errors.New("closing failure")
	for _, mode := range []string{"success", "body-error", "closing-error", "no-callback", "double-callback", "late-callback", "recovered-panic", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), syntheticExecutionRegistrarKey{}, &executionResourceScope{}), time.Second)
			defer cancel()
			tentative := acceptedPrefixTestResult()
			var saved func(context.Context) error
			var child context.Context
			calls := 0
			observe := func(c context.Context, use func(context.Context) error) error {
				saved = use
				if mode == "no-callback" || mode == "late-callback" {
					return nil
				}
				if mode == "recovered-panic" {
					defer func() { _ = recover() }()
				}
				err := use(c)
				if mode == "double-callback" {
					_ = use(c)
				}
				if mode == "closing-error" {
					return sentinel
				}
				return err
			}
			read := func(c context.Context) (domainTCPAcceptedPrefix, error) {
				calls++
				child = c
				if mode == "recovered-panic" {
					panic("test")
				}
				if mode == "body-error" {
					return tentative, sentinel
				}
				if mode == "canceled" {
					cancel()
				}
				return tentative, nil
			}
			out, err := domainTCPAcceptedPrefixObserved(ctx, observe, read)
			if mode == "success" {
				if err != nil || out.accepted != tentative.accepted || !out.accepted.open.Load() {
					t.Fatal("complete result refused", err)
				}
				if child == ctx || child.Err() == nil || ctx.Err() != nil {
					t.Fatal("observed context escaped or original context canceled")
				}
				out.revoke()
				return
			}
			if err == nil || out.accepted != nil || out.lease != nil {
				t.Fatal("incomplete observation published result", mode, err)
			}
			if calls > 0 && mode != "recovered-panic" && tentative.accepted.open.Load() {
				t.Fatal("tentative accepted marker still open")
			}
			if mode == "late-callback" {
				if saved(ctx) == nil || calls != 0 {
					t.Fatal("late callback entered body")
				}
			}
			if (mode == "body-error" || mode == "closing-error") && !errors.Is(err, sentinel) {
				t.Fatal("original error lost", err)
			}
		})
	}
}

func TestDomainAcceptedPrefixObservedJoinsEnteredReader(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), syntheticExecutionRegistrarKey{}, &executionResourceScope{}), time.Second)
	defer cancel()
	entered, exited := make(chan struct{}), make(chan struct{})
	tentative := acceptedPrefixTestResult()
	out, err := domainTCPAcceptedPrefixObserved(ctx, func(c context.Context, use func(context.Context) error) error {
		go func() { defer close(exited); _ = use(c) }()
		<-entered
		return nil
	}, func(c context.Context) (domainTCPAcceptedPrefix, error) {
		close(entered)
		<-c.Done()
		return tentative, c.Err()
	})
	if err == nil || out.accepted != nil || tentative.accepted.open.Load() {
		t.Fatal("asynchronous incomplete reader accepted", err)
	}
	// The consumer body is joined before return; its caller goroutine may be
	// finishing its final defer, so join that too before the test exits.
	<-exited
}

func TestDomainAcceptedPrefixObservedGoexitRevokesResult(t *testing.T) {
	done := make(chan struct{})
	tentative := acceptedPrefixTestResult()
	go func() {
		defer close(done)
		ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), syntheticExecutionRegistrarKey{}, &executionResourceScope{}), time.Second)
		defer cancel()
		_, _ = domainTCPAcceptedPrefixObserved(ctx, func(c context.Context, use func(context.Context) error) error {
			_ = use(c)
			runtime.Goexit()
			return nil
		}, func(context.Context) (domainTCPAcceptedPrefix, error) { return tentative, nil })
	}()
	<-done
	if tentative.accepted.open.Load() {
		t.Fatal("Goexit leaked provisional result")
	}
}

func TestDomainAcceptedPrefixFrozenInput(t *testing.T) {
	for _, mode := range []string{"owner", "xray", "policy", "spec", "copy"} {
		t.Run(mode, func(t *testing.T) {
			owner := &acceptedPrefixTestOwner{}
			c := &DomainPolicyTCPCapture{owner: owner, xray: &DomainPolicyTCPXray{}, policy: &DomainPolicy{}}
			c.self = c
			input := domainTCPAcceptedPrefixInput{owner: owner, xray: c.xray, policy: c.policy, spec: c.spec}
			if input.current(c) != nil {
				t.Fatal("original snapshot refused")
			}
			switch mode {
			case "owner":
				c.owner = &acceptedPrefixTestOwner{}
			case "xray":
				c.xray = &DomainPolicyTCPXray{}
			case "policy":
				c.policy = &DomainPolicy{}
			case "spec":
				c.spec.Listen = netip.MustParseAddrPort("127.0.0.1:8443")
			case "copy":
				c.self = &DomainPolicyTCPCapture{}
			}
			if input.current(c) == nil {
				t.Fatal("changed input accepted", mode)
			}
		})
	}
}

func TestDomainAcceptedPrefixOriginalSourcesCannotMintAdmission(t *testing.T) {
	f, kernel, runner, s := mappingReadSourcesFixture(t)
	prepared := s.prepared
	out, err := f.capture.acceptedPrefix(f.ctx, &net.TCPConn{}, DomainPolicyTCPSocket{}, kernel.capture.mapping, prepared, domainTCPAcceptedPrefixInput{owner: f.owner, spec: f.capture.spec, xray: f.capture.xray, policy: f.capture.policy})
	if err == nil || out.accepted != nil || out.lease != nil || runner.calls != 0 {
		t.Fatal("static tuple minted live prefix", err, runner.calls)
	}
}

func TestDomainAcceptedPrefixActualFileClosingDiscardsTentativeResult(t *testing.T) {
	r, ctx := domainFileObservationModel(t)
	ctx = context.WithValue(ctx, syntheticExecutionRegistrarKey{}, &executionResourceScope{})
	tentative := acceptedPrefixTestResult()
	var retained *xrayDomainTCPFileObservation
	out, err := domainTCPAcceptedPrefixObserved(ctx, func(c context.Context, use func(context.Context) error) error { return use(c) }, func(c context.Context) (domainTCPAcceptedPrefix, error) {
		err := r.withFileObservation(c, func(files *xrayDomainTCPFileObservation) error {
			acceptedCtx := context.WithValue(c, domainAcceptedTCPKey{}, tentative.accepted)
			child, closeChild, err := files.forOriginalToolRead(c, acceptedCtx, r)
			if err != nil {
				return err
			}
			defer closeChild()
			retained = child
			file, err := os.OpenFile(r.executable.path, os.O_WRONLY, 0)
			if err != nil {
				return err
			}
			_, writeErr := file.WriteAt([]byte("X"), 0)
			if err := errors.Join(writeErr, file.Close()); err != nil {
				return err
			}
			if err := os.Chtimes(r.executable.path, r.executable.info.ModTime(), r.executable.info.ModTime()); err != nil {
				return err
			}
			// All original metadata remains equal, so the outer full-byte closing
			// (not the provisional view) must detect the changed executable.
			return r.filesCurrentForObservation(acceptedCtx, child)
		})
		return tentative, err
	})
	if !errors.Is(err, ErrXrayDomainTCPOriginal) || out.accepted != nil || out.lease != nil || tentative.accepted.open.Load() {
		t.Fatal("failed full-byte closing published accepted flow", err)
	}
	if retained == nil || retained.open.Load() || retained.current(retained.ctx, r) == nil {
		t.Fatal("accepted child view escaped its parent")
	}
}

func TestDomainAcceptedPrefixObserverPanicOrGoexitJoinsReader(t *testing.T) {
	for _, mode := range []string{"panic", "goexit"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), syntheticExecutionRegistrarKey{}, &executionResourceScope{}), time.Second)
			defer cancel()
			entered, exited, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
			tentative := acceptedPrefixTestResult()
			var recovered any
			go func() {
				defer close(finished)
				defer func() { recovered = recover() }()
				_, _ = domainTCPAcceptedPrefixObserved(ctx, func(c context.Context, use func(context.Context) error) error {
					go func() { defer close(exited); _ = use(c) }()
					<-entered
					if mode == "panic" {
						panic("observer failure")
					}
					runtime.Goexit()
					return nil
				}, func(c context.Context) (domainTCPAcceptedPrefix, error) {
					close(entered)
					<-c.Done()
					return tentative, c.Err()
				})
			}()
			<-finished
			if mode == "panic" && recovered != "observer failure" {
				t.Fatal("observer panic swallowed", recovered)
			}
			if tentative.accepted.open.Load() {
				t.Fatal("observer abort returned before revoking joined tentative result")
			}
			<-exited
		})
	}
}
