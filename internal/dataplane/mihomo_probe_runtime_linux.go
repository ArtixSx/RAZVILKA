//go:build linux

package dataplane

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"slices"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/evidence"
	"github.com/ArtixSx/razvilka/internal/probecheck"
)

func (r *mihomoProbeResource) run(ctx context.Context) (result error) {
	returned := false
	defer func() {
		if !returned {
			r.actionErr = errors.Join(r.actionErr, ErrMihomoProbe)
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		result = errors.Join(result, r.clean(r.scope.contextWith(cleanup)))
		r.actionErr = errors.Join(r.actionErr, result)
	}()
	if err := r.current(ctx); err != nil {
		return err
	}
	child, err := r.source.RunProbeAdmitted(ctx, r.control, r.cleanup, r.start, func(ctx context.Context, child *components.MihomoProbeProcess) error {
		r.child = child // Retain the SAME actual child before any observation.
		ready, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		var birth mihomoProbeObservation
		for {
			var err error
			birth, err = observeMihomoProbeProcess(ready, child, r.definition.Source, r.adapter.provider, r.definition.NetworkIdentity)
			if err == nil {
				break
			}
			select {
			case <-ready.Done():
				return errors.Join(ErrMihomoProbe, ready.Err(), err)
			case <-time.After(25 * time.Millisecond):
			}
		}
		if err := r.current(ctx); err != nil {
			return err
		}
		if err := r.phase(ctx, "listener-ready", true); err != nil {
			return err
		}
		if err := r.observeService(ctx); err != nil {
			return err
		}
		closing, err := observeMihomoProbeProcess(ctx, child, r.definition.Source, r.adapter.provider, r.definition.NetworkIdentity)
		if err != nil || !birth.same(closing) {
			return errors.Join(ErrMihomoProbe, err)
		}
		return r.current(ctx)
	})
	if child != nil {
		r.child = child
	}
	returned = true
	return err
}

func (r *mihomoProbeResource) clean(ctx context.Context) error {
	if r == nil || r.self != r || xraySelectedTCPFinite(ctx) != nil {
		return ErrMihomoProbe
	}
	if err := r.control.CurrentForCleanupOperation(ctx, r.cleanup); err != nil {
		return err
	}
	r.scope.mu.Lock()
	err := r.local(ctx, false)
	r.scope.mu.Unlock()
	if err != nil {
		return err
	}
	if err := r.source.CleanupProbe(ctx); err != nil {
		return err
	}
	if err := observeMihomoProbeListenerAbsent(ctx, r.adapter.provider, r.definition.NetworkIdentity, r.definition.Source.SOCKSPort); err != nil {
		return err
	}
	phase := "unused"
	if r.attempted {
		phase = "removed"
	}
	if err := r.phase(ctx, phase, false); err != nil {
		return err
	}
	r.settled = true
	return nil
}

func (r *mihomoProbeResource) observeService(ctx context.Context) error {
	service := r.definition.Service
	status := 0
	for _, probe := range mihomoRequiredProbes(service) {
		var err error
		status, err = r.observeProbe(ctx, probe)
		if err != nil {
			return err
		}
	}
	r.result = MihomoServiceProbe{ReviewSHA256: r.definition.Source.ReviewSHA256, ConfigSHA256: r.definition.Source.ConfigSHA256, ServiceID: service.ID, NetworkProfile: r.definition.NetworkProfile, HTTPStatus: status, ServiceVerified: true}
	return nil
}

func (r *mihomoProbeResource) observeProbe(ctx context.Context, probe catalog.Probe) (int, error) {
	service := r.definition.Service
	addresses, err := resolveNodeServiceIPv4(ctx, probe.URL, nil)
	if err != nil || len(addresses) == 0 {
		return 0, errors.Join(ErrMihomoProbe, err)
	}
	status := 0
	for _, address := range addresses {
		status, err = r.observeProbeAddress(ctx, service, probe, address)
		if err != nil {
			return 0, err
		}
	}
	closing, err := resolveNodeServiceIPv4(ctx, probe.URL, nil)
	if err != nil || !slices.Equal(addresses, closing) {
		return 0, errors.Join(ErrMihomoProbe, err)
	}
	return status, nil
}

func (r *mihomoProbeResource) observeProbeAddress(ctx context.Context, service catalog.Service, probe catalog.Probe, address netip.Addr) (int, error) {
	if err := r.current(ctx); err != nil {
		return 0, err
	}
	if err := checkNodeResourceURL(ctx, probe.URL, address); err != nil {
		return 0, err
	}
	var chain []string
	response, closeTransport, err := socksHTTPGetPinnedObservedTLS(ctx, probe.URL, mihomoProbeEndpoint(r.definition.Source.SOCKSPort).String(), address, nil, &service, &chain)
	if err != nil {
		return 0, err
	}
	defer closeTransport()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, probecheck.MaxBodyBytes+1))
	closeErr := response.Body.Close()
	defer clear(body)
	if readErr != nil || closeErr != nil {
		return 0, errors.Join(readErr, closeErr)
	}
	assessment := probecheck.Evaluate(service, probe, probecheck.Observation{RequestedURL: probe.URL, FinalURL: probecheck.FinalURL(response, probe.URL), RedirectChain: chain, HTTPStatus: response.StatusCode, ContentType: response.Header.Get("Content-Type"), Body: body, BodyTruncated: len(body) > probecheck.MaxBodyBytes})
	if assessment.Verdict != evidence.VerdictPass {
		return 0, ErrMihomoProbe
	}
	if err := checkNodeResourceURL(ctx, probe.URL, address); err != nil {
		return 0, err
	}
	if err := r.current(ctx); err != nil {
		return 0, err
	}
	return response.StatusCode, nil
}
