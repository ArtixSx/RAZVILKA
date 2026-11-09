//go:build linux && razvilka_native_fixture

package dataplane

import (
	"runtime"
	"strings"
	"sync"
	"time"
)

type DomainTCPNativeMetric struct {
	Calls   int64
	Bytes   int64
	Elapsed time.Duration
}

// Snapshot completed observations only. It neither resets nor stops the
// counters; an in-flight opening/closing can finish after this diagnostic.
// This is not a readiness, publication, ownership or cleanup proof.
func DomainTCPNativeMeasurementSnapshot() map[string]DomainTCPNativeMetric {
	domainTCPNativeMetrics.Lock()
	defer domainTCPNativeMetrics.Unlock()
	out := make(map[string]DomainTCPNativeMetric, len(domainTCPNativeMetrics.values))
	for k, v := range domainTCPNativeMetrics.values {
		out[k] = v
	}
	return out
}

// Only fixed, bounded labels leave this native fixture. Neither filesystem
// paths, caller arguments nor arbitrary runtime function names are reported.
// Wrapper labels describe stack context, not exact opening/closing callsites:
// a wrapper may surround an independent hash in its callback.
func domainTCPNativeHashBucket() string {
	var pcs [64]uintptr
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs[:])])
	wrapper := "direct"
	owners := make([]string, 0, 2)
	for {
		frame, more := frames.Next()
		name := strings.TrimPrefix(frame.Function, "github.com/ArtixSx/razvilka/internal/dataplane.")
		if index := strings.Index(name, ".func"); index >= 0 {
			name = name[:index]
		}
		if wrapper == "direct" {
			switch name {
			case "(*XrayDomainTCPExecutionResource).withFileObservation":
				wrapper = "file-opening-wrapper"
			case "(*XrayDomainTCPExecutionResource).withFileObservationAfterOpening":
				wrapper = "after-opening-scope"
			}
		}
		label := ""
		switch name {
		case "(*domainTCPCaptureExecutionResource).guardOriginalBaseline":
			label = "capture-guard"
		case "(*DomainTCPOriginalScope).compareSyntheticMapping", "(*DomainTCPOriginalScope).compareSyntheticMappingWithFiles":
			label = "mapping-compare"
		case "newDomainTCPBaselineKernelOwner":
			label = "initial-kernel"
		case "(*domainTCPBaselineKernelOwner).currentWithFiles":
			label = "kernel-current"
		case "(*domainTCPPreAddRead).observe":
			label = "pre-add"
		case "(*domainTCPCaptureExecutionResource).prepare":
			label = "capture-prepare"
		case "(*syntheticBaselineExecutionResource).prepareBaseline":
			label = "standby-prepare"
		case "(*syntheticBaselineExecutionResource).compareInOriginalFileObservation":
			label = "standby-read"
		case "(*syntheticBaselineExecutionResource).prepareCapture":
			label = "standby-capture"
		case "issueDomainTCPCaptureResource":
			label = "capture-issue"
		case "(*SyntheticDNSExecutionBinding).issueBaseline":
			label = "standby-issue"
		case "(*DomainPolicyTCPCapture).PrepareSyntheticMapping":
			label = "capture-mapping"
		case "(*DomainPolicyTCPCapture).observePreparationClosing":
			label = "capture-closing"
		case "(*domainTCPCaptureEffectRunner).Run":
			label = "capture-effect-admission"
		case "(*syntheticBaselineEffectRunner).Run":
			label = "standby-effect-admission"
		case "(*XrayDomainTCPExecutionResource).start":
			label = "process-start"
		case "(*XrayDomainTCPExecutionResource).cleanup":
			label = "process-cleanup"
		case "AcquireXrayDomainTCPExecutionResource":
			label = "resource-acquire"
		}
		if label != "" && len(owners) < 2 && (len(owners) == 0 || owners[0] != label) {
			owners = append(owners, label)
		}
		if !more {
			break
		}
	}
	if len(owners) == 0 {
		owners = append(owners, "other")
	}
	return "hash-stack/" + wrapper + "/" + strings.Join(owners, "/")
}

var domainTCPNativeMetrics struct {
	sync.Mutex
	active bool
	values map[string]DomainTCPNativeMetric
}

// CI-only observation, never a scope, source or effect admission.
func StartDomainTCPNativeMeasurement() func() map[string]DomainTCPNativeMetric {
	domainTCPNativeMetrics.Lock()
	if domainTCPNativeMetrics.active {
		domainTCPNativeMetrics.Unlock()
		panic("overlapping domain native measurements")
	}
	domainTCPNativeMetrics.active = true
	domainTCPNativeMetrics.values = make(map[string]DomainTCPNativeMetric)
	domainTCPNativeMetrics.Unlock()
	var once sync.Once
	var result map[string]DomainTCPNativeMetric
	return func() map[string]DomainTCPNativeMetric {
		once.Do(func() {
			domainTCPNativeMetrics.Lock()
			defer domainTCPNativeMetrics.Unlock()
			domainTCPNativeMetrics.active = false
			result = domainTCPNativeMetrics.values
		})
		out := make(map[string]DomainTCPNativeMetric, len(result))
		for k, v := range result {
			out[k] = v
		}
		return out
	}
}
func domainTCPMeasure(name string) func(int64) {
	start := time.Now()
	domainTCPNativeMetrics.Lock()
	active := domainTCPNativeMetrics.active
	domainTCPNativeMetrics.Unlock()
	if !active {
		return func(int64) {}
	}
	bucket := ""
	if name == "whole-executable-hash" {
		attributionStart := time.Now()
		bucket = domainTCPNativeHashBucket()
		domainTCPNativeMetrics.Lock()
		if domainTCPNativeMetrics.active {
			v := domainTCPNativeMetrics.values["native-hash-attribution"]
			v.Calls++
			v.Elapsed += time.Since(attributionStart)
			domainTCPNativeMetrics.values["native-hash-attribution"] = v
		}
		domainTCPNativeMetrics.Unlock()
		start = time.Now() // Exclude diagnostic stack collection from SHA timing.
	}
	return func(bytes int64) {
		domainTCPNativeMetrics.Lock()
		defer domainTCPNativeMetrics.Unlock()
		if !domainTCPNativeMetrics.active {
			return
		}
		elapsed := time.Since(start)
		v := domainTCPNativeMetrics.values[name]
		v.Calls++
		v.Bytes += bytes
		v.Elapsed += elapsed
		domainTCPNativeMetrics.values[name] = v
		if bucket != "" {
			b := domainTCPNativeMetrics.values[bucket]
			b.Calls++
			b.Bytes += bytes
			b.Elapsed += elapsed
			domainTCPNativeMetrics.values[bucket] = b
		}
	}
}
