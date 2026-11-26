//go:build !linux || !razvilka_native_fixture

package dataplane

func mihomoLiveHealthCheckingFixtureFaultLocked(*mihomoLiveResource, *mihomoLiveHealthCheck) {}
