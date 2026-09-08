package probecheck

import (
	"net/http"

	"github.com/ArtixSx/razvilka/internal/catalog"
)

// RecordingClient copies the client, retaining its transport, timeout and
// safety policy. The per-request chain never mutates a shared client.
func RecordingClient(client *http.Client, service catalog.Service, chain *[]string) *http.Client {
	copy := *client
	previous := client.CheckRedirect
	copy.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		*chain = append(*chain, request.URL.String())
		if rejectedRedirect(service, ServiceProbe(service), Observation{RequestedURL: service.ProbeURL, RedirectChain: *chain}) != "" {
			return http.ErrUseLastResponse
		}
		if previous != nil {
			return previous(request, via)
		}
		if len(via) >= 4 {
			return http.ErrUseLastResponse
		}
		return nil
	}
	return &copy
}

// ServiceProbe preserves catalog predicates when an adapter only receives a
// service with the currently selected ProbeURL.
func ServiceProbe(service catalog.Service) catalog.Probe {
	probe := catalog.Probe{ID: "primary", URL: service.ProbeURL, Required: true}
	// Older catalogs only carry ProbeURL. Keep the well-known no-content probe
	// strict there too, including candidate activation checks.
	if service.ProbeURL == "https://www.youtube.com/generate_204" {
		probe.Expect.StatusCodes = []int{http.StatusNoContent}
		probe.Expect.RedirectPolicy = "none"
	}
	for _, selected := range service.Probes {
		if selected.URL == service.ProbeURL {
			if len(selected.Expect.StatusCodes) == 0 {
				selected.Expect.StatusCodes = probe.Expect.StatusCodes
			}
			if selected.Expect.RedirectPolicy == "" {
				selected.Expect.RedirectPolicy = probe.Expect.RedirectPolicy
			}
			return selected
		}
	}
	return probe
}

func FinalURL(response *http.Response, fallback string) string {
	if response != nil && response.Request != nil && response.Request.URL != nil {
		return response.Request.URL.String()
	}
	return fallback
}
