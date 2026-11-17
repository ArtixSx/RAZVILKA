package dataplane

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/probecheck"
	"net/http"
	"net/netip"
	"strconv"
	"testing"
)

func TestPinnedServiceNetworkTimingKeepsActualSOCKSTLSAndPredicate(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusForbidden} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			backend, roots, _ := newPinnedTLSFixture(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte("service reached"))
			})
			socks := newPinnedSOCKSFixture(t, backend.Listener.Addr().String(), false)
			ctx, m := probecheck.WithNetworkMeasurements(context.Background())
			resp, cleanup, err := socksHTTPGetPinnedTLS(ctx, "https://example.com/health?private=secret", socks.address, netip.MustParseAddr("8.8.8.8"), roots)
			if err != nil {
				t.Fatal(err)
			}
			_, predicateErr := strictServiceResponse("https://example.com/health?private=secret", resp)
			if err := resp.Body.Close(); err != nil {
				t.Fatal(err)
			}
			cleanup()
			rows := m.Close()
			if len(rows) != 1 || !rows[0].SOCKS.Observed || rows[0].SOCKS.Status != "complete" || rows[0].TLS.Status != "complete" || rows[0].Body.Status != "complete" || !rows[0].Headers {
				t.Fatal("missing actual bounded service phases", rows)
			}
			if (predicateErr == nil) != (status == http.StatusOK) {
				t.Fatal("timing promoted failed service status", status, predicateErr)
			}
		})
	}
}
