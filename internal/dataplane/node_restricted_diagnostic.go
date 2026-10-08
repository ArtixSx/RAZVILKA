package dataplane

import (
	"context"
	"net/netip"
	"time"

	"github.com/ArtixSx/razvilka/internal/catalog"
	"github.com/ArtixSx/razvilka/internal/evidence"
)

// probeRestrictedDiagnostic answers a user's concrete question even when the
// independent direct egress oracle is unavailable. This DOES NOT relax the
// existing route proof: Available remains false, no proof is promoted, and no
// egress address or raw observation is published. A future alternative proof
// mechanism needs its own native negative controls before enabling Apply.
func (c *ExactNodeChecker) probeRestrictedDiagnostic(ctx context.Context, r *NodeCheckResult, address, proxyIP string, service catalog.Service) {
	if ctx.Err() != nil || c.serviceProbe == nil {
		return
	}
	if checkNodeResourceURL(ctx, selectedNodeProbe(service).URL, netip.Addr{}) != nil {
		return
	}
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < 2*time.Second {
		return
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	started := c.currentTime()
	proof, err := c.serviceProbe(probeCtx, address, r.RoutePathID, proxyIP, service)
	status, message := "unknown", "Прямой контроль недоступен; отдельная сервисная проба не завершена."
	if err == nil && probeCtx.Err() == nil && proof.AssuranceLevel().AtLeast(evidence.Service) && proof.Service == service.ID && proof.Verdict == evidence.VerdictPass && proof.RoutePathID == r.RoutePathID && proof.ExpectedRoutePathID == r.RoutePathID && proof.ObservedRoutePathID == r.RoutePathID {
		status = "response_observed"
		message = "Сервис ответил через проверочный канал, но независимое доказательство пути отсутствует. Автоприменение не разрешено."
	}
	r.addStage("service_diagnostic", status, message, started, c.currentTime())
	r.Available = false
	r.Verdict = evidence.VerdictInconclusive
	r.EgressIP = ""
	r.Message = message
}
