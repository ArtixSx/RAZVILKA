package dataplane

// Reader9 distinguishes a finite retained health operation from a committed
// runtime. This state is comparison data only: an original private owner,
// control, operation and both authored journal FDs are still required.
const mihomoActiveCheckingState = "active-checking"

// This reader9 comparison header deliberately survives completion/archive.
// It binds document history only; no decoded field can recreate a writer,
// process, source or operation/cleanup capability.
type ExecutionMihomoLiveHealthOperation struct {
	Schema       int    `json:"schema"`
	ID           string `json:"id"`
	PlanID       string `json:"plan_id"`
	PlanDigest   string `json:"plan_digest"`
	BeforeSHA256 string `json:"before_sha256"`
	Phase        string `json:"phase"`
}

func validateMihomoHealthOperation(e Execution) error {
	h := e.MihomoLiveHealthOperation
	if h == nil {
		if e.State == mihomoActiveCheckingState {
			return ErrExecutionJournal
		}
		return nil
	}
	if e.DomainDNSCoexistence != nil {
		return ErrExecutionJournal
	}
	planID := e.PlanID
	if e.ResourcePlanID != "" {
		planID = e.ResourcePlanID
	}
	if h.Schema != 1 || !validPlanDigest(h.ID) || !validPlanDigest(h.BeforeSHA256) || h.PlanID != planID || h.PlanDigest != e.Digest {
		return ErrExecutionJournal
	}
	switch h.Phase {
	case "checking":
		if e.State != mihomoActiveCheckingState {
			return ErrExecutionJournal
		}
	case "settled":
		if e.State != "committed" && e.State != "temporary-complete" {
			return ErrExecutionJournal
		}
	case "retiring":
		if e.State != "rolling-back" {
			return ErrExecutionJournal
		}
	case "retired":
		if e.State != "rolled-back" {
			return ErrExecutionJournal
		}
	default:
		return ErrExecutionJournal
	}
	live := 0
	var definition *ExecutionMihomoLiveDefinition
	for _, row := range e.Resources {
		if row.Kind == "mihomo-live" {
			live++
			definition = row.MihomoLive
			if row.MihomoLive == nil || row.MihomoLive.validateActive() != nil {
				return ErrExecutionJournal
			}
			if h.Phase == "settled" && (row.State != "active" || row.Phase != "active") {
				return ErrExecutionJournal
			}
			if h.Phase == "retired" && (row.State != "removed" || row.Phase != "removed") {
				return ErrExecutionJournal
			}
		} else if row.Kind != "node-transit" || row.NodeTransit == nil {
			return ErrExecutionJournal
		}
		if (h.Phase == "settled" || h.Phase == "retired") && row.Kind == "node-transit" && row.State != "removed" && row.State != "unused" {
			return ErrExecutionJournal
		}
	}
	if e.MihomoTransitHistoryArchive != nil {
		if live != 0 || h.Phase != "settled" {
			return ErrExecutionJournal
		}
	} else if live != 1 {
		return ErrExecutionJournal
	}
	if definition != nil {
		for _, row := range e.Resources {
			if row.Kind == "node-transit" && !mihomoLiveTransitMatches(row.NodeTransit, definition, planID, e.Digest) {
				return ErrExecutionJournal
			}
		}
	}
	return nil
}

func validateMihomoActiveCheckingExecution(e Execution) error {
	if e.State != mihomoActiveCheckingState {
		return nil
	}
	if e.ResourcePlanID != "" || e.MihomoTransitHistoryArchive != nil || e.FinishedAt != "" || len(e.Error) > 4096 {
		return ErrExecutionJournal
	}
	var live *ExecutionMihomoLiveDefinition
	for _, row := range e.Resources {
		if row.Kind == "mihomo-live" {
			if live != nil || row.MihomoLive == nil || row.MihomoLive.validateActive() != nil ||
				(row.State != "active" || row.Phase != "active") && (row.State != "prepared" || row.Phase != "closed") && (row.State != "removed" || row.Phase != "removed") {
				return ErrExecutionJournal
			}
			live = row.MihomoLive
		} else if row.Kind != "node-transit" || row.NodeTransit == nil {
			return ErrExecutionJournal
		}
	}
	if live == nil || live.Plan.PlanID != e.PlanID || live.Plan.Digest != e.Digest {
		return ErrExecutionJournal
	}
	for _, row := range e.Resources {
		if row.Kind != "node-transit" {
			continue
		}
		if !mihomoLiveTransitMatches(row.NodeTransit, live, e.PlanID, e.Digest) {
			return ErrExecutionJournal
		}
	}
	return nil
}

func mihomoLiveTransitMatches(s *NodeTransitSpec, live *ExecutionMihomoLiveDefinition, planID, digest string) bool {
	return s != nil && live != nil && s.Engine == "mihomo" && s.BootID == live.NetworkIdentity.BootID && s.PlanID == planID && s.PlanDigest == digest && s.NetworkProfile == live.NetworkProfile && s.RuntimeID == live.Profile.ConfigSHA256 && s.Interface == live.Policy.Interface && s.Table == live.Policy.Table && s.Priority == 80
}
