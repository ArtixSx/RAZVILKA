package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
)

// Called under the SAME scope metadata mutex, after the original producer's
// actual cleanup readbacks. A new stage can replace its pinned image only
// after BOTH previous actual writer acknowledgments. No caller supplies rows.
func (r *domainTCPFailureCleanup) publishStageLocked(ctx context.Context, stage, id string, image []byte) error {
	if r.local(ctx, r.resource) != nil || id == "" {
		return ErrPolicyAdditionUnknown
	}
	if stage != "process" && stage != "capture" && stage != "standby" {
		return ErrPolicyAdditionUnknown
	}
	if len(r.image) == 0 {
		if stage != "process" || id != r.resource.id {
			return ErrPolicyAdditionUnknown
		}
	} else if r.imageStage == stage {
		if !bytes.Equal(r.image, image) {
			return ErrExecutionJournal
		}
		if r.imageACK {
			return r.resource.records.current(ctx, true)
		}
	} else {
		if stage == "standby" {
			if !r.imageACK || r.imageStage != "capture" || r.standby == nil || r.standby.self != r.standby || r.standby.process != r.resource || r.standby.baseline == nil || id != filepath.Base(r.standby.baseline.relative) || len(r.standbyImage) == 0 || !bytes.Equal(r.standbyImage, image) {
				return ErrPolicyAdditionUnknown
			}
		} else {
			if !r.imageACK || r.imageStage != "process" || stage != "capture" || r.capture == nil || r.capture.self != r.capture || r.capture.process != r.resource || r.capture.mapping != r.resource.material.mapping || id != filepath.Base(r.capture.relative) {
				return ErrPolicyAdditionUnknown
			}
			var old, current Execution
			if json.Unmarshal(r.image, &old) != nil || json.Unmarshal(image, &current) != nil || len(old.Resources) != len(current.Resources) {
				return ErrExecutionJournal
			}
			found := false
			for i := range old.Resources {
				if old.Resources[i].ID == id {
					if found || current.Resources[i].ID != id || current.Resources[i].State != "removed" || current.Resources[i].Phase != "removed" {
						return ErrExecutionJournal
					}
					old.Resources[i].State, old.Resources[i].Phase = "removed", "removed"
					found = true
				}
			}
			canonical, err := json.Marshal(old)
			if !found || err != nil || !bytes.Equal(canonical, image) {
				return errors.Join(ErrExecutionJournal, err)
			}
		}
	}
	if r.imageStage != stage || len(r.image) == 0 {
		r.image = bytes.Clone(image)
		r.imageStage = stage
		r.imageACK = false
	}
	if err := r.cursor.publish(ctx, r.image); err != nil {
		return err
	}
	if r.fault != nil {
		if err := r.fault(stage); err != nil {
			return err
		}
	}
	r.imageACK = true
	return nil
}

func (r *domainTCPFailureCleanup) capturePublicationCurrent(ctx context.Context, capture *domainTCPCaptureExecutionResource) bool {
	if r == nil || r.resource == nil || r.local(ctx, r.resource) != nil || r.capture != capture || len(r.image) == 0 {
		return false
	}
	if r.imageStage == "capture" || r.imageStage == "standby" && r.captureDetached {
		return true
	}
	// The original failed finalizer may already have changed its row before
	// losing publication. The new process frame retains that SAME typed row;
	// accepting it here permits only fresh receipt/kernel cleanup readbacks.
	if r.imageStage == "process" && r.imageACK {
		var e Execution
		if json.Unmarshal(r.image, &e) != nil {
			return false
		}
		for _, row := range e.Resources {
			if row.ID == filepath.Base(capture.relative) {
				return row.Kind == "domain-tcp-capture" && row.State == "removed" && row.Phase == "removed"
			}
		}
	}
	return false
}
