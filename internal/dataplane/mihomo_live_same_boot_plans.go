package dataplane

import (
	"bytes"
	"errors"
	"os"
)

// Applying persists execution before finishCommit writes global plan files.
// A first candidate therefore legitimately has no plan files at all. Retain
// that exact absence; the frozen definition already contains its original
// Plan. No plan or committed record is synthesized during offline recovery.
func validateMihomoSameBootPlans(expected Plan, plans map[string][]byte, candidate bool) error {
	if candidate && len(plans) == 0 {
		return nil
	}
	return validateMihomoColdPlans(expected, plans)
}
func (c *mihomoSameBootRetirementCursor) capturePlans() error {
	if c == nil || c.owner == nil || c.owner.inputs == nil {
		return ErrMihomoLiveRetirement
	}
	i := c.owner.inputs
	c.intent.Plans = map[string][]byte{}
	for _, name := range mihomoStoppedPlanNames {
		r, err := openMihomoColdRecord(i.roots[0], name, nil)
		if errors.Is(err, os.ErrNotExist) && (i.candidate || name == "latest-committed-plan.json") {
			continue
		}
		if err != nil {
			return err
		}
		c.plans = append(c.plans, r)
		c.intent.Plans[name] = bytes.Clone(r.data)
	}
	if err := validateMihomoSameBootPlans(i.definition.Plan, c.intent.Plans, i.candidate); err != nil {
		return err
	}
	return c.freezePlanComparison()
}
func (c *mihomoSameBootRetirementCursor) plansCurrent() error {
	if c == nil || c.owner == nil || c.owner.inputs == nil {
		return ErrMihomoLiveRetirement
	}
	for _, r := range c.plans {
		if err := r.current(); err != nil {
			return err
		}
	}
	if !c.plansCaptured {
		return nil
	}
	for _, name := range mihomoStoppedPlanNames {
		if _, present := c.intent.Plans[name]; present {
			continue
		}
		if _, err := c.owner.inputs.roots[0].Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return errors.Join(ErrMihomoLiveRetirement, err)
		}
	}
	return nil
}

// The native delete owner borrows these SAME captured plan descriptors and
// fixed-name absences. It cannot substitute a parsed plan or reopen a record.
func (c *mihomoSameBootRetirementCursor) freezePlanComparison() error {
	if c == nil || c.owner == nil || c.owner.inputs == nil || c.plansCaptured {
		return ErrMihomoLiveRetirement
	}
	o := c.owner
	o.planRecords = nil
	o.planMissing = nil
	for _, name := range mihomoStoppedPlanNames {
		if _, exists := c.intent.Plans[name]; !exists {
			o.planMissing = append(o.planMissing, name)
			continue
		}
		var held *mihomoColdRecord
		for _, r := range c.plans {
			if r.root == o.inputs.roots[0] && r.name == name {
				if held != nil {
					return ErrMihomoLiveRetirement
				}
				held = r
			}
		}
		if held == nil {
			return ErrMihomoLiveRetirement
		}
		o.planRecords = append(o.planRecords, held)
	}
	c.plansCaptured = true
	return c.plansCurrent()
}
func (o *mihomoSameBootCleanup) planInputsCurrent() error {
	if o == nil || o.inputs == nil {
		return ErrMihomoLiveRetirement
	}
	for _, r := range o.planRecords {
		if err := r.current(); err != nil {
			return err
		}
	}
	for _, name := range o.planMissing {
		if _, err := o.inputs.roots[0].Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return errors.Join(ErrMihomoLiveRetirement, err)
		}
	}
	return nil
}
