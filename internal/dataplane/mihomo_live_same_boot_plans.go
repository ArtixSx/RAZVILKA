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
	c.plansCaptured = true
	return c.plansCurrent()
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
