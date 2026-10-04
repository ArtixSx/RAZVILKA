package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var errWGInactiveUnknown = errors.New("WireGuard runtime inactivity is not confirmed")

// VerifyRuntimeInactive is an observation, never a Stop/recovery operation.
// The caller must already own the common operation admission. Retained private
// intent is allowed only with its exact, settled removal receipt; absence of a
// process or an old successful Deactivate is insufficient.
func (a *WARPWireGuardAdapter) VerifyRuntimeInactive(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	err := a.verifyRuntimeInactive(ctx, verifyWGProcessesInactive)
	return errors.Join(err, ctx.Err())
}

func (a *WARPWireGuardAdapter) verifyRuntimeInactive(ctx context.Context, processes func(context.Context, []string) error) error {
	if a == nil || processes == nil || !filepath.IsAbs(a.StateRoot) || filepath.Clean(a.StateRoot) != a.StateRoot || !filepath.IsAbs(a.RuntimeConfigPath) {
		return errWGInactiveUnknown
	}
	spec, err := a.endpointSpec()
	if err != nil {
		return err
	}
	interfaces := []string{a.interfaceName(), a.interfaceName() + "-canary"}
	observe := func() error {
		if err := errors.Join(ctx.Err(), a.checkWGPolicyOperation()); err != nil {
			return err
		}
		state, owned, err := a.deactivationOwnership(ctx)
		if err != nil {
			return err
		}
		if owned {
			ref, err := a.committedWGPolicyReference(state)
			if err != nil {
				return err
			}
			status, err := a.inspectWGPolicyReference(ctx, ref, "")
			if err != nil || !status.Removed || status.Unknown || status.Promoted {
				return errors.Join(err, errWGInactiveUnknown)
			}
			if err := a.wgPolicyAbsent(ctx, ref); err != nil {
				return err
			}
			if state.WireGuardEndpoint != nil {
				route, rule, err := a.inspectWGEndpoint(ctx, state.WireGuardEndpoint)
				if err != nil || route || rule {
					return errors.Join(err, errWGInactiveUnknown)
				}
			}
		} else {
			_, exists, err := readWARPCleanupFile(filepath.Join(a.StateRoot, wgPolicyReferenceFile), policyAdditionMaxBytes)
			if err != nil || exists {
				return errors.Join(err, errWGInactiveUnknown)
			}
		}
		if err := a.verifyWGInactiveLinks(ctx, interfaces); err != nil {
			return err
		}
		for _, family := range []int{4, 6} {
			args := []string{"-N"}
			if family == 6 {
				args = append(args, "-6")
			}
			data, err := a.run(ctx, a.ip(), append(args, "rule", "show")...)
			if err != nil || len(data) > 1<<20 {
				return errors.Join(err, errWGInactiveUnknown)
			}
			for _, line := range strings.Split(string(data), "\n") {
				fields := strings.Fields(line)
				if len(fields) == 0 {
					continue
				}
				priority, err := strconv.Atoi(strings.TrimSuffix(fields[0], ":"))
				if err != nil || priority < 0 {
					return errWGInactiveUnknown
				}
				if priority >= spec.PriorityBase && priority <= spec.PriorityEnd || priority >= spec.SharedPriorityBase && priority <= spec.SharedPriorityEnd || priority == spec.EndpointPriority || priority >= 18050 && priority < 18066 {
					return errWGInactiveUnknown
				}
			}
		}
		// A foreign route in an owned namespace is an unknown outcome. Never
		// adopt or remove it to make inactivity appear true.
		for _, table := range []int{spec.Table, spec.EndpointTable, 219} {
			for _, family := range []int{4, 6} {
				if err := AssertPolicyDefaultUnreferenced(ctx, a.Runner, a.ip(), PolicyState{Table: table}, family); err != nil {
					return err
				}
				data, err := a.readWGCompleteNumericTable(ctx, table, family)
				if err != nil {
					return err
				}
				rows, err := parseWGEndpointRoutes(data)
				if err != nil || len(rows) != 0 {
					return errors.Join(err, errWGInactiveUnknown)
				}
			}
		}
		return processes(ctx, interfaces)
	}
	if err := observe(); err != nil {
		return err
	}
	// Observe both sides of the process inventory; no cached absence is used.
	return observe()
}

// An unused Linux FIB table can report ENOENT instead of an empty JSON array.
// Recognize only the bounded exact diagnostic of this family, then confirm it
// with the existing full numeric text reader. Any route or other error refuses.
func (a *WARPWireGuardAdapter) readWGCompleteNumericTable(ctx context.Context, table, family int) ([]byte, error) {
	if family != 4 && family != 6 || table < 1 || table > 252 {
		return nil, errWGInactiveUnknown
	}
	args := []string{"-N"}
	if family == 6 {
		args = append(args, "-6")
	}
	args = append(args, "-j", "route", "show", "table", strconv.Itoa(table))
	data, err := a.run(ctx, a.ip(), args...)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(data) > 1<<20 {
		return nil, errWGInactiveUnknown
	}
	if err == nil {
		return data, nil
	}
	message := strings.TrimSpace(string(data))
	if strings.HasPrefix(message, "[]\n") {
		message = strings.TrimSpace(strings.TrimPrefix(message, "[]\n"))
	}
	if strings.HasSuffix(message, "\n[]") {
		message = strings.TrimSpace(strings.TrimSuffix(message, "\n[]"))
	}
	if strings.HasPrefix(message, "[") && strings.HasSuffix(message, "]") {
		message = strings.TrimSpace(message[1 : len(message)-1])
	}
	absent := fmt.Sprintf("Error: ipv%d: FIB table does not exist.", family)
	if message != absent && message != absent+"\nDump terminated" {
		return nil, err
	}
	confirmation, confirmErr := readPolicyTable(ctx, numericPolicyReadRunner{base: a.Runner}, a.ip(), PolicyState{Table: table}, family)
	if confirmErr != nil || strings.TrimSpace(string(confirmation)) != "" {
		return nil, errors.Join(confirmErr, errWGInactiveUnknown)
	}
	return []byte("[]"), nil
}

func (a *WARPWireGuardAdapter) verifyWGInactiveLinks(ctx context.Context, interfaces []string) error {
	data, err := a.run(ctx, a.ip(), "-j", "link", "show")
	if err != nil || len(data) > 1<<20 {
		return errors.Join(err, errWGInactiveUnknown)
	}
	var links []struct {
		Name string `json:"ifname"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if d.Decode(&links) != nil || links == nil || len(links) == 0 || len(links) > 4096 || d.Decode(&struct{}{}) != io.EOF {
		return errWGInactiveUnknown
	}
	seen := map[string]bool{}
	for _, link := range links {
		if link.Name == "" || seen[link.Name] {
			return errWGInactiveUnknown
		}
		seen[link.Name] = true
		for _, iface := range interfaces {
			if link.Name == iface {
				return errWGInactiveUnknown
			}
		}
	}
	return ctx.Err()
}
