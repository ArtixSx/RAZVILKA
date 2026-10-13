package dataplane

import (
	"context"
	"errors"
	"os"
	"reflect"
	"slices"
	"strings"
)

// Ephemeral comparison of the original native child and actual COMMON writer.
// Only original resource/collector operations produce it. Rows and required
// flags are never accepted as an allowance constructor or runtime permission.
type networkPolicyXraySelectedTCPObservation struct {
	resource                      *XraySelectedTCPExecutionResource
	stock                         *networkPolicyXraySelectedTCPStockObservation
	process                       xraySelectedTCPListenerObservation
	borrow                        policyEffectBorrowObservation
	borrowed, absent, beforeStart bool
	joined                        bool
	checksum                      string
	fileInfo                      os.FileInfo
	states                        []string
	rows                          []BackendInventoryRow
	required                      []bool
}

func (o networkPolicyXraySelectedTCPObservation) close() { o.borrow.close() }

func (o networkPolicyXraySelectedTCPObservation) current(ctx context.Context) error {
	if o.stock != nil && o.stock.pair != nil {
		return o.stock.pair.withExecution(ctx, o.resource.material.execution, o.singleCurrent)
	}
	return o.singleCurrent(ctx)
}

func (o networkPolicyXraySelectedTCPObservation) singleCurrent(ctx context.Context) error {
	if o.stock == nil || o.stock.singleCurrent(ctx) != nil {
		return ErrNetworkPolicyConsumers
	}
	r := o.resource
	if value := ctx.Value(xraySelectedTCPPreparedInventoryScopeKey{}); value != nil {
		read, ok := value.(*xraySelectedTCPPreparedInventoryScope)
		if !ok || read == nil || read.resource != r || read.currentFinal(ctx) != nil {
			return ErrNetworkPolicyConsumers
		}
	}
	directory, err := os.Lstat(r.rootPath)
	if err != nil || !networkPolicyPrivateDirectory(directory) || !os.SameFile(r.anchor, directory) {
		return ErrNetworkPolicyConsumers
	}
	if o.borrowed {
		return o.borrow.current(ctx)
	}
	r.commonMu.Lock()
	defer r.commonMu.Unlock()
	if o.absent {
		if r.common != nil {
			return ErrPolicyAdditionReceipt
		}
		for _, name := range []string{policyAdditionFile, policyAdditionLock} {
			if _, err := r.root.Stat(name); !errors.Is(err, os.ErrNotExist) {
				return ErrPolicyAdditionReceipt
			}
		}
		return nil
	}
	p := r.common
	if p == nil || p.checksum != o.checksum || !slices.Equal(p.states, o.states) || o.fileInfo == nil || !os.SameFile(p.fileInfo, o.fileInfo) {
		return ErrPolicyAdditionReceipt
	}
	return p.current(ctx)
}

func equalNetworkPolicyXraySelectedTCPObservations(a, b []networkPolicyXraySelectedTCPObservation) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].resource != b[i].resource || !a[i].stock.equal(b[i].stock) || a[i].borrowed != b[i].borrowed || a[i].absent != b[i].absent ||
			a[i].beforeStart != b[i].beforeStart || a[i].joined != b[i].joined || a[i].checksum != b[i].checksum || !slices.Equal(a[i].states, b[i].states) ||
			!reflect.DeepEqual(a[i].rows, b[i].rows) || !reflect.DeepEqual(a[i].required, b[i].required) {
			return false
		}
		if !a[i].beforeStart && !a[i].joined && (a[i].process.endpoint != b[i].process.endpoint || a[i].process.inode != b[i].process.inode || !a[i].process.process.same(b[i].process.process)) {
			return false
		}
		if !a[i].absent && (a[i].fileInfo == nil || b[i].fileInfo == nil || !os.SameFile(a[i].fileInfo, b[i].fileInfo)) {
			return false
		}
	}
	return true
}

func (c *NetworkPolicyChecks) xraySelectedTCPConsumers(ctx context.Context, lan *LANPolicyRuntimePlan) (out []networkPolicyXraySelectedTCPObservation, result error) {
	if ctx != nil && ctx.Value(xraySelectedTCPReplacementKey{}) != nil {
		p, err := c.xrayReplacement(ctx)
		if err != nil || lan == nil || (!reflect.DeepEqual(lan, p.candidate.plan.LAN) && !reflect.DeepEqual(lan, p.prior.execution.plan.LAN)) {
			return nil, errors.Join(ErrNetworkPolicyConsumers, err)
		}
		defer func() {
			if result != nil {
				closeNetworkPolicyXrayObservations(out)
				out = nil
			}
		}()
		for _, execution := range []*xraySelectedTCPExecution{p.prior.execution, p.candidate} {
			if execution.resource == nil {
				continue
			}
			err := p.withExecution(ctx, execution, func(held context.Context) error {
				observations, err := c.singleXraySelectedTCPConsumers(held, execution.plan.LAN)
				for i := range observations {
					observations[i].stock.pair = p
				}
				out = append(out, observations...)
				return err
			})
			if err != nil {
				return out, err
			}
		}
		return out, nil // Actual A then C writers imply C insert-at-one precedes A.
	}
	return c.singleXraySelectedTCPConsumers(ctx, lan)
}

func (c *NetworkPolicyChecks) singleXraySelectedTCPConsumers(ctx context.Context, lan *LANPolicyRuntimePlan) (out []networkPolicyXraySelectedTCPObservation, result error) {
	stock, err := c.singleXraySelectedTCPStockExecution(ctx)
	if err != nil || stock == nil {
		return nil, err
	}
	if stock.pre != nil {
		return nil, stock.pre.current(ctx) // Never an active consumer allowance.
	}
	r := stock.resource
	if lan == nil || !reflect.DeepEqual(lan, r.definition.Match.LAN) {
		return nil, ErrNetworkPolicyConsumers
	}
	r.observationMu.RLock()
	locked := true
	defer func() {
		if locked {
			r.observationMu.RUnlock()
		}
	}()
	o := networkPolicyXraySelectedTCPObservation{resource: r, stock: stock, beforeStart: !r.startACK}
	defer func() {
		if result != nil {
			o.close()
		}
	}()
	if !o.beforeStart {
		if !r.versionVerified || r.child == nil || r.birth == nil || r.descriptorsClosed {
			return nil, ErrNetworkPolicyConsumers
		}
		read, closeRead, err := r.originalProcessReadContext(ctx, r.material.IsCleanupContext(ctx))
		if err != nil {
			return nil, err
		}
		defer closeRead()
		select {
		case <-r.child.done:
			if !r.material.IsCleanupContext(ctx) || r.child.Joined(read) != nil || xraySelectedTCPObserveListenerAbsent(read, c.identity.provider, c.network, r.definition.Match.Listener) != nil {
				return nil, ErrNetworkPolicyConsumers
			}
			o.joined = true
		default:
			o.process, err = r.child.observeListener(read, c.identity.provider, c.network, r.definition.Match.Listener)
			if err == nil && !r.birth.same(o.process.process) {
				err = ErrNetworkPolicyConsumers
			}
		}
		if err != nil || r.configCurrent(read) != nil || r.executable.current(read) != nil {
			return nil, errors.Join(ErrNetworkPolicyConsumers, err)
		}
	}
	borrow, present, err := observeBorrowedPolicyEffects(ctx, r.effects, r.rootPath)
	if err != nil {
		return nil, err
	}
	o.borrow, o.borrowed = borrow, present
	if present {
		o.absent = borrow.absent
		o.states, o.checksum, o.fileInfo = slices.Clone(borrow.states), borrow.checksum, borrow.fileInfo
	} else {
		r.commonMu.Lock()
		p := r.common
		if p != nil {
			err = p.current(ctx)
			o.states, o.checksum, o.fileInfo = slices.Clone(p.states), p.checksum, p.fileInfo
		} else {
			o.absent = true
			for _, name := range []string{policyAdditionFile, policyAdditionLock} {
				if _, fileErr := r.root.Stat(name); !errors.Is(fileErr, os.ErrNotExist) {
					err = ErrPolicyAdditionReceipt
				}
			}
		}
		r.commonMu.Unlock()
		if err != nil {
			return nil, err
		}
	}
	if o.beforeStart && !o.absent {
		return nil, ErrPolicyAdditionReceipt
	}
	if !o.absent {
		o.rows, o.required, err = xraySelectedTCPReceiptRows(r.effects, o.states, present)
		if err != nil {
			return nil, err
		}
	}
	if value := ctx.Value(xraySelectedTCPPreparedInventoryScopeKey{}); value != nil {
		read, ok := value.(*xraySelectedTCPPreparedInventoryScope)
		if !ok || read == nil || read.resource != r || read.observationHeld(ctx) != nil || !o.beforeStart || !o.absent || o.borrowed {
			return nil, ErrNetworkPolicyConsumers
		}
		// current's closing lifecycle comparison takes its own read lock. Do
		// not recursively acquire it while a native/Close writer is waiting.
		r.observationMu.RUnlock()
		locked = false
	}
	if err := o.current(ctx); err != nil {
		return nil, err
	}
	return []networkPolicyXraySelectedTCPObservation{o}, nil
}

func xraySelectedTCPReceiptRows(plan PolicyEffectPlan, states []string, borrowed bool) ([]BackendInventoryRow, []bool, error) {
	if len(states) != len(plan.Effects) {
		return nil, nil, ErrPolicyAdditionReceipt
	}
	var rows []BackendInventoryRow
	var required []bool
	for i, state := range states {
		switch state {
		case "planned", "removed":
			continue
		case "intent", "cleanup-intent":
			if !borrowed {
				return nil, nil, ErrPolicyAdditionReceipt
			}
		case "added":
		default:
			return nil, nil, ErrPolicyAdditionReceipt
		}
		add := plan.Effects[i].Add
		if plan.Effects[i].Tool != PolicyEffectIPTables || len(add) < 4 || add[0] != "-t" || add[1] != "nat" {
			return nil, nil, ErrPolicyAdditionReceipt
		}
		tokens := slices.Clone(add[2:])
		if tokens[0] == "-I" {
			if len(tokens) < 4 || tokens[1] != "PREROUTING" || tokens[2] != "1" {
				return nil, nil, ErrPolicyAdditionReceipt
			}
			tokens = append([]string{"-A", "PREROUTING"}, tokens[3:]...)
		} else if tokens[0] != "-N" && tokens[0] != "-A" {
			return nil, nil, ErrPolicyAdditionReceipt
		}
		row := BackendInventoryRow{Family: 4, Table: "nat", Tokens: tokens}
		if !networkPolicyXraySelectedTCPRow(row) {
			return nil, nil, ErrPolicyAdditionReceipt
		}
		rows = append(rows, row)
		required = append(required, state == "added")
	}
	return rows, required, nil
}

func networkPolicyXraySelectedTCPRow(row BackendInventoryRow) bool {
	return row.Family == 4 && row.Table == "nat" && len(row.Tokens) >= 2 &&
		(strings.HasPrefix(row.Tokens[1], "RZX_") || networkPolicyReferencesPrefix(row.Tokens, "RZX_"))
}
