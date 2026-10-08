package dataplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

// Ephemeral observation of the actual registered private NFQ participant.
// There is no exported allowance constructor. The original process handles,
// COMMON writer/receipt, issuer and directory anchors are mandatory.
type networkPolicyNFQObservation struct {
	execution                     *nfqws2ActiveExecution
	resource                      *NFQWSExecutionResource
	process                       NFQWSScopedProcessProof
	receipt                       networkPolicyReceiptObservation
	borrow                        policyEffectBorrowObservation
	borrowed, absent, beforeStart bool
	rows                          []BackendInventoryRow
	required                      []bool
}

func (o networkPolicyNFQObservation) close() { o.receipt.close(); o.borrow.close() }

// Pure directory/file bookends only; never calls resource.Current, a forward
// source/guard, VerifyLAN or a process callback after the final inventory.
func (o networkPolicyNFQObservation) current(ctx context.Context) error {
	r := o.resource
	if r == nil || r.scope == nil || !r.scope.observationOpen.Load() || r.scope.owned == nil || ctx == nil || ctx.Err() != nil {
		return ErrNetworkPolicyConsumers
	}
	for _, anchored := range []struct {
		path string
		info os.FileInfo
	}{{r.scope.root, r.scope.anchor}, {r.root, r.anchor}} {
		info, err := os.Lstat(anchored.path)
		if err != nil || !networkPolicyPrivateDirectory(info) || !os.SameFile(anchored.info, info) {
			return ErrNetworkPolicyConsumers
		}
	}
	info, err := r.scope.owned.RootInfo()
	if err != nil || !os.SameFile(r.scope.anchor, info) {
		return ErrNetworkPolicyConsumers
	}
	if o.borrowed {
		return o.borrow.current(ctx)
	}
	if o.absent {
		for _, name := range []string{policyAdditionFile, policyAdditionLock} {
			_, err := os.Lstat(filepath.Join(r.root, name))
			if !errors.Is(err, os.ErrNotExist) {
				return ErrPolicyAdditionReceipt
			}
		}
		return nil
	}
	return o.receipt.current()
}

func equalNetworkPolicyNFQObservations(a, b []networkPolicyNFQObservation) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].execution != b[i].execution || a[i].resource != b[i].resource || a[i].process != b[i].process || a[i].absent != b[i].absent || a[i].beforeStart != b[i].beforeStart || a[i].borrowed != b[i].borrowed ||
			a[i].receipt.checksum != b[i].receipt.checksum || a[i].borrow.checksum != b[i].borrow.checksum || !reflect.DeepEqual(a[i].borrow.states, b[i].borrow.states) || !reflect.DeepEqual(a[i].rows, b[i].rows) || !reflect.DeepEqual(a[i].required, b[i].required) {
			return false
		}
		if !a[i].absent {
			left, right := a[i].receipt.fileInfo, b[i].receipt.fileInfo
			if a[i].borrowed {
				left, right = a[i].borrow.fileInfo, b[i].borrow.fileInfo
			}
			if left == nil || right == nil || !os.SameFile(left, right) {
				return false
			}
		}
	}
	return true
}

func (c *NetworkPolicyChecks) nfqConsumers(ctx context.Context, lan *LANPolicyRuntimePlan) (out []networkPolicyNFQObservation, result error) {
	defer func() {
		if result != nil {
			for _, o := range out {
				o.close()
			}
			out = nil
		}
	}()
	a, ok := c.adapters["nfqws2"].(*NFQWS2Adapter)
	if !ok || a == nil {
		return nil, nil
	}
	nfqws2ActiveAdapterMu.Lock()
	e, process := a.activeExecution, a.activeProcess
	nfqws2ActiveAdapterMu.Unlock()
	if e == nil {
		if process != nil {
			return nil, ErrNetworkPolicyConsumers
		}
		return nil, nil
	}
	if lan == nil || e.self != e || e.material == nil || e.material.self != e.material || e.material.adapter != a || e.material.manager != c.manager ||
		e.gate != c.gate || e.lan != c.binding || e.runtime != c.runtime || e.identity != c.identity || e.material.provider != c.identity.provider || !reflect.DeepEqual(e.plan.LAN, lan) {
		return nil, ErrNetworkPolicyConsumers
	}
	if err := e.owners(ctx); err != nil {
		return nil, err
	}
	p, err := c.consumerPlan(ctx, lan)
	if err != nil || !nfqws2ActiveSamePlan(e.plan, p) {
		return nil, errors.Join(ErrNetworkPolicyConsumers, err)
	}
	e.mu.Lock()
	r, b, retired := e.resource, e.binding, e.retired
	e.mu.Unlock()
	if retired || r == nil || b == nil || r.scope == nil || r.scope.manager != c.manager || r.scope.adapterOwner != a || r.scope.networkIdentity != c.identity ||
		!r.scope.observationOpen.Load() || r.plan == nil || !reflect.DeepEqual(r.plan.spec, e.spec) || !reflect.DeepEqual(r.plan.lan, lan) || nfqws2ActiveCommandMatchesSpec(e.material.command, e.spec) != nil {
		return nil, ErrNetworkPolicyConsumers
	}
	o := networkPolicyNFQObservation{execution: e, resource: r}
	defer func() {
		if result != nil {
			o.close()
		}
	}()
	if process == nil {
		// Actual pre-Start: this exact assembly is already attached and its
		// real issuer/root exist, while native ownership/capture remain absent.
		if _, err := os.Lstat(filepath.Join(a.StateRoot, nfqws2LeaseFile)); !errors.Is(err, os.ErrNotExist) {
			return nil, ErrNetworkPolicyConsumers
		}
		if err := b.checkQueue(ctx, r.plan, nil); err != nil {
			return nil, err
		}
		o.beforeStart = true
	} else {
		o.process, err = e.process(ctx, r.plan, false)
		if err != nil {
			return nil, err
		}
		if err := b.checkQueue(ctx, r.plan, &o.process.Child); err != nil {
			return nil, err
		}
		closing, err := e.process(ctx, r.plan, false)
		if err != nil || closing != o.process {
			return nil, errors.Join(ErrNetworkPolicyConsumers, err)
		}
	}
	borrow, present, err := observeBorrowedPolicyEffects(ctx, r.plan.mixed, r.root)
	if err != nil {
		return nil, err
	}
	o.borrow, o.borrowed = borrow, present
	states := make([]string, len(r.plan.mixed.Effects))
	if present {
		o.absent = borrow.absent
		if !borrow.absent {
			states = borrow.states
		}
	} else {
		_, docErr := os.Lstat(filepath.Join(r.root, policyAdditionFile))
		_, lockErr := os.Lstat(filepath.Join(r.root, policyAdditionLock))
		if errors.Is(docErr, os.ErrNotExist) && errors.Is(lockErr, os.ErrNotExist) {
			o.absent = true
		} else {
			o.receipt, err = observeNetworkPolicyEffects(ctx, r.plan.mixed, r.root, b.options)
			if err != nil || !o.receipt.status.Complete || o.receipt.status.Unknown || o.receipt.status.Removed || o.receipt.status.Promoted {
				return nil, errors.Join(ErrNetworkPolicyConsumers, err)
			}
			for i := range states {
				states[i] = "added"
			}
		}
	}
	if o.beforeStart && !o.absent {
		return nil, ErrNetworkPolicyConsumers
	}
	if !o.absent {
		o.rows, o.required, err = networkPolicyNFQReceiptRows(r.plan, states, present)
		if err != nil {
			return nil, err
		}
	}
	if err := e.owners(ctx); err != nil {
		return nil, err
	}
	if err := o.current(ctx); err != nil {
		return nil, err
	}
	return append(out, o), nil
}

// Pure conversion after original-owner and actual receipt authentication.
// Its result alone is never an allowance constructor or an effect grant.
func networkPolicyNFQReceiptRows(p *NFQWSScopedPlan, states []string, borrowed bool) (rows []BackendInventoryRow, required []bool, err error) {
	if p == nil || len(states) != len(p.mixed.Effects) {
		return nil, nil, ErrPolicyAdditionReceipt
	}
	pending, planned := false, false
	for i, state := range states {
		switch state {
		case "added":
			if pending || planned {
				return nil, nil, ErrPolicyAdditionReceipt
			}
		case "intent":
			if pending || planned || !borrowed {
				return nil, nil, ErrPolicyAdditionReceipt
			}
			pending = true
		case "planned":
			if !borrowed {
				return nil, nil, ErrPolicyAdditionReceipt
			}
			planned = true
			continue
		default:
			return nil, nil, ErrPolicyAdditionReceipt
		}
		effect := p.mixed.Effects[i]
		if len(effect.Add) < 4 || effect.Add[0] != "-t" || effect.Add[1] != "mangle" || effect.Tool != PolicyEffectIPTables && effect.Tool != PolicyEffectIP6Tables {
			return nil, nil, ErrPolicyAdditionReceipt
		}
		family := 4
		if effect.Tool == PolicyEffectIP6Tables {
			family = 6
		}
		rows = append(rows, BackendInventoryRow{Family: family, Table: "mangle", Tokens: append([]string(nil), effect.Add[2:]...)})
		required = append(required, state == "added")
	}
	return rows, required, nil
}

func networkPolicyNFQRow(row BackendInventoryRow) bool {
	return len(row.Tokens) >= 2 && (strings.HasPrefix(row.Tokens[1], "RZQ_") || networkPolicyReferencesPrefix(row.Tokens, "RZQ_"))
}
