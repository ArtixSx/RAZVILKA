package dataplane

import (
	"context"
	"errors"
	"os"
	"reflect"
)

type nfqPreLedgerPhase uint8

const (
	nfqPreLedgerArmed nfqPreLedgerPhase = iota + 1
	nfqPreLedgerDisarmed
	nfqPreLedgerPublishing
	nfqPreLedgerSettled
)

// Issued by the original COMMON control flow only while its proven absent
// writer is still held, before any document construction/publication or Run.
// The phase never returns to armed, including after a failed recovery write.
type nfqwsPreLedgerWitness struct {
	self             *nfqwsPreLedgerWitness
	owner            *nfqwsPolicyRecovery
	session          *policyEffectSession
	borrow           *policyEffectReceiptBorrow
	reader           *nfqws2ActivePreAddRead
	path, hash       string
	documentChecksum string
	phase            nfqPreLedgerPhase
}

func (c *nfqwsPolicyRecovery) armPreLedger(s *policyEffectSession, runtime PolicyEffectRuntime) {
	if c == nil || c.self != c || c.preLedger != nil || c.index != -1 || c.entered || c.closed || c.fenced || c.session != s || s == nil || !reflect.DeepEqual(s.doc, policyAdditionDocument{}) || s.borrow == nil || s.nfqRecovery != c || c.preAdd == nil || c.preAdd.material == nil || c.preAdd.material.self != c.preAdd.material || runtime.Runner != c.preAdd || !c.preAdd.originalCommandCustody(s, -1) || c.preAdd.material != c.execution.material {
		return
	}
	// The original caller has just established s.load==ENOENT and installed
	// this exact original borrow; generic/custom runners cannot arm a witness.
	b := s.borrow
	b.mu.Lock()
	valid := b.self == b && b.session == s && b.open && b.absent && b.published == nil
	b.mu.Unlock()
	if !valid {
		return
	}
	w := &nfqwsPreLedgerWitness{owner: c, session: s, borrow: b, reader: c.preAdd, path: s.path, hash: s.hash, phase: nfqPreLedgerArmed}
	w.self = w
	c.preLedger = w
}
func (c *nfqwsPolicyRecovery) disarmPreLedger() {
	if c != nil && c.preLedger != nil && c.preLedger.phase == nfqPreLedgerArmed {
		c.preLedger.phase = nfqPreLedgerDisarmed
	}
}
func (c *nfqwsPolicyRecovery) preLedgerOriginal() bool {
	if c == nil || c.self != c || c.preLedger == nil || c.closed || c.fenced || c.entered || c.index != -1 || c.session == nil || c.preAdd == nil || c.preAdd.material == nil || c.preAdd.material.self != c.preAdd.material {
		return false
	}
	w := c.preLedger
	if !(w.self == w && w.owner == c && w.session == c.session && w.borrow == c.session.borrow && w.reader == c.preAdd && c.session.nfqRecovery == c && w.path == c.session.path && w.hash == c.session.hash && c.preAdd.originalCommandCustody(c.session, -1) && c.preAdd.material == c.execution.material) {
		return false
	}
	digest, err := PolicyEffectPlanDigest(c.session.plan)
	return err == nil && digest == w.hash
}
func (c *nfqwsPolicyRecovery) preLedgerArmed() bool {
	return c.preLedgerOriginal() && c.preLedger.phase == nfqPreLedgerArmed && reflect.DeepEqual(c.session.doc, policyAdditionDocument{}) && c.publication == 0 && !c.renameAttempted && c.pending == nil && !c.needsSync
}

// A known zero-attempt retry is a separate publishing state, never a return
// to generic absent borrowing. The original nonce/document stays immutable.
func (c *nfqwsPolicyRecovery) preLedgerUnpublished() bool {
	if !c.preLedgerOriginal() || c.publication != 0 || c.renameAttempted || c.pending != nil || c.needsSync {
		return false
	}
	w := c.preLedger
	return (w.phase == nfqPreLedgerArmed && reflect.DeepEqual(c.session.doc, policyAdditionDocument{})) || (w.phase == nfqPreLedgerPublishing && w.documentChecksum != "" && c.session.doc.Checksum == w.documentChecksum && policyAdditionChecksum(c.session.doc) == w.documentChecksum)
}

// No-follow named absence and the same held directory/lock bookends. This
// never adopts a missing receipt as provenance: the private armed witness is
// mandatory, and unknown/copy/closed/publication paths cannot enter here.
func (c *nfqwsPolicyRecovery) preLedgerAbsent(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || !c.retained || !c.preLedgerUnpublished() {
		return errors.Join(ErrPolicyAdditionUnknown, networkPolicyChecksContextError(ctx))
	}
	b := c.preLedger.borrow
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.absent != (c.preLedger.phase == nfqPreLedgerArmed) || b.published != nil || b.currentOwner() != nil {
		return ErrPolicyAdditionUnknown
	}
	if _, err := c.session.root.LstatChild(policyAdditionFile); !errors.Is(err, os.ErrNotExist) {
		return errors.Join(ErrPolicyAdditionUnknown, err)
	}
	return errors.Join(b.currentOwner(), ctx.Err())
}

// Only settleNeverIssuedPolicy calls this in production, after original
// Stop/sole Wait, with its complete two-pass process/queue/both-family proof.
func (c *nfqwsPolicyRecovery) settlePreLedger(ctx context.Context, verify func() error) error {
	if ctx == nil || ctx.Err() != nil || !c.preLedgerOriginal() || !c.retained || verify == nil {
		return errors.Join(ErrPolicyAdditionUnknown, networkPolicyChecksContextError(ctx))
	}
	w := c.preLedger
	if w.phase == nfqPreLedgerPublishing {
		if c.preLedgerUnpublished() {
			// Keep the same private document and nonce. Even a known pre-write
			// failure repeats complete fresh proof and never restores borrow.absent.
			if err := c.preLedgerAbsent(ctx); err != nil {
				return err
			}
			if err := verify(); err != nil {
				return err
			}
			if err := c.preLedgerAbsent(ctx); err != nil {
				return err
			}
			if err := c.session.save(ctx); err != nil {
				return err
			}
		} else {
			if c.publication != 1 || (c.pending == nil && c.session.borrow.published == nil) {
				return ErrPolicyAdditionUnknown
			}
			if err := c.finishPublication(ctx); err != nil {
				return err
			}
		}
		if err := c.documentCurrent(ctx); err != nil {
			return err
		}
		c.settled = true
		w.phase = nfqPreLedgerSettled
	}
	if w.phase == nfqPreLedgerSettled {
		if !c.settled || c.session.doc.Phase != "active" || c.session.status().Unknown || !c.session.status().Removed {
			return ErrPolicyAdditionUnknown
		}
		if err := verify(); err != nil {
			return err
		}
		return c.documentCurrent(ctx)
	}
	if w.phase != nfqPreLedgerArmed {
		return ErrPolicyAdditionUnknown
	}
	if err := c.preLedgerAbsent(ctx); err != nil {
		return err
	}
	if err := verify(); err != nil {
		return err
	}
	if err := c.preLedgerAbsent(ctx); err != nil {
		return err
	}
	// Construction is private memory only. All steps remain planned; this
	// records zero issued effects and grants no Add or Delete capability.
	document, err := c.session.newDocument(w.path)
	if err != nil {
		return err
	}
	if err := c.preLedgerAbsent(ctx); err != nil {
		return err
	}
	c.session.doc = document
	c.session.doc.Checksum = policyAdditionChecksum(c.session.doc)
	w.documentChecksum = c.session.doc.Checksum
	w.phase = nfqPreLedgerPublishing
	c.session.borrow.requireDocument()
	err = c.session.save(ctx)
	if err != nil {
		return err
	}
	if c.publication != 1 || c.needsSync || c.pending != nil {
		return ErrPolicyAdditionUnknown
	}
	if err := c.documentCurrent(ctx); err != nil {
		return err
	}
	c.settled = true
	w.phase = nfqPreLedgerSettled
	if err := verify(); err != nil {
		return err
	}
	return c.documentCurrent(ctx)
}
