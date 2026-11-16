package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"

	"github.com/ArtixSx/razvilka/internal/updatecheck"
)

// A synchronous continuation of an already classified publisher ACK. It owns
// no new resource and contains no reusable absence evidence. Only Retry can
// construct it, before consuming the original cursor's retry fields.
type mihomoSameBootACKResume struct {
	self                           *mihomoSameBootACKResume
	handle                         *MihomoSameBootRetirement
	cursor                         *mihomoSameBootRetirementCursor
	owner                          *mihomoSameBootCleanup
	inputs                         *mihomoSameBootInputs
	archive                        *mihomoSameBootArchive
	history                        *updatecheck.ExecutionHistoryAdmission
	proxy                          *ProxyTunnelAdapter
	home                           *mihomoColdHomeArchive
	runtime                        *mihomoColdRuntimeArchive
	tree                           *mihomoSameBootStatic
	ctx                            context.Context
	archiveName                    string
	terminalSlot                   int // Original slot+1, zero only for completed.json.
	used                           bool
	changingSlot                   int // Only while the SAME terminal publisher is on stack.
	slots                          [2]mihomoSameBootACKRecord
	pending                        [2]bool
	intent, runtimeHistory, done   mihomoSameBootACKRecord
	intentHash, runtimeHistoryHash string
}

type mihomoSameBootACKRecord struct {
	record *mihomoColdRecord
	root   *os.Root
	file   *os.File
	info   os.FileInfo
	name   string
	hash   string
}

func captureMihomoSameBootACKRecord(r *mihomoColdRecord) (mihomoSameBootACKRecord, error) {
	if r == nil || r.root == nil || r.file == nil || r.info == nil || len(r.data) == 0 {
		return mihomoSameBootACKRecord{}, ErrMihomoLiveRetirement
	}
	return mihomoSameBootACKRecord{r, r.root, r.file, r.info, r.name, nodeDefaultSourceMaterialHash(r.data)}, nil
}

func (r mihomoSameBootACKRecord) matches(actual *mihomoColdRecord) bool {
	return actual != nil && r.record == actual && r.root == actual.root && r.file == actual.file && r.name == actual.name && reflect.DeepEqual(r.info, actual.info) && r.hash == nodeDefaultSourceMaterialHash(actual.data)
}

func (h *MihomoSameBootRetirement) retainedACKResume() (*mihomoSameBootACKResume, error) {
	if h == nil || h.self != h || !h.open || !h.attempted || h.retrySidecar || !errors.Is(h.lastErr, ErrMihomoSameBootRetainedRetry) {
		return nil, ErrMihomoLiveRetirement
	}
	if err := xraySelectedTCPFinite(h.ctx); err != nil {
		return nil, errors.Join(ErrMihomoLiveRetirement, err)
	}
	c := h.cursor
	if c == nil || c.self != c || c.ctx != h.ctx || c.retryArchive != h.retryArchive || c.retryTerminal != h.retryTerminal || c.owner == nil || c.owner.inputs == nil || len(c.owner.inputs.records) < 2 || c.archive == nil {
		return nil, ErrMihomoLiveRetirement
	}
	if h.retryTerminal == 0 && h.retryArchive != "completed.json" || h.retryTerminal != 0 && (h.retryTerminal < 1 || h.retryTerminal > 2 || h.retryArchive != "") {
		return nil, ErrMihomoLiveRetirement
	}
	r := &mihomoSameBootACKResume{handle: h, cursor: c, owner: c.owner, inputs: c.owner.inputs, archive: c.archive, history: c.history, proxy: c.effectProxy, home: c.home, runtime: c.runtimeAfter, tree: c.finalTree, ctx: c.ctx, archiveName: h.retryArchive, terminalSlot: h.retryTerminal, changingSlot: -1, pending: c.terminalPending}
	r.self = r
	var err error
	for n := range 2 {
		r.slots[n], err = captureMihomoSameBootACKRecord(c.owner.inputs.records[n])
		if err != nil {
			return nil, err
		}
	}
	r.intent, err = captureMihomoSameBootACKRecord(c.archive.records["retirement.json"])
	if err != nil {
		return nil, err
	}
	r.runtimeHistory, err = captureMihomoSameBootACKRecord(c.archive.records["runtime-history"])
	if err != nil {
		return nil, err
	}
	r.intentHash, r.runtimeHistoryHash = r.intent.hash, r.runtimeHistory.hash
	if r.archiveName == "completed.json" {
		r.done, err = captureMihomoSameBootACKRecord(c.archive.records["completed.json"])
		if err != nil {
			return nil, err
		}
	}
	if err := errors.Join(r.bound(), r.admissionVector()); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *mihomoSameBootACKResume) associations() error {
	if r == nil || r.self != r || r.handle == nil || r.cursor == nil || r.owner == nil || r.inputs == nil || r.archive == nil || r.history == nil || r.proxy == nil || r.home == nil || r.runtime == nil || r.tree == nil {
		return ErrMihomoLiveRetirement
	}
	if err := xraySelectedTCPFinite(r.ctx); err != nil {
		return errors.Join(ErrMihomoLiveRetirement, err)
	}
	h, c, o := r.handle, r.cursor, r.owner
	if h.self != h || !h.open || !h.attempted || h.cursor != c || h.ctx != r.ctx || h.retrySidecar || h.retryArchive != r.archiveName || h.retryTerminal != r.terminalSlot || !errors.Is(h.lastErr, ErrMihomoSameBootRetainedRetry) || c.self != c || c.closed || c.closeErr != nil || c.unknown != nil || c.terminalCloseErr != nil || c.ctx != r.ctx || c.owner != o || o.self != o || !o.effectsClosed || o.effectUnknown || !c.sidecarDone || !c.policyDone || !c.forwardingDone || o.inputs != r.inputs || o.read == nil || o.read.proxy == nil || c.archive != r.archive || c.history != r.history || c.effectProxy != r.proxy || c.home != r.home || c.runtimeAfter != r.runtime || c.finalTree != r.tree || r.archive.inputs != r.inputs || r.archive.self != r.archive || r.archive.root == nil || r.archive.closed || r.archive.closeErr != nil || len(r.inputs.records) < 2 || len(r.inputs.roots) < 1 || r.inputs.roots[0] == nil {
		return ErrMihomoLiveRetirement
	}
	return nil
}

func (r *mihomoSameBootACKResume) bound() error {
	if err := r.associations(); err != nil {
		return err
	}
	if !r.intent.matches(r.archive.records["retirement.json"]) || !r.runtimeHistory.matches(r.archive.records["runtime-history"]) || r.archiveName == "completed.json" && !r.done.matches(r.archive.records["completed.json"]) {
		return ErrMihomoLiveRetirement
	}
	for n := range 2 {
		actual := r.inputs.records[n]
		if r.changingSlot == n && !r.pending[n] {
			// A later Before→After transition is recognized only while the
			// existing CAS publisher is on stack, never during other callbacks.
			if actual == r.slots[n].record && actual.root == r.slots[n].root && actual.name == r.slots[n].name && bytes.Equal(actual.data, r.cursor.intent.After) && r.cursor.terminalPending[n] {
				if err := actual.current(); err != nil {
					return err
				}
				continue
			}
		}
		if !r.slots[n].matches(actual) || r.pending[n] != r.cursor.terminalPending[n] {
			return ErrMihomoLiveRetirement
		}
	}
	return nil
}

func (r *mihomoSameBootACKResume) admissionVector() error {
	if r == nil || r.cursor == nil || r.inputs == nil || len(r.inputs.records) < 2 {
		return ErrMihomoLiveRetirement
	}
	c := r.cursor
	for n := range 2 {
		if r.inputs.records[n] == nil {
			return ErrMihomoLiveRetirement
		}
		want, pending := c.intent.After, false
		if r.terminalSlot != 0 {
			if n == r.terminalSlot-1 {
				pending = true
			} else if n > r.terminalSlot-1 {
				want = c.intent.Before
			}
		}
		if len(want) == 0 || !bytes.Equal(r.inputs.records[n].data, want) || c.terminalPending[n] != pending {
			return ErrMihomoLiveRetirement
		}
	}
	return nil
}

func (r *mihomoSameBootACKResume) documentsCurrent() error {
	if err := r.archive.current(); err != nil {
		return err
	}
	c := r.cursor
	intent, e1 := json.Marshal(c.intent)
	history, e2 := json.Marshal(struct {
		Schema  int
		Runtime mihomoColdRuntimeArchive
		Home    *mihomoColdHomeArchive
	}{1, *c.runtimeAfter, c.home})
	terminal, e3 := json.Marshal(c.terminal)
	if e1 != nil || e2 != nil || e3 != nil || nodeDefaultSourceMaterialHash(intent) != r.intentHash || nodeDefaultSourceMaterialHash(history) != r.runtimeHistoryHash || !bytes.Equal(terminal, c.intent.After) {
		return errors.Join(ErrMihomoLiveRetirement, e1, e2, e3)
	}
	if r.archiveName == "completed.json" {
		done, err := json.Marshal(struct {
			Schema                    int
			BeforeSHA256, AfterSHA256 string
		}{1, nodeDefaultSourceMaterialHash(c.intent.Before), nodeDefaultSourceMaterialHash(c.intent.After)})
		if err != nil || nodeDefaultSourceMaterialHash(done) != r.done.hash {
			return errors.Join(ErrMihomoLiveRetirement, err)
		}
	}
	return r.ctx.Err()
}

func (r *mihomoSameBootACKResume) current() error {
	if err := r.bound(); err != nil {
		return err
	}
	if err := r.documentsCurrent(); err != nil {
		return err
	}
	err := r.cursor.terminalCurrent()
	return errors.Join(err, r.documentsCurrent(), r.bound())
}

func (r *mihomoSameBootACKResume) beforeTerminal(n int) error {
	if err := r.bound(); err != nil {
		return err
	}
	if r.archiveName != "" || n < r.terminalSlot-1 || n > 1 || r.changingSlot != -1 {
		return ErrMihomoLiveRetirement
	}
	for prior := 0; prior < n; prior++ {
		if r.cursor.terminalPending[prior] || !bytes.Equal(r.inputs.records[prior].data, r.cursor.intent.After) {
			return ErrMihomoLiveRetirement
		}
	}
	r.changingSlot = n
	return nil
}

func (r *mihomoSameBootACKResume) afterTerminal(n int) error {
	if err := r.associations(); err != nil {
		return err
	}
	if n < 0 || n > 1 || r.changingSlot != n || r.cursor.terminalPending[n] || r.inputs.records[n] != r.slots[n].record || !bytes.Equal(r.inputs.records[n].data, r.cursor.intent.After) {
		return ErrMihomoLiveRetirement
	}
	actual := r.inputs.records[n]
	if actual.info == nil || actual.file == nil || actual.root != r.slots[n].root || actual.name != r.slots[n].name {
		return ErrMihomoLiveRetirement
	}
	if r.pending[n] {
		if !r.slots[n].matches(actual) {
			return ErrMihomoLiveRetirement
		}
	} else if actual.file == r.slots[n].file || os.SameFile(actual.info, r.slots[n].info) {
		return ErrMihomoLiveRetirement
	}
	if err := actual.current(); err != nil {
		return err
	}
	captured, err := captureMihomoSameBootACKRecord(actual)
	if err != nil {
		return err
	}
	r.slots[n], r.pending[n], r.changingSlot = captured, false, -1
	return r.bound()
}

func (r *mihomoSameBootACKResume) run(h *MihomoSameBootRetirement) (Execution, error) {
	if r == nil || r.self != r || r.handle != h || r.used {
		return Execution{}, ErrMihomoLiveRetirement
	}
	r.used = true
	defer mihomoSameBootNativeTiming(r.cursor, "run")()
	if err := errors.Join(r.bound(), r.admissionVector()); err != nil {
		return Execution{}, err
	}
	if err := r.cursor.checkHistory(); err != nil {
		return Execution{}, err
	}
	if err := r.current(); err != nil {
		return Execution{}, err
	}
	return r.cursor.runTerminalSuffix(r)
}
