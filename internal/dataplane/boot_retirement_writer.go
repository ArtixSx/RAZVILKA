package dataplane

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// This original writer exists only inside the offline operation. Persisted
// documents cannot mint it or choose its roots. Normal retry/close publication
// remains unchanged; post-reboot retirement keeps all writes on held roots.
type bootRetirementWriter struct {
	manager                                 *Manager
	state, transactions, transaction, proxy *os.Root
	transactionPath                         string
	provenance                              func() error
	archive                                 string
	manifest                                bootRetirementManifest
	pending                                 *bootRetirementPublication
	fault                                   func(string) error
	observe                                 func() error
}

func newBootRetirementWriter(m *Manager, state *os.Root, id string) (*bootRetirementWriter, error) {
	w := &bootRetirementWriter{manager: m, state: state, transactionPath: filepath.Join(m.StateRoot, "transactions", id)}
	var err error
	w.transactions, err = openRetirementChild(state, "transactions")
	if err != nil {
		return nil, err
	}
	w.transaction, err = openRetirementChild(w.transactions, id)
	if err != nil {
		w.close()
		return nil, err
	}
	w.proxy, err = openRetirementChild(state, "sing-box")
	if err != nil {
		w.close()
		return nil, err
	}
	if err := w.current(); err != nil {
		w.close()
		return nil, err
	}
	return w, nil
}

func (w *bootRetirementWriter) close() {
	for _, root := range []*os.Root{w.proxy, w.transaction, w.transactions} {
		if root != nil {
			root.Close()
		}
	}
}

func (w *bootRetirementWriter) current() error {
	path, err := os.Lstat(w.manager.StateRoot)
	if err != nil {
		return ErrBootRetirement
	}
	held, err := w.state.Stat(".")
	if err != nil || !path.IsDir() || path.Mode()&os.ModeSymlink != 0 || !os.SameFile(path, held) {
		return ErrBootRetirement
	}
	if err := errors.Join(checkRetirementChild(w.state, "transactions", w.transactions), checkRetirementChild(w.transactions, filepath.Base(w.transactionPath), w.transaction), checkRetirementChild(w.state, "sing-box", w.proxy)); err != nil {
		return ErrBootRetirement
	}
	if w.provenance != nil {
		return w.provenance()
	}
	return nil
}

func (w *bootRetirementWriter) writeExecution(path string, execution Execution) error {
	if path != w.transactionPath || execution.PlanID != filepath.Base(path) || w.current() != nil {
		return ErrBootRetirement
	}
	if err := validateExecutionResources(execution, true); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(execution, "", "  ")
	if err != nil {
		return err
	}
	return w.publish(map[string][]byte{filepath.Join("transactions", execution.PlanID, "execution.json"): raw, "latest-execution.json": raw})
}

func (w *bootRetirementWriter) recordPlan(plan Plan) error {
	if plan.PlanID != filepath.Base(w.transactionPath) || plan.State == "committed" || w.current() != nil {
		return ErrBootRetirement
	}
	w.manager.journalMu.Lock()
	defer w.manager.journalMu.Unlock()
	raw, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	return w.publish(map[string][]byte{"latest-plan.json": raw})
}

func writeBootRetirementAtomic(root *os.Root, name string, data []byte) error {
	if !filepath.IsLocal(name) || filepath.Clean(name) == "." {
		return ErrBootRetirement
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	temporary := filepath.Join(filepath.Dir(name), ".boot-retirement-"+hex.EncodeToString(nonce[:]))
	file, err := root.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() { file.Close(); root.Remove(temporary) }()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := root.Rename(temporary, name); err != nil {
		return err
	}
	return syncBootRetirementDirectory(root, filepath.Dir(name))
}

// Pin immutable provenance bytes and its original file identity. Replacement,
// deletion or in-place alteration must never be hidden by successful moves.
func pinBootRetirementFile(root *os.Root, name string, expected []byte) (func() error, func(), error) {
	file, err := root.Open(name)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(file, bootRetirementLimit+1))
	if err != nil || !bytes.Equal(raw, expected) {
		file.Close()
		return nil, nil, ErrBootRetirement
	}
	check := func() error {
		current, err := root.Lstat(name)
		if err != nil || !os.SameFile(info, current) {
			return ErrBootRetirement
		}
		raw, err := bootRetirementRead(root, name)
		if err != nil || !bytes.Equal(raw, expected) {
			return ErrBootRetirement
		}
		return nil
	}
	if err := check(); err != nil {
		file.Close()
		return nil, nil, err
	}
	return check, func() { file.Close() }, nil
}

func publishBootRetirementWitness(root *os.Root, archive string, manifest bootRetirementManifest, boot string) (func() error, func(), error) {
	// A later physical reboot needs its own fresh negative observation. The
	// original manifest and all old receipts retain their original boot bytes.
	witness := struct {
		Schema                                            int
		ManifestSHA256, SettingsSHA256, Boot, Observation string
	}{1, bootRetirementChecksum(manifest), manifest.SettingsSHA256, boot, "bracketed-proc-interface-kernel-absence-v1"}
	raw, _ := json.Marshal(witness)
	name := filepath.Join(archive, "observations", boot+".json")
	current, err := bootRetirementRead(root, name)
	if errors.Is(err, os.ErrNotExist) {
		if err := mkdirBootRetirement(root, filepath.Dir(name)); err != nil {
			return nil, nil, err
		}
		if err := writeBootRetirementAtomic(root, name, raw); err != nil {
			return nil, nil, err
		}
		if err := syncBootRetirementDirectory(root, archive); err != nil {
			return nil, nil, err
		}
	} else if err != nil || !bytes.Equal(current, raw) {
		return nil, nil, ErrBootRetirement
	}
	return pinBootRetirementFile(root, name, raw)
}
