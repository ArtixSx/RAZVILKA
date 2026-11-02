package dataplane

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ArtixSx/razvilka/internal/routeidentity"
)

// Immutable receipt/config inputs of the original cold operation. Policy's
// own receipt is advanced only by its retained writer and is not in this set.
type mihomoSameBootStatic struct {
	self     *mihomoSameBootStatic
	inputs   *mihomoSameBootInputs
	root     *os.Root
	info     os.FileInfo
	dirs     map[string]*os.Root
	infos    map[string]os.FileInfo
	members  map[string]map[string]bool // Exact original names and directory kinds, never cached observations.
	files    []*mihomoColdRecord
	absent   []string
	closed   bool
	closeErr error
}

func (c *mihomoSameBootStatic) sidecarRecord(name string) *mihomoColdRecord {
	if c == nil || c.self != c || c.closed || (name != "sidecar.pid" && name != "sidecar.pid"+routeidentity.ReceiptSuffix) {
		return nil
	}
	for _, r := range c.files {
		if r.name == filepath.Join("runtime", name) {
			return r
		}
	}
	return nil
}

// Only bounded held/named file metadata at the actual pidfd signal leaf.
// Full bytes, source, provider and private journals bracket the outer call;
// this method does not reenter them while the Control/Gate mutex is held.
func (c *mihomoSameBootStatic) signalRecordsCurrent() error {
	for _, name := range []string{"sidecar.pid", "sidecar.pid" + routeidentity.ReceiptSuffix} {
		r := c.sidecarRecord(name)
		if r == nil {
			return ErrMihomoLiveRetirement
		}
		if err := sameBootPolicyRecordIdentity(r); err != nil {
			return err
		}
	}
	return nil
}

func holdMihomoSameBootStatic(ctx context.Context, i *mihomoSameBootInputs, a *ProxyTunnelAdapter, before mihomoColdRuntimeArchive) (_ *mihomoSameBootStatic, resultErr error) {
	return holdMihomoSameBootTree(ctx, i, a, before, false)
}

func holdMihomoSameBootTree(ctx context.Context, i *mihomoSameBootInputs, a *ProxyTunnelAdapter, before mihomoColdRuntimeArchive, all bool) (_ *mihomoSameBootStatic, resultErr error) {
	if i == nil || a == nil || a.StateRoot != filepath.Join(i.statePath, "mihomo") || !before.Present || validateMihomoColdRuntime(a, i.definition, before) != nil {
		return nil, ErrMihomoLiveRetirement
	}
	if err := i.current(ctx); err != nil {
		return nil, err
	}
	if i.candidate {
		for name := range before.Directories {
			if strings.HasPrefix(filepath.ToSlash(name), "policy-generations/") {
				return nil, ErrPolicyAdditionUnknown
			}
		}
	}
	c := &mihomoSameBootStatic{inputs: i, dirs: map[string]*os.Root{}, infos: map[string]os.FileInfo{}, members: map[string]map[string]bool{".": {}}}
	for name := range before.Directories {
		c.members[name] = map[string]bool{}
	}
	for name := range before.Directories {
		parent := filepath.Dir(name)
		if c.members[parent] == nil {
			return nil, ErrMihomoLiveRetirement
		}
		c.members[parent][filepath.Base(name)] = true
	}
	for name := range before.Files {
		parent := filepath.Dir(name)
		if c.members[parent] == nil {
			return nil, ErrMihomoLiveRetirement
		}
		c.members[parent][filepath.Base(name)] = false
	}
	c.self = c
	keep := false
	defer func() {
		if !keep {
			resultErr = errors.Join(resultErr, c.close())
		}
	}()
	var err error
	c.root, err = openRetirementChild(i.roots[0], "mihomo")
	if err != nil {
		return nil, err
	}
	c.info, err = c.root.Stat(".")
	if err != nil {
		return nil, err
	}
	if executionHistoryIdentity(c.info) != before.Identity {
		return nil, ErrMihomoLiveRetirement
	}
	for name, identity := range before.Directories {
		dir, err := openRetirementChild(c.root, name)
		if err != nil {
			return nil, err
		}
		c.dirs[name] = dir
		info, err := dir.Stat(".")
		if err != nil {
			return nil, err
		}
		c.infos[name] = info
		if executionHistoryIdentity(info) != identity {
			return nil, ErrMihomoLiveRetirement
		}
	}
	names := []string{}
	if all {
		for name := range before.Files {
			names = append(names, name)
		}
	} else {
		for _, path := range []string{a.engineConfigPath(), a.sidecarConfigPath(), a.sidecarProcess().PIDPath, a.sidecarProcess().PIDPath + routeidentity.ReceiptSuffix, a.policyBindingPath(), a.policyPath(), a.forwardingPath()} {
			name, err := filepath.Rel(a.StateRoot, path)
			if err != nil || !filepath.IsLocal(name) {
				return nil, ErrMihomoLiveRetirement
			}
			names = append(names, name)
		}
	}
	for _, name := range names {
		if i.candidate && (name == filepath.Base(a.policyBindingPath()) || name == filepath.Base(a.policyPath())) {
			if _, err := c.root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
				return nil, errors.Join(ErrMihomoLiveRetirement, err)
			}
			c.absent = append(c.absent, name)
			continue
		}
		raw, exists := before.Files[name]
		if !exists {
			return nil, ErrMihomoLiveRetirement
		}
		r, err := openMihomoColdRecord(c.root, name, raw)
		if err != nil {
			return nil, err
		}
		c.files = append(c.files, r)
		if mihomoColdFileIdentity(r.info) != before.FileIdentities[name] {
			return nil, ErrMihomoLiveRetirement
		}
	}
	if err := c.current(); err != nil {
		return nil, err
	}
	keep = true
	return c, nil
}
func (c *mihomoSameBootStatic) current() error {
	if c == nil || c.inputs == nil {
		return ErrMihomoLiveRetirement
	}
	return c.currentAt(c.inputs.roots[0], "mihomo")
}
func (c *mihomoSameBootStatic) currentAt(parent *os.Root, name string) error {
	if c == nil || c.self != c || c.closed || c.root == nil || c.inputs == nil {
		return errors.Join(ErrMihomoLiveRetirement, sameBootStaticCloseError(c))
	}
	if err := c.inputs.current(c.inputs.ctx); err != nil {
		return err
	}
	if parent == nil {
		return ErrMihomoLiveRetirement
	}
	named, e1 := parent.Lstat(name)
	held, e2 := c.root.Stat(".")
	if e1 != nil || e2 != nil || !networkPolicyPrivateDirectory(named) || !networkPolicyPrivateDirectory(held) || !os.SameFile(c.info, named) || !os.SameFile(c.info, held) {
		return errors.Join(ErrMihomoLiveRetirement, e1, e2)
	}
	for name, dir := range c.dirs {
		named, e1 := c.root.Lstat(name)
		held, e2 := dir.Stat(".")
		if e1 != nil || e2 != nil || !networkPolicyPrivateDirectory(named) || !networkPolicyPrivateDirectory(held) || !os.SameFile(c.infos[name], named) || !os.SameFile(c.infos[name], held) {
			return errors.Join(ErrMihomoLiveRetirement, e1, e2)
		}
	}
	for _, r := range c.files {
		if err := errors.Join(mihomoSameBootStaticPath(r.root, r.name), r.current(), sameBootPolicyRecordIdentity(r)); err != nil {
			return err
		}
	}
	for _, name := range c.absent {
		if _, err := c.root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return errors.Join(ErrMihomoLiveRetirement, err)
		}
	}
	if err := c.membersCurrent(); err != nil {
		return err
	}
	closing, e1 := parent.Lstat(name)
	closingHeld, e2 := c.root.Stat(".")
	if e1 != nil || e2 != nil || !networkPolicyPrivateDirectory(closing) || !networkPolicyPrivateDirectory(closingHeld) || !os.SameFile(c.info, closing) || !os.SameFile(c.info, closingHeld) {
		return errors.Join(ErrMihomoLiveRetirement, e1, e2)
	}
	return c.closeErr
}

// Every effect bookend observes the entire original member set afresh. Log
// bodies may grow while a genuine child exits; no extra file, generation or
// replacement directory can be hidden by the immutable selected-file checks.
func (c *mihomoSameBootStatic) membersCurrent() error {
	if c == nil || c.self != c || c.closed || c.members == nil || len(c.members) != len(c.dirs)+1 {
		return ErrMihomoLiveRetirement
	}
	for name, expected := range c.members {
		dir := c.root
		if name != "." {
			dir = c.dirs[name]
		}
		if dir == nil || len(expected) > 512 {
			return ErrMihomoLiveRetirement
		}
		f, err := dir.Open(".")
		if err != nil {
			return err
		}
		entries, readErr := f.ReadDir(len(expected) + 1)
		closeErr := f.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(entries) != len(expected) {
			return errors.Join(ErrMihomoLiveRetirement, readErr, closeErr)
		}
		for _, entry := range entries {
			isDirectory, present := expected[entry.Name()]
			info, err := dir.Lstat(entry.Name())
			if !present || err != nil || isDirectory && (!networkPolicyPrivateDirectory(info) || !executionHistoryOwner(info, true)) || !isDirectory && (!validNetworkPolicyReceiptFile(info) || !executionHistoryOwner(info, false)) {
				return errors.Join(ErrMihomoLiveRetirement, err)
			}
		}
		if name != "." {
			named, e1 := c.root.Lstat(name)
			held, e2 := dir.Stat(".")
			if e1 != nil || e2 != nil || !networkPolicyPrivateDirectory(named) || !networkPolicyPrivateDirectory(held) || !os.SameFile(c.infos[name], named) || !os.SameFile(c.infos[name], held) {
				return errors.Join(ErrMihomoLiveRetirement, e1, e2)
			}
		}
	}
	return nil
}
func sameBootStaticCloseError(c *mihomoSameBootStatic) error {
	if c != nil {
		return c.closeErr
	}
	return nil
}
func (c *mihomoSameBootStatic) close() error {
	if c == nil || c.self != c {
		return ErrMihomoLiveRetirement
	}
	if !c.closed {
		c.closed = true
		for _, r := range c.files {
			c.closeErr = errors.Join(c.closeErr, r.file.Close())
			clear(r.data)
		}
		for _, d := range c.dirs {
			c.closeErr = errors.Join(c.closeErr, d.Close())
		}
		if c.root != nil {
			c.closeErr = errors.Join(c.closeErr, c.root.Close())
		}
	}
	return c.closeErr
}
