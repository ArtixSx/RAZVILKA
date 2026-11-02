package dataplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// New documentary namespace, never interpreted as the after-reboot protocol.
// Immutable documents are authored by this cursor before their acknowledgments
// can be used. Existing files must match the original retained inode as well
// as the expected bytes; an EEXIST result is never an ownership grant.
type mihomoSameBootArchive struct {
	self             *mihomoSameBootArchive
	inputs           *mihomoSameBootInputs
	parent, root     *os.Root
	parentInfo, info os.FileInfo
	relative         string
	records          map[string]*mihomoColdRecord
	closed           bool
	closeErr         error
	fault            func(string) error // Private refusal-only cut AFTER real publication; never an issuer.
}

func newMihomoSameBootArchive(i *mihomoSameBootInputs) (out *mihomoSameBootArchive, resultErr error) {
	if i == nil || i.self != i {
		return nil, ErrMihomoLiveRetirement
	}
	if err := i.current(i.ctx); err != nil {
		return nil, err
	}
	c := &mihomoSameBootArchive{inputs: i, relative: filepath.Join("mihomo-live-same-boot-retirements", i.before.PlanID), records: map[string]*mihomoColdRecord{}}
	c.self = c
	keep := false
	defer func() {
		if !keep {
			resultErr = errors.Join(resultErr, c.close())
		}
	}()
	state := i.roots[0]
	if err := mkdirBootRetirement(state, "mihomo-live-same-boot-retirements"); err != nil {
		return nil, err
	}
	var err error
	c.parent, err = openRetirementChild(state, "mihomo-live-same-boot-retirements")
	if err != nil {
		return nil, err
	}
	c.parentInfo, err = c.parent.Stat(".")
	if err != nil {
		return nil, err
	}
	if err := mkdirBootRetirement(c.parent, i.before.PlanID); err != nil {
		return nil, err
	}
	c.root, err = openRetirementChild(c.parent, i.before.PlanID)
	if err != nil {
		return nil, err
	}
	c.info, err = c.root.Stat(".")
	if err != nil {
		return nil, err
	}
	// A foreign/preexisting directory can be observed only as an empty inert
	// container. No document in it is adopted by a fresh original cursor.
	f, err := c.root.Open(".")
	if err != nil {
		return nil, err
	}
	entries, readErr := f.ReadDir(1)
	closeErr := f.Close()
	if len(entries) != 0 || readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil {
		return nil, errors.Join(ErrMihomoLiveRetirement, readErr, closeErr)
	}
	if err := errors.Join(syncBootRetirementDirectory(state, "."), syncBootRetirementDirectory(c.parent, "."), c.current()); err != nil {
		return nil, err
	}
	keep = true
	return c, nil
}

func (c *mihomoSameBootArchive) current() error {
	if c == nil || c.self != c || c.closed || c.inputs == nil || c.root == nil || c.parent == nil {
		return errors.Join(ErrMihomoLiveRetirement, cCloseErr(c))
	}
	if err := c.inputs.current(c.inputs.ctx); err != nil {
		return err
	}
	for _, item := range []struct {
		parent *os.Root
		name   string
		root   *os.Root
		info   os.FileInfo
	}{{c.inputs.roots[0], "mihomo-live-same-boot-retirements", c.parent, c.parentInfo}, {c.parent, c.inputs.before.PlanID, c.root, c.info}} {
		held, e1 := item.root.Stat(".")
		named, e2 := item.parent.Lstat(item.name)
		if e1 != nil || e2 != nil || !networkPolicyPrivateDirectory(held) || !networkPolicyPrivateDirectory(named) || !os.SameFile(item.info, held) || !os.SameFile(item.info, named) {
			return errors.Join(ErrMihomoLiveRetirement, e1, e2)
		}
	}
	for _, r := range c.records {
		if err := r.current(); err != nil {
			return err
		}
	}
	return nil
}
func cCloseErr(c *mihomoSameBootArchive) error {
	if c != nil {
		return c.closeErr
	}
	return nil
}

// Invoked synchronously under the original Manager operation. A returned
// authored FD is installed in the cursor even when publication/fsync reports
// an error; retry then repeats the real durability ACK on that SAME inode.
func (c *mihomoSameBootArchive) publish(name string, value any, current func() error) error {
	if c == nil || c.self != c || name != "retirement.json" && name != "completed.json" || current == nil {
		return ErrMihomoLiveRetirement
	}
	data, err := json.Marshal(value)
	if err != nil || len(data) == 0 || len(data) > bootRetirementLimit {
		return errors.Join(ErrMihomoLiveRetirement, err)
	}
	if err := errors.Join(c.current(), current()); err != nil {
		return err
	}
	if prior := c.records[name]; prior != nil {
		if !bytes.Equal(prior.data, data) {
			return ErrMihomoLiveRetirement
		}
		return errors.Join(prior.current(), prior.file.Sync(), syncBootRetirementDirectory(c.root, "."), c.current(), current())
	}
	f, err := writeMihomoColdRetained(c.root, name, data, func() error { return errors.Join(c.current(), current()) })
	if f != nil {
		info, statErr := f.Stat()
		c.records[name] = &mihomoColdRecord{root: c.root, name: name, file: f, info: info, data: bytes.Clone(data)}
		err = errors.Join(err, statErr, syncBootRetirementDirectory(c.root, "."), c.records[name].current())
		if c.fault != nil {
			err = errors.Join(err, c.fault(name))
		}
	}
	return errors.Join(err, c.current(), current())
}
func (c *mihomoSameBootArchive) close() error {
	if c == nil || c.self != c {
		return ErrMihomoLiveRetirement
	}
	if !c.closed {
		c.closed = true
		for _, r := range c.records {
			c.closeErr = errors.Join(c.closeErr, r.file.Close())
			clear(r.data)
		}
		if c.root != nil {
			c.closeErr = errors.Join(c.closeErr, c.root.Close())
		}
		if c.parent != nil {
			c.closeErr = errors.Join(c.closeErr, c.parent.Close())
		}
	}
	return c.closeErr
}
