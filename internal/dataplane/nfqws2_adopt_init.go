package dataplane

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
)

// DefaultNFQWS2PackageList is where opkg records the files installed by the
// nfqws2-keenetic package, including the init script NFQWS2Adapter runs.
const DefaultNFQWS2PackageList = "/opt/lib/opkg/info/nfqws2-keenetic.list"

// ErrNFQWS2NotOwned: RAZVILKA holds no NFQWS2 ownership lease, so a changed
// package init needs no adoption; the next Apply records the current one.
var ErrNFQWS2NotOwned = errors.New("NFQWS2 is not owned by this instance; there is no init to adopt")

// AdoptPackageInit records a replaced NFQWS2 init script in the ownership
// lease after an operator upgraded the nfqws2-keenetic package outside
// RAZVILKA. Upgrading the package replaces S51nfqws2, and until the new script
// is adopted every ownership check refuses, including rollback verification.
//
// It changes no runtime and grants no network permission. The configuration
// and both managed list blocks must still match the lease exactly: only the
// init hash may differ, and the new script must be a file listed by the
// installed package, executable and not writable by group or others.
// packageList is the opkg file list; empty means DefaultNFQWS2PackageList.
func (a *NFQWS2Adapter) AdoptPackageInit(packageList string) (previous, adopted string, err error) {
	if packageList == "" {
		packageList = DefaultNFQWS2PackageList
	}
	unlock, err := a.lockResources()
	if err != nil {
		return "", "", err
	}
	defer unlock()
	lease, err := a.readLease()
	if err != nil {
		return "", "", err
	}
	if lease == nil {
		return "", "", ErrNFQWS2NotOwned
	}
	config, _, err := nfqws2Read(a.ConfigPath)
	if err != nil {
		return "", "", err
	}
	if nfqws2Hash(config) != lease.ConfigHash {
		return "", "", errors.New("NFQWS2 configuration changed outside its ownership manifest; only a package init change can be adopted")
	}
	for index, path := range []string{a.UserListPath, a.IPSetListPath} {
		data, _, err := nfqws2Read(path)
		if err != nil {
			return "", "", err
		}
		if err := a.checkListOwnership(lease, index, data, false); err != nil {
			return "", "", err
		}
	}
	init, exists, err := nfqws2Read(a.InitPath)
	if err != nil || !exists || len(init) == 0 {
		return "", "", errors.Join(err, errors.New("NFQWS2 init is unavailable"))
	}
	info, err := os.Lstat(a.InitPath)
	if err != nil {
		return "", "", err
	}
	if runtime.GOOS != "windows" && (info.Mode().Perm()&0o022 != 0 || info.Mode().Perm()&0o100 == 0) {
		return "", "", errors.New("NFQWS2 init must be executable and not writable by group or others")
	}
	listed, err := packageListsPath(packageList, a.InitPath)
	if err != nil {
		return "", "", err
	}
	if !listed {
		return "", "", errors.New("NFQWS2 init is not provided by the installed nfqws2-keenetic package")
	}
	adopted = nfqws2Hash(init)
	if adopted == lease.InitHash {
		return lease.InitHash, adopted, nil
	}
	updated := *lease
	updated.InitHash = adopted
	if err := a.writeLease(&updated); err != nil {
		return "", "", err
	}
	return lease.InitHash, adopted, nil
}

// AdoptNFQWS2PackageInit runs NFQWS2Adapter.AdoptPackageInit under the
// dataplane operation, so it cannot interleave with an Apply or rollback.
func (m *Manager) AdoptNFQWS2PackageInit(ctx context.Context, packageList string) (previous, adopted string, err error) {
	if m == nil || m.StateRoot == "" {
		return "", "", errors.New("dataplane state root is not configured")
	}
	if err := m.beginOperation(ctx); err != nil {
		return "", "", err
	}
	defer m.endOperation()
	adapter, _ := m.adapter("nfqws2")
	nfqws2, ok := adapter.(*NFQWS2Adapter)
	if !ok {
		return "", "", errors.New("NFQWS2 adapter is not registered")
	}
	return nfqws2.AdoptPackageInit(packageList)
}

// packageListsPath reports whether an opkg ".list" file names path. Each line
// starts with an installed path; anything after whitespace is ignored.
func packageListsPath(list, path string) (bool, error) {
	data, exists, err := nfqws2Read(list)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, errors.New("installed nfqws2-keenetic package file list is unavailable")
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		if fields := strings.Fields(scanner.Text()); len(fields) > 0 && fields[0] == path {
			return true, nil
		}
	}
	return false, scanner.Err()
}

// NFQWS2ServiceState reports the package service status and the current
// configuration bytes. A managed component update compares them before and
// after the package change; neither call changes the runtime.
func (m *Manager) NFQWS2ServiceState(ctx context.Context) (running bool, config []byte, err error) {
	adapter, _ := m.adapter("nfqws2")
	nfqws2, ok := adapter.(*NFQWS2Adapter)
	if !ok {
		return false, nil, errors.New("NFQWS2 adapter is not registered")
	}
	config, _, err = nfqws2Read(nfqws2.ConfigPath)
	if err != nil {
		return false, nil, err
	}
	if nfqws2.Runner == nil || !regularFile(nfqws2.InitPath) {
		return false, config, nil
	}
	output, statusErr := nfqws2.run(ctx, nfqws2.InitPath, "status")
	return statusErr == nil && runningOutput(string(output)), config, nil
}
