package dataplane

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ArtixSx/razvilka/internal/components"
	"github.com/ArtixSx/razvilka/internal/engineconfig"
)

// ConfigureNFQWSStockNative binds the real component writer before HTTP and
// workers start. It never substitutes a detached installed-version DTO for it.
func (m *Manager) ConfigureNFQWSStockNative(owner *components.Manager) error {
	if m == nil || owner == nil {
		return components.ErrStockNFQWSNative
	}
	adapter, ok := m.adapter("nfqws2")
	if !ok {
		return components.ErrStockNFQWSNative
	}
	a, ok := adapter.(*NFQWS2Adapter)
	if !ok || a.stockNativeOwner != nil {
		return components.ErrStockNFQWSNative
	}
	a.stockNativeOwner = owner
	return nil
}

func (a *NFQWS2Adapter) validateStockNative(ctx context.Context, plan Plan, root string) (result error) {
	// Separate managed execution owns its own original runtime/validation
	// issuer. This hook is only the ordinary package adapter path above it.
	if a.stockNativeOwner == nil {
		return nil
	}
	if filepath.Clean(a.InitPath) != filepath.Join(a.stockNativeOwner.InitDir, "S51nfqws2") {
		return components.ErrStockNFQWSNative
	}
	if filepath.Clean(a.ConfigPath) != filepath.Join(filepath.Dir(a.stockNativeOwner.InitDir), "nfqws2", "nfqws2.conf") {
		return components.ErrStockNFQWSNative
	}
	snapshot, err := readNFQWS2Snapshot(root)
	if err != nil {
		return err
	}
	config := snapshot.Config
	if snapshot.ConfigDraft {
		config = snapshot.StagedConfig
	}
	expected, err := a.exclusionConfig(config, plan)
	if snapshot.FirstStart {
		expected, err = a.firstStartConfig(plan, config)
	}
	if err != nil {
		return err
	}
	staged, exists, err := nfqws2Read(filepath.Join(root, "nfqws2.conf.staged"))
	if err != nil || !exists || !bytes.Equal(staged, expected) {
		return components.ErrStockNFQWSNative
	}
	owner, _, err := removeManagedBlock(string(config))
	if err != nil {
		return err
	}
	if snapshot.FirstStart {
		instance, err := a.owner()
		if err != nil {
			return err
		}
		owner, err = engineconfig.NFQWSFirstStartEffectiveConfig(staged, instance)
		if err != nil {
			return err
		}
	}
	running, runningExists, err := nfqws2Read(a.ConfigPath + ".run")
	if err != nil {
		return err
	}
	if runningExists {
		var err error
		if snapshot.FirstStart {
			instance, _ := a.owner()
			err = engineconfig.NFQWSFirstStartRunningConfig(config, instance, running)
		} else {
			err = engineconfig.NFQWSRunningConfigMatches(owner, string(running))
		}
		if err != nil {
			return err
		}
	}
	leading := []string{}
	domains, addresses := nfqws2PlanExclusions(plan, a.ID())
	if snapshot.FirstStart {
		domains, addresses = nil, nil
	}
	if len(domains) > 0 {
		leading = append(leading, "--hostlist-domains="+strings.Join(sortedUnique(domains), ","))
	}
	if len(addresses) > 0 {
		if len(leading) > 0 {
			leading = append(leading, "--new")
		}
		prefixes := []string{}
		for _, value := range addresses {
			prefix, e := siteExclusionPrefix(value)
			if e != nil {
				return e
			}
			prefixes = append(prefixes, prefix.String())
		}
		leading = append(leading, "--ipset-ip="+strings.Join(sortedUnique(prefixes), ","))
	}
	arguments, err := engineconfig.NFQWSStartupArguments(owner, leading)
	if err != nil {
		return err
	}
	paths := a.ownedListPaths()
	var listImages [4][]byte
	for index, name := range nfqws2ListStages {
		data, exists, err := nfqws2Read(filepath.Join(root, name))
		if err != nil || !exists {
			return components.ErrStockNFQWSNative
		}
		listImages[index] = data
	}
	// Validate the actual staged list bytes that will be installed, not the
	// previous live lists. Their eventual paths remain in the saved config.
	for i, arg := range arguments {
		flag, path, hasValue := strings.Cut(arg, "=")
		if !hasValue {
			continue
		}
		switch flag {
		case "--hostlist-auto", "--hostlist-auto-debug":
			return errors.New("stock NFQWS2 automatic-list validation requires a separate reviewed path")
		case "--hostlist", "--hostlist-exclude", "--ipset", "--ipset-exclude":
			index := slices.Index(paths[:], filepath.Clean(path))
			if index < 0 {
				return components.ErrStockNFQWSNative
			}
			arguments[i] = flag + "=" + filepath.Join(root, nfqws2ListStages[index])
		}
	}
	current := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if guard, ok := ctx.Value(reviewGuardKey{}).(func(context.Context) error); ok && guard != nil {
			if err := guard(ctx); err != nil {
				return err
			}
		}
		actual, exists, err := nfqws2Read(a.ConfigPath)
		if err != nil || exists != snapshot.ConfigExisted || !bytes.Equal(actual, snapshot.Config) {
			return ErrReviewChanged
		}
		actual, exists, err = nfqws2Read(filepath.Join(root, "nfqws2.conf.staged"))
		if err != nil || !exists || !bytes.Equal(actual, staged) {
			return ErrReviewChanged
		}
		actual, exists, err = nfqws2Read(a.ConfigPath + ".run")
		if err != nil || exists != runningExists || !bytes.Equal(actual, running) {
			return ErrReviewChanged
		}
		for index, name := range nfqws2ListStages {
			actual, exists, err := nfqws2Read(filepath.Join(root, name))
			if err != nil || !exists || !bytes.Equal(actual, listImages[index]) {
				return ErrReviewChanged
			}
		}
		return nil
	}
	if err := current(); err != nil {
		return err
	}
	nativeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	review, err := a.stockNativeOwner.ReviewStockNFQWSNative(nativeCtx, arguments)
	if err != nil {
		return err
	}
	retained := false
	defer func() {
		if !retained {
			result = errors.Join(result, review.Close())
		}
	}()
	if err := current(); err != nil {
		return err
	}
	if err := review.DryRun(nativeCtx); err != nil {
		return err
	}
	if err := current(); err != nil {
		return err
	}
	if snapshot.FirstStart {
		if a.firstStartReview != nil {
			return components.ErrStockNFQWSNative
		}
		a.firstStartReview, a.firstStartReviewRoot = review, root
		retained = true
	}
	return nil
}
