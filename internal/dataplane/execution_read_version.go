package dataplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

// Separate from StrategyLab, package journals and snapshot readers. Version2
// understands original domain capture/socket-bound NFQUEUE records; version3
// additionally understands original accepted-FD transparent baseline flows.
// Version4 also reads retained restorative standby and scoped Mihomo intent;
// interpreting these records never grants adoption, launch or cleanup.
// Version5 additionally reads source-issued Mihomo parent/death lineage.
// Version6 additionally reads persistent original Mihomo runtime intent.
// Version7 also reads an originally detached DNS owner with retained baseline.
// Version9 additionally reads an original retained active-checking operation.
const ExecutionReadVersion = 9

// InspectRetainedExecutionReadVersion reads every retained execution, including
// older transactions. Its seal is comparison data, never cleanup authority.
func InspectRetainedExecutionReadVersion(ctx context.Context, path string) (version int, digest string, result error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return 0, "", ErrExecutionJournal
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return 1, "absent", ctx.Err()
	}
	if err != nil || !executionHistoryOwner(info, true) {
		return 0, "", ErrExecutionJournal
	}
	root, err := ownedfs.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer func() {
		if err := root.Close(); err != nil {
			version, digest = 0, ""
			result = errors.Join(result, ErrExecutionJournal, err)
		}
	}()
	heldRoot, err := root.RootInfo()
	if err != nil || !os.SameFile(info, heldRoot) || heldRoot.Mode() != info.Mode() || !executionHistoryOwner(heldRoot, true) {
		return 0, "", ErrExecutionJournal
	}
	type observation struct {
		path string
		info os.FileInfo
		hash string
	}
	var observed []observation
	directories := map[string]os.FileInfo{}
	names := []string{"latest-execution.json"}
	var transactions []os.DirEntry
	var transactionDirectory os.FileInfo
	if dir, err := root.Stat("transactions"); err == nil {
		if !executionHistoryOwner(dir, true) {
			return 0, "", ErrExecutionJournal
		}
		transactionDirectory = dir
		transactions, err = root.ReadDirAt("transactions", 1024)
		if err != nil || len(transactions) >= 1024 {
			return 0, "", ErrExecutionJournal
		}
		sort.Slice(transactions, func(i, j int) bool { return transactions[i].Name() < transactions[j].Name() })
		for _, entry := range transactions {
			if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !validExecutionPlanID(entry.Name()) {
				return 0, "", ErrExecutionJournal
			}
			directory := filepath.Join("transactions", entry.Name())
			parent, err := root.Stat(directory)
			if err != nil || !executionHistoryOwner(parent, true) {
				return 0, "", ErrExecutionJournal
			}
			directories[directory] = parent
			names = append(names, filepath.Join("transactions", entry.Name(), "execution.json"))
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, "", err
	}
	sort.Strings(names)
	required, total := 1, int64(0)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return 0, "", err
		}
		before, err := root.Stat(name)
		if errors.Is(err, os.ErrNotExist) {
			observed = append(observed, observation{path: name})
			continue
		}
		if err != nil || !executionHistoryOwner(before, false) || before.Size() > 4<<20 {
			return 0, "", ErrExecutionJournal
		}
		f, err := executionHistoryOpen(root, name)
		if err != nil {
			return 0, "", err
		}
		held, statErr := f.Stat()
		if statErr != nil || !os.SameFile(before, held) || !executionHistoryOwner(held, false) {
			f.Close()
			return 0, "", ErrExecutionJournal
		}
		data, readErr := io.ReadAll(io.LimitReader(f, (4<<20)+1))
		afterFD, statErr := f.Stat()
		closeErr := f.Close()
		after, afterErr := root.Stat(name)
		if readErr != nil || statErr != nil || closeErr != nil || afterErr != nil || len(data) > 4<<20 || !sameExecutionHistoryFile(held, afterFD) || !sameExecutionHistoryFile(held, after) {
			return 0, "", ErrExecutionJournal
		}
		total += int64(len(data))
		if total > 32<<20 {
			return 0, "", ErrExecutionJournal
		}
		var execution Execution
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if nfqws2ManagedUniqueJSON(data) != nil || decoder.Decode(&execution) != nil || decoder.Decode(new(any)) != io.EOF || !validExecutionPlanID(execution.PlanID) || validateExecutionResources(execution, false) != nil {
			return 0, "", ErrExecutionJournal
		}
		if name != "latest-execution.json" && filepath.Base(filepath.Dir(name)) != execution.PlanID {
			return 0, "", ErrExecutionJournal
		}
		if execution.MihomoTransitHistoryArchive != nil && name == "latest-execution.json" {
			return 0, "", ErrExecutionJournal
		}
		switch execution.State {
		case mihomoActiveCheckingState:
			required = max(required, 9)
		case "applying", "checking", "resource-failed", "cancelled", "replacement-pending", "rejected", "journal-failed", "rolling-back", "rolled-back", "rollback-failed", "canary-failed", "network-stale", "committing", "committed", "temporary-complete":
		default:
			return 0, "", ErrExecutionJournal
		}
		if execution.MihomoLiveHealthOperation != nil {
			required = max(required, 9)
		}
		if execution.DomainDNSCoexistence != nil || execution.MihomoTransitHistoryArchive != nil {
			required = max(required, 8)
		}
		for _, resource := range execution.Resources {
			if resource.DomainDNSCoexistence != nil {
				required = max(required, 8)
			}

			if resource.DomainDNSDetached != nil {
				required = max(required, 7)
			}
			if resource.MihomoLive != nil || resource.NodeTransit != nil && resource.NodeTransit.Engine == "mihomo" {
				required = max(required, 6)
			}
			if resource.DomainTCPCapture != nil || resource.XrayDomainTCP != nil || resource.NFQWS != nil && resource.NFQWS.Spec.Probe != nil {
				required = max(required, 2)
			}
			if resource.DomainTCPBaseline != nil {
				required = max(required, 3)
			}
			if resource.SyntheticBaseline != nil && resource.Phase == "standby-retained" {
				required = max(required, 4)
			}
			if resource.MihomoProbe != nil {
				required = max(required, 4)
				if !resource.MihomoProbe.Source.ParentOrigin.IsZero() {
					required = max(required, 5)
				}
			}
		}
		sum := sha256.Sum256(data)
		observed = append(observed, observation{name, held, hex.EncodeToString(sum[:])})
	}
	// Closing observations reject namespace/object changes during the scan.
	if transactionDirectory != nil {
		dir, err := root.Stat("transactions")
		if err != nil || !os.SameFile(transactionDirectory, dir) || !executionHistoryOwner(dir, true) {
			return 0, "", ErrExecutionJournal
		}
		after, err := root.ReadDirAt("transactions", 1024)
		if err != nil || len(after) != len(transactions) {
			return 0, "", ErrExecutionJournal
		}
		sort.Slice(after, func(i, j int) bool { return after[i].Name() < after[j].Name() })
		for i := range after {
			if after[i].Name() != transactions[i].Name() || after[i].Type() != transactions[i].Type() {
				return 0, "", ErrExecutionJournal
			}
		}
	} else if _, err := root.Stat("transactions"); !errors.Is(err, os.ErrNotExist) {
		return 0, "", ErrExecutionJournal
	}
	seal := sha256.New()
	fmt.Fprintf(seal, "root %s\n", executionHistoryIdentity(info))
	for _, name := range names {
		parentName := filepath.Dir(name)
		if parent := directories[parentName]; parent != nil {
			fresh, err := root.Stat(parentName)
			if err != nil || !os.SameFile(parent, fresh) || !executionHistoryOwner(fresh, true) {
				return 0, "", ErrExecutionJournal
			}
			fmt.Fprintf(seal, "directory %s %s\n", parentName, executionHistoryIdentity(parent))
		}
	}
	for _, o := range observed {
		current, err := root.Stat(o.path)
		if o.info == nil {
			if !errors.Is(err, os.ErrNotExist) {
				return 0, "", ErrExecutionJournal
			}
			fmt.Fprintf(seal, "%s absent\n", o.path)
			continue
		}
		if err != nil || !sameExecutionHistoryFile(o.info, current) {
			return 0, "", ErrExecutionJournal
		}
		fmt.Fprintf(seal, "%s %s %s %d %d %s\n", o.path, o.hash, executionHistoryIdentity(o.info), o.info.Size(), o.info.Mode(), o.info.ModTime().UTC().String())
	}
	closing, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, closing) || !executionHistoryOwner(closing, true) {
		return 0, "", ErrExecutionJournal
	}
	closingFD, err := root.RootInfo()
	if err != nil || !os.SameFile(info, closingFD) || closingFD.Mode() != info.Mode() || !executionHistoryOwner(closingFD, true) {
		return 0, "", ErrExecutionJournal
	}
	return required, hex.EncodeToString(seal.Sum(nil)), ctx.Err()
}

func sameExecutionHistoryFile(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime()) && executionHistoryOwner(b, false)
}
