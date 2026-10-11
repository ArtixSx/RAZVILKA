package updatecheck

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"

	"github.com/ArtixSx/razvilka/internal/config"
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

var ErrPairedOfflineRestore = errors.New("paired offline restore requires a current owner and complete matching evidence")
var ErrPairedOfflineOrphan = errors.New("paired offline restore has retained staging evidence; manual review required")

// This result describes data only. It grants no Start, runtime acceptance,
// stopped settlement, helper adoption, or compatibility with current journals.
type SelfUpdateOfflineRestoreResult struct {
	State string `json:"state"`
}

// Offline admission belongs to the actual CURRENT exclusive owner/Stop epoch,
// not the historical reviewed epoch. Only a bounded fd-pinned rename runs in
// begin. The trusted caller supplies no paths, payloads, or claimed checksum.
type SelfUpdateOfflineRestoreAdmission func(context.Context, string, string, func() error) error

const pairedOfflineStagePrefix = ".paired-offline-"

const pairedOfflineInitGuard = "#!/bin/sh\n" +
	"echo 'RAZVILKA: paired state restored offline; current recovery review required before Start' >&2\n" +
	"exit 1\n"

// Independent monotonic evidence remains in place, including unknown retained
// generations. The complete prior bytes still reside in the bound archive.
// A preserved runtime/controller record does not become compatible with the
// restored app/config merely because it has been retained.
var pairedOfflineProtected = []string{
	"etc/razvilka/private-restore", "etc/razvilka/private-restore-nodes-v1",
	"etc/razvilka/private-restore-native-v1", "etc/razvilka/private-restore-feeds-v1",
	"etc/razvilka/cloudflare-private",
	"razvilka/state/self-update", "razvilka/state/self-update-files", "razvilka/state/self-update-stop",
	"razvilka/state/update-backups", "razvilka/state/current-backup",
	"razvilka/state/dataplane", "razvilka/state/warp", "razvilka/state/backups",
	"razvilka/state/components/update-journal", "razvilka/state/components/operations",
	"razvilka/state/components/rollback-packages",
}

type offlinePriorNode struct {
	directory bool
	mode      uint32
	size      int64
	sha       string
	blob      string
	data      []byte
}

type offlinePriorReplacement struct {
	path       string
	before     map[string]offlinePriorNode
	after      map[string]offlinePriorNode
	seen       []priorStateObservation
	parent     *os.Root
	parentInfo os.FileInfo
	parentFD   *os.File
	stage      string
	staged     os.FileInfo
}

func offlinePriorNodes(doc pairedPriorArchive) map[string]offlinePriorNode {
	nodes := make(map[string]offlinePriorNode)
	for _, root := range doc.Roots {
		if !root.Exists {
			continue
		}
		nodes[root.Path] = offlinePriorNode{directory: root.Directory, mode: root.Mode}
		for _, entry := range root.Entries {
			nodes[root.Path+"/"+filepath.ToSlash(entry.Name)] = offlinePriorNode{directory: entry.Directory, mode: entry.Mode}
		}
	}
	for _, payload := range doc.Payloads {
		path := doc.Roots[payload.Root].Path
		if payload.Name != "" {
			path += "/" + filepath.ToSlash(payload.Name)
		}
		node := nodes[path]
		node.size, node.sha, node.blob = payload.Size, payload.SHA256, payload.Blob
		nodes[path] = node
	}
	return nodes
}

func offlineProtected(path string) bool {
	for _, prefix := range pairedOfflineProtected {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	// A future private-restore generation is retained as independent evidence,
	// never interpreted, adopted or removed by an older restore implementation.
	name := strings.TrimPrefix(path, "etc/razvilka/")
	return name != path && strings.HasPrefix(strings.Split(name, "/")[0], "private-restore-")
}

func offlineAnchor(path string) bool {
	if path == "etc/razvilka" || path == "razvilka/state" {
		return true // Never exchange a live control/config root inode.
	}
	for _, prefix := range pairedOfflineProtected {
		if strings.HasPrefix(prefix, path+"/") {
			return true
		}
	}
	return false
}

func offlineSubtree(nodes map[string]offlinePriorNode, path string) map[string]offlinePriorNode {
	result := map[string]offlinePriorNode{}
	for name, node := range nodes {
		if name == path || strings.HasPrefix(name, path+"/") {
			node.blob, node.data = "", nil
			result[name] = node
		}
	}
	return result
}

func offlineRestorePlan(before, after map[string]offlinePriorNode, seen []priorStateObservation) ([]offlinePriorReplacement, error) {
	for path := range before {
		for _, name := range strings.Split(path, "/") {
			if strings.HasPrefix(name, pairedOfflineStagePrefix) {
				return nil, ErrPairedOfflineOrphan
			}
		}
	}
	var plan []offlinePriorReplacement
	var visit func(string) error
	visit = func(path string) error {
		if offlineProtected(path) {
			return nil
		}
		if offlineAnchor(path) {
			old, oldExists := before[path]
			prior, priorExists := after[path]
			if !oldExists || !old.directory || priorExists && !prior.directory {
				return ErrPairedOfflineRestore
			}
			children := map[string]bool{}
			for _, nodes := range []map[string]offlinePriorNode{before, after} {
				for name := range nodes {
					if strings.HasPrefix(name, path+"/") {
						children[path+"/"+strings.Split(strings.TrimPrefix(name, path+"/"), "/")[0]] = true
					}
				}
			}
			var names []string
			for name := range children {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				if err := visit(name); err != nil {
					return err
				}
			}
			return nil
		}
		old, prior := offlineSubtree(before, path), offlineSubtree(after, path)
		if reflect.DeepEqual(old, prior) {
			return nil
		}
		item := offlinePriorReplacement{path: path, before: old, after: map[string]offlinePriorNode{}}
		for name, node := range after {
			if name == path || strings.HasPrefix(name, path+"/") {
				item.after[name] = node
			}
		}
		for _, observation := range seen {
			name := filepath.ToSlash(observation.path)
			if name == path || strings.HasPrefix(name, path+"/") {
				item.seen = append(item.seen, observation)
			}
		}
		plan = append(plan, item)
		return nil
	}
	for _, spec := range pairedPriorRoots {
		if err := visit(spec.path); err != nil {
			return nil, err
		}
	}
	// All payloads are staged first. The durable init guards precede every
	// application/data replacement; the old executable is published last.
	priority := func(path string) int {
		if path == "etc/init.d/S99razvilka" || path == "etc/init.d/S99artem-flow" || path == "etc/init.d/S99artem-flow.razvilka-disabled" {
			return 0
		}
		if path == "bin/razvilka" {
			return 2
		}
		return 1
	}
	sort.SliceStable(plan, func(i, j int) bool { return priority(plan[i].path) < priority(plan[j].path) })
	return plan, nil
}

// Preserve current saved exclusion/Stop intent in the prior config. Unrelated
// prior fields remain byte-valued JSON; no global config DTO rewrite silently
// drops data. Unknown config schemas/fields are refused by the owning typed
// reader before any effect. The offline archive still retains their bytes.
func offlinePriorConfig(prior, current []byte) ([]byte, error) {
	cfg, _, err := config.InspectBytes(current)
	if err != nil || cfg.Revision == ^uint64(0) {
		return nil, ErrPairedOfflineRestore
	}
	if _, _, err := config.InspectBytes(prior); err != nil {
		return nil, ErrPairedOfflineRestore
	}
	var old, fresh map[string]json.RawMessage
	if json.Unmarshal(prior, &old) != nil || json.Unmarshal(current, &fresh) != nil {
		return nil, ErrPairedOfflineRestore
	}
	for _, name := range []string{"network_policy", "applied_network_policy", "inactive_resource_exclusions", "default_route_consent", "service_control"} {
		if value, ok := fresh[name]; ok {
			old[name] = bytes.Clone(value)
		} else {
			delete(old, name)
		}
	}
	old["revision"], _ = json.Marshal(cfg.Revision + 1)
	old["safe_mode"] = json.RawMessage("true")
	var control map[string]json.RawMessage
	if value := old["service_control"]; len(value) > 0 && json.Unmarshal(value, &control) != nil {
		return nil, ErrPairedOfflineRestore
	}
	if control == nil {
		control = map[string]json.RawMessage{}
	}
	control["stopped"] = json.RawMessage("true")
	old["service_control"], _ = json.Marshal(control)
	data, err := json.Marshal(old)
	if err != nil || len(data) > 4<<20 {
		return nil, ErrPairedOfflineRestore
	}
	checked, _, err := config.InspectBytes(data)
	if err != nil || !checked.SafeMode || !checked.ServiceControl.Stopped || !fileConfigExclusionsPreserved(cfg, checked) {
		return nil, ErrPairedOfflineRestore
	}
	return append(data, '\n'), nil
}

func readOfflineBlob(ctx context.Context, archive *os.Root, node offlinePriorNode, limit int64) ([]byte, error) {
	if node.directory || node.size > limit {
		return nil, ErrPairedOfflineRestore
	}
	file, err := openPriorArchiveReadOnly(archive, node.blob)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) != node.size || digestBytes(data) != node.sha {
		return nil, ErrPairedOfflineRestore
	}
	return data, ctx.Err()
}

// RestorePairedPriorState is an explicit offline operation. It uses a fresh
// trusted owner capability because a historical review cannot authorize a
// restore over newer Stop/exclusions. App/Main supplies the current exclusive
// context and admission; no old UI helper or receipt DTO can manufacture them.
func (a *SelfUpdateFileAdapter) RestorePairedPriorState(ctx context.Context, id string, currentOwner SelfUpdateRuntimeObservation, admission SelfUpdateOfflineRestoreAdmission) (SelfUpdateOfflineRestoreResult, error) {
	var result SelfUpdateOfflineRestoreResult
	if runtime.GOOS != "linux" || a == nil || ctx == nil || currentOwner == nil || admission == nil || a.runtimeInactive == nil {
		return result, ErrPairedOfflineRestore
	}
	record, review, err := a.loadBoundReview(ctx, id, true, true)
	if err != nil {
		// An interrupted current helper can be restored only after its actual
		// independent process evidence is proven inactive below.
		record, review, err = a.load(ctx, id)
	}
	if err != nil {
		return result, err
	}
	// The restore writer is the physically running verified candidate. A
	// retained prior controller is evidence only, even if its path still exists
	// or it reports a familiar version. No source-reader ABI is inferred here.
	self, err := fileProcessAt(os.Getpid())
	if err != nil || self.ExecutableSHA256 != strings.TrimPrefix(record.Job.Release.Binary.Digest, "sha256:") || self.ExecutableSHA256 != record.Files["dist/"+record.Job.Release.Binary.Name] {
		return result, ErrPairedOfflineRestore
	}
	check := func(c context.Context) error {
		if c != ctx || a.checkStop(c, id, "read/observe") != nil {
			return ErrPairedOfflineRestore
		}
		return currentOwner(c, id)
	}
	quiescence := func(c context.Context) error {
		if a.fileQuiescence(c, id) != nil || a.filePanelAbsent(c) != nil || a.runtimeInactive(c, id) != nil {
			return ErrPairedOfflineRestore
		}
		identity, err := a.helperIdentityForRecord(id, review, record)
		if err != nil {
			return err
		}
		observe := a.processInactive
		if observe == nil {
			observe = fileProcessInactive
		}
		for _, process := range []fileProcess{identity.Process, identity.OldPanel} {
			if err := observe(c, process); err != nil {
				return err
			}
		}
		return c.Err()
	}
	store, err := a.OpenFileJournal()
	if err != nil {
		return result, err
	}
	defer store.Close()
	err = store.WithPairedOfflineRestore(ctx, id, check, quiescence, func(c context.Context, receipt selfupdatejournal.Receipt, held selfupdatejournal.Check) error {
		return restorePairedOffline(c, a.installation, receipt, a.owned, held, func(effect string, begin func() error) error {
			return admission(c, id, effect, begin)
		}, commitOfflinePriorReplacement, nil)
	})
	if err == nil {
		result.State = "offline-requires-review"
	}
	return result, err
}

type offlinePriorCommit func(context.Context, *offlinePriorReplacement, func(func() error) error) error

func syncOfflineRoot(root *os.Root) error {
	if runtime.GOOS == "windows" {
		return nil
	} // model only; public API is Linux.
	file, err := root.Open(".")
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func stageOfflinePriorReplacement(ctx context.Context, installation string, archive *os.Root, item *offlinePriorReplacement, owned func(string) error) error {
	path := filepath.Join(installation, filepath.FromSlash(item.path))
	if owned(filepath.Dir(path)) != nil {
		return ErrPairedOfflineRestore
	}
	parent, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	item.parent = parent
	item.parentInfo, err = parent.Stat(".")
	if err != nil || !safePriorSourceInfo(item.parentInfo) {
		return ErrPairedOfflineRestore
	}
	item.parentFD, err = parent.Open(".")
	if err != nil {
		return err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	item.stage = pairedOfflineStagePrefix + hex.EncodeToString(nonce[:])
	node, exists := item.after[item.path]
	if !exists {
		return nil
	}
	if node.directory {
		if err := parent.Mkdir(item.stage, 0700); err != nil {
			return err
		}
		root, err := parent.OpenRoot(item.stage)
		if err != nil {
			return err
		}
		defer root.Close()
		var names []string
		for name := range item.after {
			if name != item.path {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return err
			}
			node := item.after[name]
			rel := filepath.FromSlash(strings.TrimPrefix(name, item.path+"/"))
			if node.directory {
				if err := root.Mkdir(rel, 0700); err != nil {
					return err
				}
			} else if err := stageOfflinePriorFile(ctx, archive, root, rel, node); err != nil {
				return err
			}
		}
		// Parent permissions are installed after descendants are copied/synced.
		for i := len(names) - 1; i >= 0; i-- {
			entry := item.after[names[i]]
			if !entry.directory {
				continue
			}
			rel := filepath.FromSlash(strings.TrimPrefix(names[i], item.path+"/"))
			if err := root.Chmod(rel, os.FileMode(entry.mode)); err != nil {
				return err
			}
			child, err := root.OpenRoot(rel)
			if err != nil {
				return err
			}
			err = syncOfflineRoot(child)
			child.Close()
			if err != nil {
				return err
			}
		}
		if err := root.Chmod(".", os.FileMode(node.mode)); err != nil {
			return err
		}
		if err := syncOfflineRoot(root); err != nil {
			return err
		}
	} else if err := stageOfflinePriorFile(ctx, archive, parent, item.stage, node); err != nil {
		return err
	}
	if err := syncOfflineRoot(parent); err != nil {
		return err
	}
	item.staged, err = parent.Lstat(item.stage)
	if err != nil || !safePriorSourceInfo(item.staged) {
		return ErrPairedOfflineRestore
	}
	return ctx.Err()
}

func stageOfflinePriorFile(ctx context.Context, archive, output *os.Root, name string, node offlinePriorNode) error {
	file, err := output.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if node.data != nil {
		if int64(len(node.data)) != node.size || digestBytes(node.data) != node.sha {
			return ErrPairedOfflineRestore
		}
		_, err = file.Write(node.data)
	} else {
		before, statErr := archive.Lstat(node.blob)
		if statErr != nil || !privatePriorArchiveInfo(before, false) || before.Size() != node.size {
			return ErrPairedOfflineRestore
		}
		in, openErr := openPriorArchiveReadOnly(archive, node.blob)
		if openErr != nil {
			return openErr
		}
		opened, openErr := in.Stat()
		if openErr != nil || !samePriorInfo(before, opened) {
			in.Close()
			return ErrPairedOfflineRestore
		}
		hash := sha256.New()
		var n int64
		n, err = copyPriorArchiveBytes(ctx, io.MultiWriter(file, hash), in)
		after, statErr := in.Stat()
		in.Close()
		current, currentErr := archive.Lstat(node.blob)
		if err != nil || statErr != nil || currentErr != nil || n != node.size || hex.EncodeToString(hash.Sum(nil)) != node.sha || !samePriorInfo(before, after) || !samePriorInfo(before, current) {
			return ErrPairedOfflineRestore
		}
	}
	if err != nil {
		return err
	}
	if err := file.Chmod(os.FileMode(node.mode)); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	actual, err := output.Lstat(name)
	if err != nil || actual.Size() != node.size || !safePriorSourceInfo(actual) {
		return ErrPairedOfflineRestore
	}
	_, hash, err := copyPriorArchiveFile(ctx, output, name, actual, nil, "")
	if err != nil || hash != node.sha {
		return ErrPairedOfflineRestore
	}
	return ctx.Err()
}

func verifyOfflinePriorTarget(ctx context.Context, source *os.Root, item *offlinePriorReplacement) error {
	path := filepath.FromSlash(item.path)
	if len(item.before) == 0 {
		if _, err := source.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return ErrPairedOfflineRestore
		}
		return ctx.Err()
	}
	seen := map[string]bool{}
	for _, observation := range item.seen {
		info, err := source.Lstat(observation.path)
		if err != nil || !samePriorInfo(observation.info, info) || !safePriorSourceInfo(info) {
			return ErrPairedOfflineRestore
		}
		name := filepath.ToSlash(observation.path)
		node, exists := item.before[name]
		if !exists {
			return ErrPairedOfflineRestore
		}
		seen[name] = true
		if node.directory {
			file, err := source.Open(observation.path)
			if err != nil {
				return err
			}
			entries, readErr := file.ReadDir(4097)
			file.Close()
			if readErr != nil && readErr != io.EOF || len(entries) > 4096 {
				return ErrPairedOfflineRestore
			}
			count := 0
			for child := range item.before {
				if filepath.ToSlash(filepath.Dir(filepath.FromSlash(child))) == name {
					count++
				}
			}
			if len(entries) != count {
				return ErrPairedOfflineRestore
			}
			for _, child := range entries {
				if _, exists := item.before[name+"/"+child.Name()]; !exists {
					return ErrPairedOfflineRestore
				}
			}
		} else {
			n, hash, err := copyPriorArchiveFile(ctx, source, observation.path, info, nil, "")
			if err != nil || n != node.size || hash != node.sha {
				return ErrPairedOfflineRestore
			}
		}
	}
	if len(seen) != len(item.before) {
		return ErrPairedOfflineRestore
	}
	return ctx.Err()
}

func verifyOfflinePriorStage(ctx context.Context, item *offlinePriorReplacement) error {
	if _, exists := item.after[item.path]; !exists {
		return ctx.Err()
	}
	for path, node := range item.after {
		name := item.stage
		if path != item.path {
			name = filepath.Join(name, filepath.FromSlash(strings.TrimPrefix(path, item.path+"/")))
		}
		info, err := item.parent.Lstat(name)
		if err != nil || !safePriorSourceInfo(info) || info.IsDir() != node.directory || runtime.GOOS != "windows" && uint32(info.Mode().Perm()) != node.mode {
			return ErrPairedOfflineRestore
		}
		if node.directory {
			file, err := item.parent.Open(name)
			if err != nil {
				return err
			}
			entries, readErr := file.ReadDir(4097)
			file.Close()
			if readErr != nil && readErr != io.EOF || len(entries) > 4096 {
				return ErrPairedOfflineRestore
			}
			count := 0
			for child := range item.after {
				if filepath.ToSlash(filepath.Dir(filepath.FromSlash(child))) == path {
					count++
				}
			}
			if len(entries) != count {
				return ErrPairedOfflineRestore
			}
			for _, child := range entries {
				if _, exists := item.after[path+"/"+child.Name()]; !exists {
					return ErrPairedOfflineRestore
				}
			}
		} else {
			n, sha, err := copyPriorArchiveFile(ctx, item.parent, name, info, nil, "")
			if err != nil || n != node.size || sha != node.sha {
				return ErrPairedOfflineRestore
			}
		}
	}
	return ctx.Err()
}

func restorePairedOffline(ctx context.Context, installation string, receipt selfupdatejournal.Receipt, owned func(string) error, check selfupdatejournal.Check, admission func(string, func() error) error, commit offlinePriorCommit, cut func(string) error) error {
	if ctx == nil || owned == nil || check == nil || admission == nil || commit == nil || receipt.Schema != selfupdatejournal.PairedSchema || receipt.Paired == nil {
		return ErrPairedOfflineRestore
	}
	if _, finite := ctx.Deadline(); !finite {
		return ErrPairedOfflineRestore
	}
	var archiveStable func() error
	boundary := func(name string) error {
		if err := check(ctx); err != nil {
			return err
		}
		if archiveStable != nil {
			if err := archiveStable(); err != nil {
				return err
			}
		}
		if cut != nil {
			return cut(name)
		}
		return ctx.Err()
	}
	if err := boundary("before:offline-read"); err != nil || owned(installation) != nil {
		return errors.Join(ErrPairedOfflineRestore, err)
	}
	b := receipt.Paired
	binding := pairedPriorBinding{receipt.ID, b.ReviewSHA256, b.PreparedSHA256, b.InstallationID, b.Sequence, b.Revision}
	path := filepath.Join(installation, filepath.FromSlash(pairedPriorArchiveDirectory), receipt.ID)
	archive, err := ownedfs.Open(path)
	if err != nil || owned(path) != nil {
		if archive != nil {
			archive.Close()
		}
		return ErrPairedOfflineRestore
	}
	defer archive.Close()
	archiveFS, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	defer archiveFS.Close()
	archiveInfo, archiveErr := archive.RootInfo()
	baseInfo, baseErr := os.Lstat(filepath.Dir(path))
	if archiveErr != nil || baseErr != nil || !privatePriorArchiveInfo(archiveInfo, true) || !privatePriorArchiveInfo(baseInfo, true) {
		return ErrPairedOfflineRestore
	}
	archiveStable = func() error {
		current, err := os.Lstat(path)
		base, baseErr := os.Lstat(filepath.Dir(path))
		if err != nil || baseErr != nil || !os.SameFile(archiveInfo, current) || !os.SameFile(baseInfo, base) || !privatePriorArchiveInfo(current, true) || !privatePriorArchiveInfo(base, true) || owned(path) != nil {
			return ErrPairedOfflineRestore
		}
		return ctx.Err()
	}
	prior, data, err := readPairedPriorArchive(ctx, archive, archiveFS, binding)
	if err != nil || digestBytes(data) != b.ManifestSHA256 || priorArchiveMatchesReceipt(prior, receipt) != nil {
		return ErrPairedOfflineRestore
	}
	source, err := ownedfs.Open(installation)
	if err != nil {
		return err
	}
	defer source.Close()
	fs, err := os.OpenRoot(installation)
	if err != nil {
		return err
	}
	defer fs.Close()
	current, seen, err := scanPairedPriorState(ctx, source, fs, nil, binding, owned, boundary)
	if err != nil {
		return err
	}
	before, after := offlinePriorNodes(current), offlinePriorNodes(prior)
	oldConfig, err := readOfflineBlob(ctx, archiveFS, after["etc/razvilka/config.json"], 4<<20)
	if err != nil {
		return err
	}
	currentConfig, err := source.ReadLimited("etc/razvilka/config.json", 4<<20)
	if err != nil || digestBytes(currentConfig) != before["etc/razvilka/config.json"].sha {
		return ErrPairedOfflineRestore
	}
	merged, err := offlinePriorConfig(oldConfig, currentConfig)
	if err != nil {
		return err
	}
	after["etc/razvilka/config.json"] = offlinePriorNode{mode: 0600, size: int64(len(merged)), sha: digestBytes(merged), data: merged}
	for _, name := range []string{"etc/init.d/S99razvilka", "etc/init.d/S99artem-flow", "etc/init.d/S99artem-flow.razvilka-disabled"} {
		_, old := after[name]
		_, exists := before[name]
		if old || exists {
			guard := []byte(pairedOfflineInitGuard)
			mode := uint32(0755)
			if strings.HasSuffix(name, ".razvilka-disabled") {
				mode = 0600
			}
			after[name] = offlinePriorNode{mode: mode, size: int64(len(guard)), sha: digestBytes(guard), data: guard}
		}
	}
	delete(after, "razvilka/run/razvilka.pid") // A historical PID is not a live owner.
	plan, err := offlineRestorePlan(before, after, seen)
	if err != nil || len(plan) >= 40000 {
		if err == nil {
			err = ErrPairedOfflineRestore
		}
		return err
	}
	defer func() {
		for i := range plan {
			if plan[i].parentFD != nil {
				plan[i].parentFD.Close()
			}
			if plan[i].parent != nil {
				plan[i].parent.Close()
			}
		}
	}()
	for i := range plan {
		if err := boundary("before:offline-stage:" + plan[i].path); err != nil {
			return err
		}
		if err := stageOfflinePriorReplacement(ctx, installation, archiveFS, &plan[i], owned); err != nil {
			return err
		}
	}
	// Corruption/foreign archive replacement detected before any installation
	// effect leaves the current installation untouched (private stages retained).
	fresh, freshData, err := readPairedPriorArchive(ctx, archive, archiveFS, binding)
	if err != nil || !reflect.DeepEqual(prior, fresh) || !bytes.Equal(data, freshData) || boundary("before:offline-effects") != nil {
		return ErrPairedOfflineRestore
	}
	// A later target conflict must be found before the first guard/data write,
	// not only when that target's turn arrives. Every target is checked again
	// immediately before its own bounded publication.
	for i := range plan {
		if err := verifyOfflinePriorTarget(ctx, fs, &plan[i]); err != nil {
			return err
		}
		if err := verifyOfflinePriorStage(ctx, &plan[i]); err != nil {
			return err
		}
	}
	for i := range plan {
		item := &plan[i]
		if err := boundary("before:offline-replace:" + item.path); err != nil {
			return err
		}
		if err := verifyOfflinePriorTarget(ctx, fs, item); err != nil {
			return err
		}
		if err := verifyOfflinePriorStage(ctx, item); err != nil {
			return err
		}
		effect := fmt.Sprintf("paired-offline-file-%d", i)
		if err := commit(ctx, item, func(begin func() error) error {
			return admission(effect, begin)
		}); err != nil {
			return err
		}
		if err := syncOfflineRoot(item.parent); err != nil {
			return err
		}
		if err := boundary("after:offline-replace:" + item.path); err != nil {
			return err
		}
	}
	return boundary("after:offline-restore")
}
