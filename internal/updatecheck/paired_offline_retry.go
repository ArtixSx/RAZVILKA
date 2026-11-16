package updatecheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"github.com/ArtixSx/razvilka/internal/selfupdatejournal"
)

// This bounded descriptor is immutable after binding to receipt5. It contains
// hashes/metadata, not private payloads. Original and replacement inode
// identities distinguish a known rename from a same-content foreign object.
type offlineRetryIdentity struct {
	Device   uint64 `json:"device"`
	Inode    uint64 `json:"inode"`
	Mode     uint32 `json:"mode"`
	Size     int64  `json:"size"`
	Modified int64  `json:"modified_ns"`
}
type offlineRetryNode struct {
	Path      string               `json:"path"`
	Directory bool                 `json:"directory"`
	Mode      uint32               `json:"mode"`
	Size      int64                `json:"size"`
	SHA256    string               `json:"sha256,omitempty"`
	Identity  offlineRetryIdentity `json:"identity"`
}
type offlineRetryItem struct {
	Path   string               `json:"path"`
	Stage  string               `json:"stage"`
	Parent offlineRetryIdentity `json:"parent"`
	Before []offlineRetryNode   `json:"before"`
	After  []offlineRetryNode   `json:"after"`
}
type offlineRetryPlan struct {
	Schema        int                `json:"schema"`
	ReceiptSHA256 string             `json:"receipt_sha256"`
	Items         []offlineRetryItem `json:"items"`
	Unchanged     []offlineRetryNode `json:"unchanged"`
}

func encodeOfflinePriorPlan(ctx context.Context, receipt selfupdatejournal.Receipt, plan []offlinePriorReplacement, before map[string]offlinePriorNode, seen []priorStateObservation) ([]byte, error) {
	encoded, _ := json.Marshal(receipt)
	doc := offlineRetryPlan{Schema: 1, ReceiptSHA256: digestBytes(encoded)}
	for i := range plan {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		item := &plan[i]
		parent, err := offlinePersistentIdentity(item.parentInfo)
		if err != nil {
			return nil, err
		}
		out := offlineRetryItem{Path: item.path, Stage: item.stage, Parent: parent}
		beforeInfo := map[string]os.FileInfo{}
		for _, observed := range item.seen {
			beforeInfo[filepath.ToSlash(observed.path)] = observed.info
		}
		for phase, nodes := range []map[string]offlinePriorNode{item.before, item.after} {
			var paths []string
			for path := range nodes {
				paths = append(paths, path)
			}
			sort.Strings(paths)
			for _, path := range paths {
				node := nodes[path]
				info := beforeInfo[path]
				if phase == 1 {
					info, err = item.parent.Lstat(offlineRetryName(item.path, item.stage, path))
					if err != nil {
						return nil, err
					}
				}
				identity, err := offlinePersistentIdentity(info)
				if err != nil {
					return nil, err
				}
				row := offlineRetryNode{path, node.directory, node.mode, node.size, node.sha, identity}
				if phase == 0 {
					out.Before = append(out.Before, row)
				} else {
					out.After = append(out.After, row)
				}
			}
		}
		doc.Items = append(doc.Items, out)
	}
	for _, observation := range seen {
		path := filepath.ToSlash(observation.path)
		if observation.info == nil || offlineProtected(path) {
			continue
		}
		changed := false
		for _, item := range plan {
			if path == item.path || strings.HasPrefix(path, item.path+"/") {
				changed = true
				break
			}
		}
		if changed {
			continue
		}
		node, exists := before[path]
		if !exists {
			return nil, ErrPairedOfflineRestore
		}
		identity, err := offlinePersistentIdentity(observation.info)
		if err != nil {
			return nil, err
		}
		doc.Unchanged = append(doc.Unchanged, offlineRetryNode{path, node.directory, node.mode, node.size, node.sha, identity})
	}
	sort.Slice(doc.Unchanged, func(i, j int) bool { return doc.Unchanged[i].Path < doc.Unchanged[j].Path })
	data, err := json.Marshal(doc)
	if err != nil || len(data) > selfupdatejournal.MaximumOfflinePlanBytes {
		return nil, ErrPairedOfflineRestore
	}
	return data, nil
}

func offlineRetryName(target, root, path string) string {
	if path == target {
		return root
	}
	return filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(path, target+"/")))
}

func decodeOfflinePriorPlan(receipt selfupdatejournal.Receipt, data []byte) (offlineRetryPlan, error) {
	var doc offlineRetryPlan
	encoded, _ := json.Marshal(receipt)
	if len(data) == 0 || len(data) > selfupdatejournal.MaximumOfflinePlanBytes || decodeFileProtocol(data, &doc) != nil || doc.Schema != 1 || doc.ReceiptSHA256 != digestBytes(encoded) || len(doc.Items) == 0 || len(doc.Items) >= 40000 {
		return doc, ErrPairedOfflineRestore
	}
	canonical, _ := json.Marshal(doc)
	if !bytes.Equal(data, canonical) {
		return doc, ErrPairedOfflineRestore
	}
	names, stages := map[string]bool{}, map[string]bool{}
	// Reconstruct the same fixed-root traversal order, including guarded init
	// first and binary last. Arbitrary destinations/overlapping targets cannot
	// acquire authority just because a manifest is canonical JSON.
	before, after := map[string]offlinePriorNode{}, map[string]offlinePriorNode{}
	for _, spec := range pairedPriorRoots {
		if offlineAnchor(spec.path) {
			before[spec.path] = offlinePriorNode{directory: true, mode: 0700}
			after[spec.path] = before[spec.path]
		}
	}
	total := 0
	for _, item := range doc.Items {
		if item.Path == "" || filepath.ToSlash(filepath.Clean(filepath.FromSlash(item.Path))) != item.Path || !filepath.IsLocal(filepath.FromSlash(item.Path)) || strings.Contains(item.Path, "\\") || offlineProtected(item.Path) || offlineAnchor(item.Path) || names[item.Path] || !strings.HasPrefix(item.Stage, pairedOfflineStagePrefix) || !jobIDPattern.MatchString(strings.TrimPrefix(item.Stage, pairedOfflineStagePrefix)) || item.Parent.Inode == 0 {
			return doc, ErrPairedOfflineRestore
		}
		if _, _, ok := pairedPriorRootFor(item.Path); !ok {
			return doc, ErrPairedOfflineRestore
		}
		for parent := filepath.ToSlash(filepath.Dir(filepath.FromSlash(item.Path))); parent != "."; parent = filepath.ToSlash(filepath.Dir(filepath.FromSlash(parent))) {
			if offlineAnchor(parent) {
				before[parent] = offlinePriorNode{directory: true, mode: 0700}
				after[parent] = before[parent]
			}
		}
		stage := filepath.ToSlash(filepath.Join(filepath.Dir(filepath.FromSlash(item.Path)), item.Stage))
		if stages[stage] {
			return doc, ErrPairedOfflineRestore
		}
		stages[stage] = true
		names[item.Path] = true
		for phase, rows := range [][]offlineRetryNode{item.Before, item.After} {
			if len(rows) > 4097 {
				return doc, ErrPairedOfflineRestore
			}
			previous := ""
			for j, row := range rows {
				total++
				for _, part := range strings.Split(row.Path, "/") {
					if strings.HasPrefix(part, pairedOfflineStagePrefix) {
						return doc, ErrPairedOfflineRestore
					}
				}
				if total > 80000 || (j == 0 && row.Path != item.Path) || row.Path <= previous || (row.Path != item.Path && !strings.HasPrefix(row.Path, item.Path+"/")) || filepath.ToSlash(filepath.Clean(filepath.FromSlash(row.Path))) != row.Path || strings.Contains(row.Path, "\\") || offlineProtected(row.Path) || offlineAnchor(row.Path) || row.Mode > 0777 || row.Mode&0022 != 0 || row.Identity.Inode == 0 || row.Size < 0 || row.Size > maximumPairedArchiveFileBytes {
					return doc, ErrPairedOfflineRestore
				}
				if row.Directory && (row.Size != 0 || row.SHA256 != "") || !row.Directory && !validDigest("sha256:"+row.SHA256) {
					return doc, ErrPairedOfflineRestore
				}
				previous = row.Path
				node := offlinePriorNode{directory: row.Directory, mode: row.Mode, size: row.Size, sha: row.SHA256}
				if phase == 0 {
					before[row.Path] = node
				} else {
					after[row.Path] = node
				}
			}
		}
	}
	expected, err := offlineRestorePlan(before, after, nil)
	if err != nil || len(expected) != len(doc.Items) {
		return doc, ErrPairedOfflineRestore
	}
	for i := range expected {
		if expected[i].path != doc.Items[i].Path {
			return doc, ErrPairedOfflineRestore
		}
	}
	previous := ""
	if len(doc.Unchanged) > 40000 {
		return doc, ErrPairedOfflineRestore
	}
	for _, row := range doc.Unchanged {
		for _, part := range strings.Split(row.Path, "/") {
			if strings.HasPrefix(part, pairedOfflineStagePrefix) {
				return doc, ErrPairedOfflineRestore
			}
		}
		if row.Path <= previous || !filepath.IsLocal(filepath.FromSlash(row.Path)) || filepath.ToSlash(filepath.Clean(filepath.FromSlash(row.Path))) != row.Path || strings.Contains(row.Path, "\\") || offlineProtected(row.Path) || row.Identity.Inode == 0 || row.Mode > 0777 || row.Mode&0022 != 0 || row.Size < 0 || row.Size > maximumPairedArchiveFileBytes {
			return doc, ErrPairedOfflineRestore
		}
		if _, _, covered := pairedPriorRootFor(row.Path); !covered {
			return doc, ErrPairedOfflineRestore
		}
		if row.Directory && (row.Size != 0 || row.SHA256 != "") || !row.Directory && !validDigest("sha256:"+row.SHA256) {
			return doc, ErrPairedOfflineRestore
		}
		for _, item := range doc.Items {
			if row.Path == item.Path || strings.HasPrefix(row.Path, item.Path+"/") {
				return doc, ErrPairedOfflineRestore
			}
		}
		previous = row.Path
	}
	return doc, nil
}

// A complete managed inventory covers unchanged files as well as replacements.
// Only explicitly protected monotonic journals and the bound private stages
// are omitted. New ordinary children cannot hide under an unchanged anchor.
func verifyOfflineRetryInventory(ctx context.Context, fs *os.Root, doc offlineRetryPlan, completed int) error {
	expected := map[string]offlineRetryNode{}
	for _, row := range doc.Unchanged {
		expected[row.Path] = row
	}
	stages := map[string]bool{}
	for i, item := range doc.Items {
		rows := item.Before
		if i < completed {
			rows = item.After
		}
		for _, row := range rows {
			if _, duplicate := expected[row.Path]; duplicate {
				return ErrPairedOfflineRestore
			}
			expected[row.Path] = row
		}
		stages[filepath.ToSlash(filepath.Join(filepath.Dir(filepath.FromSlash(item.Path)), item.Stage))] = true
	}
	found := map[string]bool{}
	count := 0
	var walk func(string) error
	walk = func(path string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if offlineProtected(path) || stages[path] {
			return nil
		}
		info, err := fs.Lstat(filepath.FromSlash(path))
		row, exists := expected[path]
		if errors.Is(err, os.ErrNotExist) && !exists {
			return nil
		}
		if err != nil || !exists || !safePriorSourceInfo(info) || info.IsDir() != row.Directory || uint32(info.Mode().Perm()) != row.Mode {
			return ErrPairedOfflineRestore
		}
		identity, err := offlinePersistentIdentity(info)
		if err != nil {
			return err
		}
		if offlineAnchor(path) {
			if identity.Device != row.Identity.Device || identity.Inode != row.Identity.Inode || identity.Mode != row.Identity.Mode {
				return ErrPairedOfflineRestore
			}
		} else if identity != row.Identity {
			return ErrPairedOfflineRestore
		}
		found[path] = true
		count++
		if count > 80000 {
			return ErrPairedOfflineRestore
		}
		if info.IsDir() {
			file, err := fs.Open(filepath.FromSlash(path))
			if err != nil {
				return err
			}
			entries, readErr := file.ReadDir(4097)
			file.Close()
			if readErr != nil && readErr != io.EOF || len(entries) > 4096 {
				return ErrPairedOfflineRestore
			}
			for _, entry := range entries {
				if err := walk(path + "/" + entry.Name()); err != nil {
					return err
				}
			}
		} else {
			n, hash, err := copyPriorArchiveFile(ctx, fs, filepath.FromSlash(path), info, nil, "")
			if err != nil || n != row.Size || hash != row.SHA256 {
				return ErrPairedOfflineRestore
			}
		}
		return ctx.Err()
	}
	for _, spec := range pairedPriorRoots {
		if err := walk(spec.path); err != nil {
			return err
		}
	}
	if len(found) != len(expected) {
		return ErrPairedOfflineRestore
	}
	return ctx.Err()
}

func offlineRetryRows(ctx context.Context, parent *os.Root, target, root string, rows []offlineRetryNode) ([]priorStateObservation, error) {
	if len(rows) == 0 {
		if _, err := parent.Lstat(root); !errors.Is(err, os.ErrNotExist) {
			return nil, ErrPairedOfflineRestore
		}
		return nil, ctx.Err()
	}
	var seen []priorStateObservation
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name := offlineRetryName(target, root, row.Path)
		info, err := parent.Lstat(name)
		if err != nil || !safePriorSourceInfo(info) || info.IsDir() != row.Directory || uint32(info.Mode().Perm()) != row.Mode {
			return nil, ErrPairedOfflineRestore
		}
		identity, err := offlinePersistentIdentity(info)
		if err != nil || identity != row.Identity {
			return nil, ErrPairedOfflineRestore
		}
		if row.Directory {
			dir, err := parent.Open(name)
			if err != nil {
				return nil, err
			}
			entries, readErr := dir.ReadDir(4097)
			dir.Close()
			if readErr != nil && readErr != io.EOF || len(entries) > 4096 {
				return nil, ErrPairedOfflineRestore
			}
			children := map[string]bool{}
			for _, child := range rows {
				if filepath.ToSlash(filepath.Dir(filepath.FromSlash(child.Path))) == row.Path {
					children[filepath.Base(filepath.FromSlash(child.Path))] = true
				}
			}
			if len(entries) != len(children) {
				return nil, ErrPairedOfflineRestore
			}
			for _, entry := range entries {
				if !children[entry.Name()] {
					return nil, ErrPairedOfflineRestore
				}
			}
		} else {
			n, hash, err := copyPriorArchiveFile(ctx, parent, name, info, nil, "")
			if err != nil || n != row.Size || hash != row.SHA256 {
				return nil, ErrPairedOfflineRestore
			}
		}
		seen = append(seen, priorStateObservation{filepath.FromSlash(row.Path), info})
	}
	return seen, ctx.Err()
}

func offlineRetryParent(installation string, item offlineRetryItem, owned func(string) error) (*os.Root, *os.File, error) {
	path := filepath.Dir(filepath.Join(installation, filepath.FromSlash(item.Path)))
	if owned(path) != nil {
		return nil, nil, ErrPairedOfflineRestore
	}
	parent, err := os.OpenRoot(path)
	if err != nil {
		return nil, nil, err
	}
	fail := func() (*os.Root, *os.File, error) { parent.Close(); return nil, nil, ErrPairedOfflineRestore }
	info, err := parent.Stat(".")
	if err != nil || !safePriorSourceInfo(info) {
		return fail()
	}
	identity, err := offlinePersistentIdentity(info)
	if err != nil || identity.Device != item.Parent.Device || identity.Inode != item.Parent.Inode || identity.Mode != item.Parent.Mode {
		return fail()
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, current) {
		return fail()
	}
	fd, err := parent.Open(".")
	if err != nil {
		return fail()
	}
	return parent, fd, nil
}

func offlineRetryLayout(ctx context.Context, parent *os.Root, item offlineRetryItem) (bool, []priorStateObservation, error) {
	name := filepath.Base(filepath.FromSlash(item.Path))
	before, preErr := offlineRetryRows(ctx, parent, item.Path, name, item.Before)
	_, stagePreErr := offlineRetryRows(ctx, parent, item.Path, item.Stage, item.After)
	_, postErr := offlineRetryRows(ctx, parent, item.Path, name, item.After)
	_, stagePostErr := offlineRetryRows(ctx, parent, item.Path, item.Stage, item.Before)
	pre, post := preErr == nil && stagePreErr == nil, postErr == nil && stagePostErr == nil
	if pre == post {
		return false, nil, ErrPairedOfflineRestore
	}
	return post, before, ctx.Err()
}

// Reject every unbound stage, including siblings of fixed file roots that are
// not recursively scanned by the archive copier. Never infer or delete it.
func offlineRetryNoForeignStages(ctx context.Context, fs *os.Root, doc offlineRetryPlan) error {
	allowed := map[string]bool{}
	for _, item := range doc.Items {
		allowed[filepath.ToSlash(filepath.Join(filepath.Dir(filepath.FromSlash(item.Path)), item.Stage))] = true
	}
	count := 0
	var walk func(string, bool) error
	walk = func(path string, recurse bool) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		file, err := fs.Open(filepath.FromSlash(path))
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		entries, readErr := file.ReadDir(4097)
		file.Close()
		if readErr != nil && readErr != io.EOF || len(entries) > 4096 {
			return ErrPairedOfflineRestore
		}
		for _, entry := range entries {
			count++
			if count > 100000 {
				return ErrPairedOfflineRestore
			}
			name := path + "/" + entry.Name()
			if strings.HasPrefix(entry.Name(), pairedOfflineStagePrefix) {
				if !allowed[name] {
					return ErrPairedOfflineOrphan
				}
				continue
			}
			if recurse && entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
				if err := walk(name, true); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, path := range []string{"bin", "etc/init.d", "razvilka", "razvilka/run"} {
		if err := walk(path, false); err != nil {
			return err
		}
	}
	for _, spec := range pairedPriorRoots {
		if spec.directory {
			if err := walk(spec.path, true); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

func offlinePriorPlanPosition(ctx context.Context, installation string, fs *os.Root, doc offlineRetryPlan, owned func(string) error) (int, error) {
	if err := offlineRetryNoForeignStages(ctx, fs, doc); err != nil {
		return 0, err
	}
	completed := 0
	sawPre := false
	for _, item := range doc.Items {
		parent, fd, err := offlineRetryParent(installation, item, owned)
		if err != nil {
			return 0, err
		}
		post, _, err := offlineRetryLayout(ctx, parent, item)
		fd.Close()
		parent.Close()
		if err != nil {
			return 0, err
		}
		if post {
			if sawPre {
				return 0, ErrPairedOfflineRestore
			}
			completed++
		} else {
			sawPre = true
		}
	}
	if err := verifyOfflineRetryInventory(ctx, fs, doc, completed); err != nil {
		return 0, err
	}
	return completed, ctx.Err()
}

func offlineRetryNodes(rows []offlineRetryNode) map[string]offlinePriorNode {
	nodes := map[string]offlinePriorNode{}
	for _, row := range rows {
		nodes[row.Path] = offlinePriorNode{directory: row.Directory, mode: row.Mode, size: row.Size, sha: row.SHA256}
	}
	return nodes
}

// A plan-only cut has no receipt5 authority. Re-derive every replacement from
// the immutable source archive and the verified CURRENT pre-config; never
// promote a descriptor's self-asserted destination/hash into installation
// authority. The prepared callback repeats this immediately before fencing5.
func verifyOfflinePriorUnbound(ctx context.Context, installation string, source *ownedfs.Root, fs, archive *os.Root, prior pairedPriorArchive, doc offlineRetryPlan, owned func(string) error) error {
	completed, err := offlinePriorPlanPosition(ctx, installation, fs, doc, owned)
	if err != nil || completed != 0 {
		return ErrPairedOfflineRestore
	}
	before := offlineRetryNodes(doc.Unchanged)
	for _, item := range doc.Items {
		for name, node := range offlineRetryNodes(item.Before) {
			before[name] = node
		}
	}
	after := offlinePriorNodes(prior)
	priorConfig, err := readOfflineBlob(ctx, archive, after["etc/razvilka/config.json"], 4<<20)
	if err != nil {
		return err
	}
	currentConfig, err := source.ReadLimited("etc/razvilka/config.json", 4<<20)
	if err != nil || digestBytes(currentConfig) != before["etc/razvilka/config.json"].sha {
		return ErrPairedOfflineRestore
	}
	merged, err := offlinePriorConfig(priorConfig, currentConfig)
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
	delete(after, "razvilka/run/razvilka.pid")
	expected, err := offlineRestorePlan(before, after, nil)
	if err != nil || len(expected) != len(doc.Items) {
		return ErrPairedOfflineRestore
	}
	for i, item := range doc.Items {
		if expected[i].path != item.Path || !reflect.DeepEqual(offlineSubtree(expected[i].before, item.Path), offlineRetryNodes(item.Before)) || !reflect.DeepEqual(offlineSubtree(expected[i].after, item.Path), offlineRetryNodes(item.After)) {
			return ErrPairedOfflineRestore
		}
	}
	return ctx.Err()
}

func resumeOfflinePriorPlan(ctx context.Context, installation string, fs *os.Root, receipt selfupdatejournal.Receipt, data []byte, owned func(string) error, boundary func(string) error, admission func(string, func() error) error, commit offlinePriorCommit, verifyOnly bool) error {
	doc, err := decodeOfflinePriorPlan(receipt, data)
	if err != nil {
		return err
	}
	if err := offlineRetryNoForeignStages(ctx, fs, doc); err != nil {
		return err
	}
	plans := make([]offlinePriorReplacement, len(doc.Items))
	defer func() {
		for i := range plans {
			if plans[i].parentFD != nil {
				plans[i].parentFD.Close()
			}
			if plans[i].parent != nil {
				plans[i].parent.Close()
			}
		}
	}()
	completed := 0
	sawPre := false
	for i, item := range doc.Items {
		if err := boundary("before:offline-retry-verify:" + item.Path); err != nil {
			return err
		}
		parent, fd, err := offlineRetryParent(installation, item, owned)
		if err != nil {
			return err
		}
		plans[i].parent, plans[i].parentFD = parent, fd
		post, _, err := offlineRetryLayout(ctx, parent, item)
		if err != nil {
			return err
		}
		if post {
			if sawPre {
				return ErrPairedOfflineRestore
			}
			completed++
		} else {
			sawPre = true
		}
	}
	if verifyOnly && completed != len(doc.Items) {
		return ErrPairedOfflineRestore
	}
	if err := verifyOfflineRetryInventory(ctx, fs, doc, completed); err != nil {
		return err
	}
	for i := completed; i < len(doc.Items); i++ {
		item := doc.Items[i]
		plan := &plans[i]
		if err := boundary("before:offline-replace:" + item.Path); err != nil {
			return err
		}
		post, seen, err := offlineRetryLayout(ctx, plan.parent, item)
		if err != nil || post {
			return ErrPairedOfflineRestore
		}
		plan.path, plan.stage, plan.seen = item.Path, item.Stage, seen
		plan.before, plan.after = map[string]offlinePriorNode{}, map[string]offlinePriorNode{}
		for _, row := range item.Before {
			plan.before[row.Path] = offlinePriorNode{directory: row.Directory, mode: row.Mode, size: row.Size, sha: row.SHA256}
		}
		for _, row := range item.After {
			plan.after[row.Path] = offlinePriorNode{directory: row.Directory, mode: row.Mode, size: row.Size, sha: row.SHA256}
		}
		plan.parentInfo, err = plan.parent.Stat(".")
		if err != nil {
			return err
		}
		if len(item.After) > 0 {
			plan.staged, err = plan.parent.Lstat(item.Stage)
			if err != nil {
				return err
			}
		}
		if err := commit(ctx, plan, func(begin func() error) error { return admission(fmt.Sprintf("paired-offline-file-%d", i), begin) }); err != nil {
			return err
		}
		if err := syncOfflineRoot(plan.parent); err != nil {
			return err
		}
		if err := boundary("after:offline-replace:" + item.Path); err != nil {
			return err
		}
	}
	// No metadata terminalizes a partial restore: re-read every post-image,
	// displaced original, pinned parent, archive/owner, and foreign-stage fence.
	for i, item := range doc.Items {
		if err := boundary("after:offline-verify:" + item.Path); err != nil {
			return err
		}
		parent, fd, err := offlineRetryParent(installation, item, owned)
		if err != nil {
			return err
		}
		fd.Close()
		parent.Close()
		post, _, err := offlineRetryLayout(ctx, plans[i].parent, item)
		if err != nil || !post {
			return ErrPairedOfflineRestore
		}
	}
	if err := offlineRetryNoForeignStages(ctx, fs, doc); err != nil {
		return err
	}
	if err := verifyOfflineRetryInventory(ctx, fs, doc, len(doc.Items)); err != nil {
		return err
	}
	return boundary("after:offline-restore")
}
