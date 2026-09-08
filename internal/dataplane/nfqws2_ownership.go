package dataplane

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/ArtixSx/razvilka/internal/ownedfs"
)

const nfqws2LeaseFile = "ownership.json"

type nfqws2ListLease struct {
	Path         string `json:"path"`
	BlockHash    string `json:"block_hash"`
	PreviousHash string `json:"previous_hash,omitempty"`
}

// The durable intent precedes every global write. Both current and prior block
// hashes allow cleanup after a partial activation, but only for this instance.
type nfqws2Lease struct {
	Version     int                `json:"version"`
	StateRoot   string             `json:"state_root"`
	Owner       string             `json:"owner"`
	Transaction string             `json:"transaction"`
	ConfigPath  string             `json:"config_path"`
	InitPath    string             `json:"init_path"`
	ConfigHash  string             `json:"config_hash"`
	PriorConfig string             `json:"prior_config_hash,omitempty"`
	InitHash    string             `json:"init_hash"`
	Lists       [2]nfqws2ListLease `json:"lists"`
}

func (a *NFQWS2Adapter) bindStateRoot(root string) error {
	path, err := filepath.Abs(filepath.Join(root, "runtime", "nfqws2"))
	if err != nil || root == "" {
		return errors.New("NFQWS2 instance state is unavailable")
	}
	if a.StateRoot != "" && filepath.Clean(a.StateRoot) != path {
		return errors.New("NFQWS2 adapter is already bound to another instance")
	}
	a.StateRoot = path
	return nil
}

func (a *NFQWS2Adapter) owner() (string, error) {
	if !filepath.IsAbs(a.StateRoot) || filepath.Clean(a.StateRoot) != a.StateRoot {
		return "", errors.New("NFQWS2 instance ownership is unavailable")
	}
	digest := sha256.Sum256([]byte(a.StateRoot))
	return hex.EncodeToString(digest[:12]), nil
}

func nfqws2Hash(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func nfqws2Block(data []byte) ([]byte, error) {
	current := string(data)
	if _, _, err := removeManagedBlock(current); err != nil {
		return nil, err
	}
	start, end := strings.Index(current, managedBegin), strings.Index(current, managedEnd)
	if start < 0 {
		return nil, nil
	}
	end += len(managedEnd)
	if start > 0 && current[start-1] != '\n' || end < len(current) && current[end] != '\n' && current[end] != '\r' {
		return nil, errors.New("NFQWS2 ownership marker is not a complete line")
	}
	return []byte(current[start:end]), nil
}

// Read before mutation: reject symlinks, special files and unbounded lists.
func nfqws2Read(path string) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() || info.Size() > 8<<20 {
		return nil, false, errors.New("NFQWS2 resource is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, false, errors.New("NFQWS2 resource changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, (8<<20)+1))
	if err != nil || len(data) > 8<<20 {
		return nil, false, errors.New("NFQWS2 resource read failed or exceeded its bound")
	}
	return data, true, nil
}

func (a *NFQWS2Adapter) readLease() (*nfqws2Lease, error) {
	if a.StateRoot == "" {
		return nil, nil
	}
	root, err := ownedfs.Open(a.StateRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer root.Close()
	data, err := root.ReadLimited(nfqws2LeaseFile, 16<<10)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var lease nfqws2Lease
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&lease); err != nil {
		return nil, errors.New("NFQWS2 ownership manifest is invalid")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("NFQWS2 ownership manifest has trailing data")
	}
	owner, err := a.owner()
	if err != nil || lease.Version != 1 || lease.Owner != owner || lease.StateRoot != a.StateRoot || !filepath.IsAbs(lease.Transaction) ||
		lease.ConfigPath != a.ConfigPath || lease.InitPath != a.InitPath || lease.Lists[0].Path != a.UserListPath || lease.Lists[1].Path != a.IPSetListPath {
		return nil, errors.New("NFQWS2 ownership manifest belongs to another instance or resource")
	}
	for _, list := range lease.Lists {
		for index, value := range []string{list.BlockHash, list.PreviousHash} {
			decoded, err := hex.DecodeString(value)
			if index == 1 && value == "" {
				continue
			}
			if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != value {
				return nil, errors.New("NFQWS2 ownership hash is invalid")
			}
		}
	}
	for index, value := range []string{lease.ConfigHash, lease.InitHash, lease.PriorConfig} {
		decoded, err := hex.DecodeString(value)
		if index == 2 && value == "" {
			continue
		}
		if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != value {
			return nil, errors.New("NFQWS2 runtime hash is invalid")
		}
	}
	return &lease, nil
}

func (a *NFQWS2Adapter) writeLease(lease *nfqws2Lease) error {
	if _, err := a.owner(); err != nil {
		return err
	}
	if err := os.MkdirAll(a.StateRoot, 0o700); err != nil {
		return err
	}
	root, err := ownedfs.Open(a.StateRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	if lease == nil {
		err = root.Remove(nfqws2LeaseFile)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	data, err := json.Marshal(lease)
	if err != nil {
		return err
	}
	return root.WriteAtomic(nfqws2LeaseFile, data, 0o600)
}

func (a *NFQWS2Adapter) checkListOwnership(lease *nfqws2Lease, index int, data []byte, partial bool) error {
	block, err := nfqws2Block(data)
	if err != nil || len(block) == 0 && !partial {
		return errors.New("NFQWS2 managed block is missing or malformed")
	}
	if len(block) == 0 {
		return nil
	}
	owner, err := a.owner()
	if err != nil || lease == nil || !strings.Contains(string(block), "\n# RAZVILKA INSTANCE "+owner+"\n") {
		return errors.New("NFQWS2 managed block is not owned by this instance")
	}
	hash := nfqws2Hash(block)
	if hash != lease.Lists[index].BlockHash && (!partial || hash != lease.Lists[index].PreviousHash) {
		return errors.New("NFQWS2 managed block changed outside its ownership manifest")
	}
	return nil
}

func (a *NFQWS2Adapter) verifyOwnedLists(partial bool) (*nfqws2Lease, error) {
	lease, err := a.readLease()
	if err != nil {
		return nil, err
	}
	if lease != nil {
		if err := a.verifyOwnedRuntime(lease, partial); err != nil {
			return nil, err
		}
	}
	for index, path := range []string{a.UserListPath, a.IPSetListPath} {
		data, _, err := nfqws2Read(path)
		if err != nil {
			return nil, err
		}
		if err := a.checkListOwnership(lease, index, data, partial); err != nil {
			return nil, err
		}
	}
	if !partial && lease == nil {
		return nil, errors.New("NFQWS2 runtime ownership is unavailable")
	}
	return lease, nil
}

func (a *NFQWS2Adapter) verifyOwnedRuntime(lease *nfqws2Lease, partial bool) error {
	config, _, err := nfqws2Read(a.ConfigPath)
	if err != nil {
		return err
	}
	hash := nfqws2Hash(config)
	if hash != lease.ConfigHash && (!partial || hash != lease.PriorConfig) {
		return errors.New("NFQWS2 configuration changed outside its ownership manifest")
	}
	init, _, err := nfqws2Read(a.InitPath)
	if err != nil || nfqws2Hash(init) != lease.InitHash {
		return errors.New("NFQWS2 init changed outside its ownership manifest")
	}
	return nil
}

func (a *NFQWS2Adapter) stageOwnedList(index int, stage string, values []string) error {
	owner, err := a.owner()
	if err != nil {
		return err
	}
	paths := []string{a.UserListPath, a.IPSetListPath}
	current, _, err := nfqws2Read(paths[index])
	if err != nil {
		return err
	}
	lease, err := a.readLease()
	if err != nil {
		return err
	}
	if err := a.checkListOwnership(lease, index, current, true); err != nil {
		return err
	}
	merged, err := replaceManagedBlock(string(current), append([]string{"# RAZVILKA INSTANCE " + owner}, values...))
	if err != nil {
		return err
	}
	return writeAtomic(stage, []byte(merged), 0o600)
}

func (a *NFQWS2Adapter) prepareActivationLease(root string) error {
	snapshot, err := readNFQWS2Snapshot(root)
	if err != nil {
		return err
	}
	prior, err := a.readLease()
	if err != nil || !reflect.DeepEqual(prior, snapshot.Lease) {
		return errors.New("NFQWS2 instance lease changed after its snapshot")
	}
	owner, err := a.owner()
	if err != nil {
		return err
	}
	transaction, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	lease := &nfqws2Lease{Version: 1, StateRoot: a.StateRoot, Owner: owner, Transaction: transaction, ConfigPath: a.ConfigPath, InitPath: a.InitPath}
	stagedConfig, exists, err := nfqws2Read(filepath.Join(root, "nfqws2.conf.staged"))
	if err != nil || !exists || len(stagedConfig) == 0 {
		return errors.New("NFQWS2 staged configuration is unavailable")
	}
	init, exists, err := nfqws2Read(a.InitPath)
	if err != nil || !exists || len(init) == 0 {
		return errors.New("NFQWS2 init is unavailable")
	}
	lease.ConfigHash, lease.PriorConfig, lease.InitHash = nfqws2Hash(stagedConfig), nfqws2Hash(snapshot.Config), nfqws2Hash(init)
	before := [][]byte{snapshot.Config, snapshot.UserList, snapshot.IPSetList}
	existed := []bool{snapshot.ConfigExisted, snapshot.UserListExisted, snapshot.IPSetListExisted}
	for index, path := range []string{a.ConfigPath, a.UserListPath, a.IPSetListPath} {
		current, exists, err := nfqws2Read(path)
		if err != nil || exists != existed[index] || !bytes.Equal(current, before[index]) {
			return errors.New("NFQWS2 global resource changed after its snapshot")
		}
		if index == 0 {
			continue
		}
		if err := a.checkListOwnership(prior, index-1, current, true); err != nil {
			return err
		}
		stageName := []string{"user.list.staged", "ipset.list.staged"}[index-1]
		staged, exists, err := nfqws2Read(filepath.Join(root, stageName))
		block, blockErr := nfqws2Block(staged)
		if err != nil || !exists || blockErr != nil || !strings.Contains(string(block), "\n# RAZVILKA INSTANCE "+owner+"\n") {
			return errors.New("NFQWS2 staged ownership is invalid")
		}
		previous, _ := nfqws2Block(current)
		lease.Lists[index-1] = nfqws2ListLease{Path: path, BlockHash: nfqws2Hash(block), PreviousHash: nfqws2Hash(previous)}
	}
	if err := a.writeLease(lease); err != nil {
		return fmt.Errorf("persist NFQWS2 ownership intent: %w", err)
	}
	return nil
}

func (a *NFQWS2Adapter) mayRollback(root string, snapshot nfqws2Snapshot) (bool, error) {
	lease, err := a.readLease()
	if err != nil {
		return false, err
	}
	transaction, err := filepath.Abs(root)
	if err != nil || lease == nil || lease.Transaction != transaction {
		return false, err // This prepared adapter never reached a live write.
	}
	if err := a.verifyOwnedRuntime(lease, true); err != nil {
		return false, err
	}
	before := [][]byte{snapshot.Config, snapshot.UserList, snapshot.IPSetList}
	existed := []bool{snapshot.ConfigExisted, snapshot.UserListExisted, snapshot.IPSetListExisted}
	for index, path := range []string{a.ConfigPath, a.UserListPath, a.IPSetListPath} {
		current, exists, err := nfqws2Read(path)
		if err != nil {
			return false, err
		}
		stageName := []string{"nfqws2.conf.staged", "user.list.staged", "ipset.list.staged"}[index]
		staged, _, err := nfqws2Read(filepath.Join(root, stageName))
		if err != nil || !(exists == existed[index] && bytes.Equal(current, before[index])) && !(exists && bytes.Equal(current, staged)) {
			return false, errors.New("NFQWS2 rollback resource is no longer owned")
		}
	}
	return true, nil
}
