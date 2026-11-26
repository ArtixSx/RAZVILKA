package dataplane

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type wgEmptyTableNameFile struct {
	info os.FileInfo
	hash [32]byte
}

// iproute2 v4.4 rtnl_rttable_a2n checks configured names BEFORE strtoul:
// an entry "207 206" redirects even a decimal "table 206" query. Capture
// every possible table-name source and refuse that name, then compare the
// same files/directories (including absence) after the original command.
// This validates query selection only; it grants no route ownership.
func wgEmptyTableNames(ctx context.Context, table int) (map[string]wgEmptyTableNameFile, error) {
	image := map[string]wgEmptyTableNameFile{}
	rememberDirectory := func(path string) (bool, error) {
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			image[path] = wgEmptyTableNameFile{}
			return false, nil
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false, errWGInactiveUnknown
		}
		image[path] = wgEmptyTableNameFile{info: info}
		return true, nil
	}
	paths := []string{}
	for _, root := range rtTablesSources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, err := rememberDirectory(root); err != nil {
			return nil, err
		}
		paths = append(paths, filepath.Join(root, "rt_tables"))
		directory := filepath.Join(root, "rt_tables.d")
		present, err := rememberDirectory(directory)
		if err != nil {
			return nil, err
		}
		if !present {
			continue
		}
		entries, err := os.ReadDir(directory)
		if err != nil || len(entries) > 128 {
			return nil, errWGInactiveUnknown
		}
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), ".") && len(entry.Name()) > 5 && strings.HasSuffix(entry.Name(), ".conf") {
				paths = append(paths, filepath.Join(directory, entry.Name()))
			}
		}
	}
	if len(paths) > 128 {
		return nil, errWGInactiveUnknown
	}
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			image[path] = wgEmptyTableNameFile{}
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
			return nil, errWGInactiveUnknown
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, errWGInactiveUnknown
		}
		opened, statErr := file.Stat()
		data, readErr := io.ReadAll(io.LimitReader(file, (64<<10)+1))
		closeErr := file.Close()
		current, currentErr := os.Lstat(path)
		if statErr != nil || readErr != nil || closeErr != nil || currentErr != nil || len(data) > 64<<10 || !os.SameFile(info, opened) || !os.SameFile(info, current) {
			return nil, errWGInactiveUnknown
		}
		for _, line := range strings.Split(string(data), "\n") {
			line, _, _ = strings.Cut(line, "#")
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			if len(fields) != 2 || fields[1] == strconv.Itoa(table) {
				return nil, errWGInactiveUnknown
			}
			if _, err := strconv.ParseUint(fields[0], 0, 32); err != nil {
				return nil, errWGInactiveUnknown
			}
		}
		image[path] = wgEmptyTableNameFile{info: info, hash: sha256.Sum256(data)}
	}
	return image, ctx.Err()
}

func wgEmptyTableNamesCurrent(ctx context.Context, table int, before map[string]wgEmptyTableNameFile) error {
	after, err := wgEmptyTableNames(ctx, table)
	if err != nil || len(before) != len(after) {
		return errors.Join(err, errWGInactiveUnknown)
	}
	for path, prior := range before {
		next, found := after[path]
		if !found || prior.hash != next.hash || (prior.info == nil) != (next.info == nil) || prior.info != nil && !os.SameFile(prior.info, next.info) {
			return errWGInactiveUnknown
		}
	}
	return ctx.Err()
}
