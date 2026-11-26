//go:build !linux

package dataplane

import (
	"github.com/ArtixSx/razvilka/internal/ownedfs"
	"os"
)

func executionHistoryOpen(*ownedfs.Root, string) (*os.File, error) { return nil, ErrExecutionJournal }
func executionHistoryOwner(os.FileInfo, bool) bool                 { return false }
func executionHistoryIdentity(os.FileInfo) string                  { return "" }
