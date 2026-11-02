//go:build !linux

package dataplane

import "os"

func domainTCPGlobalRootSame(os.FileInfo, os.FileInfo) bool { return false }

func domainTCPGlobalOriginalInfo(os.FileInfo) bool             { return false }
func domainTCPGlobalInfoSame(os.FileInfo, os.FileInfo) bool    { return false }
func domainTCPGlobalRenamedInfo(os.FileInfo, os.FileInfo) bool { return false }
