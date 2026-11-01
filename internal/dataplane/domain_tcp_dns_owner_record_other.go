//go:build !linux

package dataplane

import "os"

func domainTCPDNSOwnerRenameNoReplace(*os.File, string, string) error {
	return ErrDomainPolicyTCPConsumer
}

func domainTCPDNSOwnerPrivateFile(info os.FileInfo) bool {
	return info != nil && validCloudflareScanLockFile(info)
}
func domainTCPDNSOwnerDirectory(info os.FileInfo) bool { return networkPolicyPrivateDirectory(info) }
