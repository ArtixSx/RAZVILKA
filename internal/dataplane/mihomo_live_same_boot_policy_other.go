//go:build !linux

package dataplane

import "os"

func mihomoSameBootStaticPath(*os.Root, string) error { return ErrMihomoLiveRetirement }

func sameBootPolicyRecordIdentity(*mihomoColdRecord) error { return ErrPolicyAdditionUnknown }
