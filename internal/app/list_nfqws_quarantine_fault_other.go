//go:build !linux || !razvilka_native_fixture

package app

import "github.com/ArtixSx/razvilka/internal/dataplane"

func managedNFQQuarantineClosingFault(*dataplane.NFQWSPendingQuarantine) error { return nil }
