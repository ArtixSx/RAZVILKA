//go:build linux && razvilka_native_fixture

package app

import (
	"context"
	"github.com/ArtixSx/razvilka/internal/dataplane"
	"os"
	"sync"
)

// Isolated native fixture only. This one-shot error is AFTER real source
// descriptor Close, never a fabricated terminal resource/publication grant.
var managedNFQQuarantineCloseCuts sync.Map

func managedNFQQuarantineClosingFault(q *dataplane.NFQWSPendingQuarantine) error {
	if q == nil || os.Getenv("RAZVILKA_NFQWS_QUARANTINE_CLOSE_RETRY") != "1" || os.Getenv("RAZVILKA_NFQWS_NEVER_ISSUED_NATIVE") != "settlement-sync" {
		return nil
	}
	if _, used := managedNFQQuarantineCloseCuts.LoadOrStore(q, struct{}{}); used {
		return nil
	}
	return context.DeadlineExceeded
}
