package app

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// This is a finite communication window for already validated long callers.
// It changes no operation or native expiry, and does not change the server's
// normal header/body/idle deadlines or ordinary response policy.
const managedNFQResponseGrace = time.Minute // default 45s rollback plus bounded reply margin

func managedNFQResponseDeadline(w http.ResponseWriter, ctx context.Context) error {
	if ctx == nil {
		return errors.New("finite managed response context required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, bounded := ctx.Deadline()
	if !bounded {
		return errors.New("finite managed response deadline required")
	}
	return http.NewResponseController(w).SetWriteDeadline(deadline.Add(managedNFQResponseGrace))
}
