package providerfeed

import (
	"net/http"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodestore"
)

// OpenWithDependencies provides trusted in-process dependencies for a server
// workflow or controlled integration test. They are never accepted from HTTP
// requests, subscription data or configuration. Open's private-directory and
// CAS guards, and every fetch's ValidateURL/WithPolicy boundary, remain intact.
// A nil/default Transport still uses WithPolicy's public-only transport.
// The client value is copied; a custom Transport and clock remain trusted
// dependencies whose lifetime/concurrency are owned by their caller.
func OpenWithDependencies(nodes *nodestore.Store, path string, client *http.Client, now func() time.Time) (*Manager, error) {
	if client == nil || now == nil || now().IsZero() {
		return nil, ErrRequest
	}
	clientCopy := *client
	m, err := Open(nodes, path)
	if err != nil {
		return nil, err
	}
	m.client, m.now = &clientCopy, now
	return m, nil
}
