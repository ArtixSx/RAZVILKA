package nodestore

import (
	"context"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

// ExactHistoryReadVersion is a read capability, independent of envelope schema
// 4. CORE exposes it via -node-history-read-version; OPS must gate downgrade
// against current/retained images before any stop or install operation.
const ExactHistoryReadVersion = 2

// RequiredHistoryReadVersion inspects validated private state without returning
// IDs or secrets. Failure is a compatibility fence, never implicit version 1.
// Retained restore images/backups must be inspected by their owning workflow.
func (s *Store) RequiredHistoryReadVersion(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, _, err := s.load(ctx)
	if err != nil {
		return 0, err
	}
	return requiredHistoryReadVersion(doc), nil
}

// RequiredPrivateHistoryReadVersion checks a retained private backup without
// importing it or dropping history. The owning restore/update workflow must
// include every retained image it can later restore in its downgrade gate.
func RequiredPrivateHistoryReadVersion(in PrivateSnapshot) (int, error) {
	if err := ValidatePrivateSnapshot(in); err != nil {
		return 0, err
	}
	doc, err := decodeImage(restorejournal.Image{Exists: true, Data: in.Content})
	if err != nil {
		return 0, err
	}
	return requiredHistoryReadVersion(doc), nil
}

func requiredHistoryReadVersion(doc document) int {
	for _, node := range doc.Nodes {
		for _, check := range node.Checks {
			if check.RoutePathID == "xray:"+node.ID {
				return ExactHistoryReadVersion
			}
		}
	}
	return 1
}
