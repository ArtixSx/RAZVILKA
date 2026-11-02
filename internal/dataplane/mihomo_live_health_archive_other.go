//go:build !linux

package dataplane

import "context"

func (*mihomoTransitArchiveCursor) create(context.Context) error         { return ErrExecutionJournal }
func (*mihomoTransitArchiveCursor) publish(context.Context) error        { return ErrExecutionJournal }
func (*mihomoTransitArchiveCursor) closeArchive(context.Context) error   { return ErrExecutionJournal }
func (*mihomoTransitArchiveCursor) archiveCurrent(context.Context) error { return ErrExecutionJournal }
func (*mihomoLiveResource) transitArchivePeakBudget(context.Context, int) error {
	return ErrExecutionJournal
}
