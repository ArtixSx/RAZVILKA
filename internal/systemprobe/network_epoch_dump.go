package systemprobe

import (
	"context"
	"errors"
	"fmt"
)

var errEpochDumpInterrupted = fmt.Errorf("%w: interrupted netlink snapshot", ErrNetworkUnavailable)

// Linux explicitly requires discarding an interrupted dump and starting over:
// https://www.kernel.org/doc/html/latest/userspace-api/netlink/intro.html#dump-consistency
// Only that signal is retryable. Notification loss and malformed input still
// break proof continuity. All attempts share the original snapshot deadline.
func retryEpochDump(ctx context.Context, dump func(context.Context) ([]epochMessage, error)) ([]epochMessage, error) {
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		messages, err := dump(ctx)
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, contextErr
		}
		if err == nil {
			return messages, nil
		}
		if !errors.Is(err, errEpochDumpInterrupted) || attempt == 2 {
			return nil, err
		}
	}
	return nil, ErrNetworkUnavailable
}
