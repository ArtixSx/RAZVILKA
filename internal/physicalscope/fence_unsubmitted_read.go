package physicalscope

import "context"

// This is a refusal before a request reaches the original collector. It says
// nothing about physical freshness: retained cleanup must perform every fresh
// observation again. In-flight cancellation deliberately never issues it.
type fenceUnsubmittedRead struct {
	self   *fenceUnsubmittedRead
	reader *originalFenceCollector
	cause  error
}

func (e *fenceUnsubmittedRead) Error() string { return "original fence read not submitted" }
func (e *fenceUnsubmittedRead) Unwrap() error { return e.cause }

func (r *originalFenceCollector) unsubmittedRead(ctx context.Context) error {
	e := &fenceUnsubmittedRead{reader: r, cause: ctx.Err()}
	e.self = e
	return boundary("fence.check.context", e)
}

// Accept only our own two wrapping boundaries and their exact ErrUnknown
// joins. errors.As alone could hide a simultaneous source loss in another arm.
func (r *originalFenceCollector) ownsUnsubmittedRead(err error) bool {
	for {
		switch e := err.(type) {
		case *boundaryFailure:
			if e.stage != "packet.capture" && e.stage != "fence.check.context" {
				return false
			}
			err = e.cause
		case interface{ Unwrap() []error }:
			parts := e.Unwrap()
			if len(parts) != 2 || parts[0] != ErrUnknown {
				return false
			}
			err = parts[1]
		case *fenceUnsubmittedRead:
			return r != nil && e != nil && e.self == e && e.reader == r &&
				(e.cause == context.Canceled || e.cause == context.DeadlineExceeded)
		default:
			return false
		}
	}
}

func packetReadNotSubmitted(f ipv4LANPacketFence, err error) bool {
	owner, ok := f.(interface{ ownsUnsubmittedRead(error) bool })
	return ok && owner.ownsUnsubmittedRead(err)
}
