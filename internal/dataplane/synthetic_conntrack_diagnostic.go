package dataplane

import "errors"

// Closed, process-local diagnostics only. Causes remain available to errors.Is;
// neither Error nor the native fixture serializes their native text or values.
type syntheticCTReason string

const (
	syntheticCTContext         syntheticCTReason = "context-budget"
	syntheticCTOpen            syntheticCTReason = "transport-open"
	syntheticCTTransport       syntheticCTReason = "transport-type"
	syntheticCTClose           syntheticCTReason = "transport-close"
	syntheticCTPrequeued       syntheticCTReason = "transport-prequeued"
	syntheticCTSend            syntheticCTReason = "transport-send"
	syntheticCTPoll            syntheticCTReason = "transport-poll"
	syntheticCTPollEvents      syntheticCTReason = "transport-poll-events"
	syntheticCTReceive         syntheticCTReason = "transport-receive"
	syntheticCTRequestIdentity syntheticCTReason = "request-identity"
	syntheticCTState           syntheticCTReason = "decoder-state"
	syntheticCTSender          syntheticCTReason = "datagram-sender"
	syntheticCTTruncated       syntheticCTReason = "datagram-truncated"
	syntheticCTEmpty           syntheticCTReason = "datagram-empty"
	syntheticCTBudget          syntheticCTReason = "decoder-budget"
	syntheticCTMessageLength   syntheticCTReason = "message-length"
	syntheticCTMessageFlags    syntheticCTReason = "message-flags"
	syntheticCTSequence        syntheticCTReason = "message-sequence"
	syntheticCTPort            syntheticCTReason = "message-port"
	syntheticCTPadding         syntheticCTReason = "message-padding"
	syntheticCTMessageKind     syntheticCTReason = "message-kind"
	syntheticCTDone            syntheticCTReason = "done-status"
	syntheticCTDuplicateID     syntheticCTReason = "row-duplicate-id"
	syntheticCTRowBudget       syntheticCTReason = "row-budget"
	syntheticCTFinish          syntheticCTReason = "decoder-incomplete"
	syntheticCTDrain           syntheticCTReason = "terminal-drain"
	syntheticCTAttribute       syntheticCTReason = "attribute-framing"
	syntheticCTDuplicateAttr   syntheticCTReason = "attribute-duplicate"
	syntheticCTNestedFlags     syntheticCTReason = "attribute-nested-flags"
	syntheticCTFamily          syntheticCTReason = "row-family-version"
	syntheticCTTupleShape      syntheticCTReason = "row-tuple-shape"
	syntheticCTReplyProtocol   syntheticCTReason = "row-reply-protocol"
	syntheticCTStatusShape     syntheticCTReason = "row-status-shape"
	syntheticCTIDShape         syntheticCTReason = "row-id-shape"
	syntheticCTStatusMask      syntheticCTReason = "row-status-mask"
	syntheticCTZeroID          syntheticCTReason = "row-id-zero"
	syntheticCTRowShape        syntheticCTReason = "row-attribute-shape"
	syntheticCTAttr24          syntheticCTReason = "row-attribute-24"
	syntheticCTAttr25          syntheticCTReason = "row-attribute-25"
	syntheticCTAttr26          syntheticCTReason = "row-attribute-26"
	syntheticCTUnknownAttr     syntheticCTReason = "row-attribute-unknown"
)

const (
	syntheticCTScopeIdentity    syntheticCTReason = "abi-identity"
	syntheticCTABIUnknown       syntheticCTReason = "decoder-abi"
	syntheticCTStockMarkShape   syntheticCTReason = "stock-ndmmark-shape"
	syntheticCTStockIfacesShape syntheticCTReason = "stock-ndm-ifaces-shape"
	syntheticCTStockNTCEShape   syntheticCTReason = "stock-ntce-shape"
)

func (r syntheticCTReason) label() string {
	switch r {
	case syntheticCTContext, syntheticCTOpen, syntheticCTTransport, syntheticCTClose,
		syntheticCTPrequeued, syntheticCTSend, syntheticCTPoll, syntheticCTPollEvents,
		syntheticCTReceive, syntheticCTRequestIdentity, syntheticCTState, syntheticCTSender,
		syntheticCTTruncated, syntheticCTEmpty, syntheticCTBudget, syntheticCTMessageLength,
		syntheticCTMessageFlags, syntheticCTSequence, syntheticCTPort, syntheticCTPadding,
		syntheticCTMessageKind, syntheticCTDone, syntheticCTDuplicateID, syntheticCTRowBudget,
		syntheticCTFinish, syntheticCTDrain, syntheticCTAttribute, syntheticCTDuplicateAttr,
		syntheticCTNestedFlags, syntheticCTFamily, syntheticCTTupleShape, syntheticCTReplyProtocol,
		syntheticCTStatusShape, syntheticCTIDShape, syntheticCTStatusMask, syntheticCTZeroID,
		syntheticCTRowShape, syntheticCTAttr24, syntheticCTAttr25, syntheticCTAttr26, syntheticCTUnknownAttr,
		syntheticCTScopeIdentity, syntheticCTABIUnknown, syntheticCTStockMarkShape, syntheticCTStockIfacesShape, syntheticCTStockNTCEShape:
		return string(r)
	default:
		return "unclassified"
	}
}

type syntheticCTError struct {
	reason syntheticCTReason
	cause  error
}

func (e *syntheticCTError) Error() string {
	return errSyntheticConntrack.Error() + ": " + e.reason.label()
}
func (e *syntheticCTError) Is(target error) bool { return target == errSyntheticConntrack }
func (e *syntheticCTError) Unwrap() error        { return e.cause }

func syntheticCTFailure(reason syntheticCTReason, cause error) error {
	return &syntheticCTError{reason: reason, cause: cause}
}

func syntheticCTDiagnostic(err error) string {
	if err == nil {
		return "none"
	}
	var diagnostic *syntheticCTError
	if errors.As(err, &diagnostic) && diagnostic != nil {
		return diagnostic.reason.label()
	}
	return "unclassified"
}
