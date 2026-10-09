// The standalone wire routines below are transferred from the Root-reviewed
// disposable Telegram120 QA source. No nodeeval/App/health wrappers are used.
// Format checked 2026-10-08 against official Telegram sources:
// https://core.telegram.org/schema/mtproto
// https://core.telegram.org/mtproto/auth_key
// https://core.telegram.org/mtproto/description
// https://core.telegram.org/mtproto/mtproto-transports#abridged
// DC2 matches Telegram Desktop kBuiltInDcs in mtproto_dc_options.cpp.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"

	xnetproxy "golang.org/x/net/proxy"
)

const qaMTEndpoint = "149.154.167.51:443"
const qaMTBudget = 3 * time.Second
const qaMTMaxFrame = 4096
const qaMTMaxFingerprints = 16
const qaMTReqPQ uint32 = 0xbe7e8ef1
const qaMTResPQ uint32 = 0x05162463
const qaMTVector uint32 = 0x1cb5c415

type qaMTObservation struct {
	Code      string
	Reply     bool
	ElapsedMS int64
}

// Only the configured loopback address is dialed directly. The numeric DC is
// sent to SOCKS; process/node ownership is verified separately by the operator.
func qaMTDial(ctx context.Context, address string) (net.Conn, error) {
	return qaMTSOCKSDial(ctx, address, &net.Dialer{Timeout: qaMTBudget})
}

func qaMTSOCKSDial(ctx context.Context, address string, forward xnetproxy.Dialer) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	ip, ipErr := netip.ParseAddr(host)
	number, portErr := strconv.Atoi(port)
	if err != nil || ipErr != nil || !ip.IsLoopback() || ip.Zone() != "" || portErr != nil || number < 1 || number > 65535 {
		return nil, errors.New("MTProto QA loopback unavailable")
	}
	proxy, err := xnetproxy.SOCKS5("tcp", address, nil, forward)
	if err != nil {
		return nil, err
	}
	dialer, ok := proxy.(xnetproxy.ContextDialer)
	if !ok {
		return nil, errors.New("MTProto QA bounded SOCKS unavailable")
	}
	return dialer.DialContext(ctx, "tcp", qaMTEndpoint)
}

func qaMTProbe(ctx context.Context, address string) qaMTObservation {
	return qaMTExchange(ctx, address, qaMTDial, time.Now)
}

func qaMTProbeWithDialer(ctx context.Context, dialer xnetproxy.ContextDialer) qaMTObservation {
	return qaMTExchange(ctx, qaMTEndpoint, func(ctx context.Context, target string) (net.Conn, error) {
		if target != qaMTEndpoint {
			return nil, errors.New("MTProto QA target changed")
		}
		return dialer.DialContext(ctx, "tcp", target)
	}, time.Now)
}

func qaMTExchange(parent context.Context, address string, dial func(context.Context, string) (net.Conn, error), now func() time.Time) qaMTObservation {
	ctx, cancel := context.WithTimeout(parent, qaMTBudget)
	defer cancel()
	if ctx.Err() != nil {
		return qaMTObservation{Code: qaMTIOCode(ctx, ctx.Err())}
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return qaMTObservation{Code: "mtproto-entropy-unavailable"}
	}
	defer clear(nonce[:])
	conn, err := dial(ctx, address)
	if err != nil {
		return qaMTObservation{Code: qaMTIOCode(ctx, err)}
	}
	defer conn.Close()
	end, _ := ctx.Deadline()
	if conn.SetDeadline(end) != nil {
		return qaMTObservation{Code: "mtproto-deadline-setup"}
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	request := qaMTRequest(nonce, now())
	defer clear(request)
	if _, err := io.Copy(conn, bytes.NewReader(request)); err != nil {
		return qaMTObservation{Code: qaMTIOCode(ctx, err)}
	}
	frame, code := qaMTReadFrame(ctx, conn)
	if code != "" {
		return qaMTObservation{Code: code}
	}
	defer clear(frame)
	code = qaMTValidate(frame, nonce, now())
	if ctx.Err() != nil {
		return qaMTObservation{Code: qaMTIOCode(ctx, ctx.Err())}
	}
	if code != "" {
		return qaMTObservation{Code: code}
	}
	return qaMTObservation{Code: "mtproto-respq", Reply: true}
}

func qaMTRequest(nonce [16]byte, now time.Time) []byte {
	packet := make([]byte, 42)
	packet[0], packet[1] = 0xef, 10 // one transport marker, then 40-byte payload / 4
	fraction := ((uint64(now.Nanosecond()) << 32) / 1000000000) &^ 3
	if fraction == 0 {
		fraction = 4 // Official msg_id requires a nonempty fractional part.
	}
	messageID := uint64(now.Unix())<<32 | fraction
	binary.LittleEndian.PutUint64(packet[10:18], messageID)
	binary.LittleEndian.PutUint32(packet[18:22], 20)
	binary.LittleEndian.PutUint32(packet[22:26], qaMTReqPQ)
	copy(packet[26:], nonce[:])
	return packet
}

func qaMTReadFrame(ctx context.Context, r io.Reader) ([]byte, string) {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return nil, qaMTIOCode(ctx, err)
	}
	words := uint32(first[0])
	if words == 0 || words > 127 {
		return nil, "mtproto-frame-invalid"
	}
	if words == 127 {
		var extended [3]byte
		if _, err := io.ReadFull(r, extended[:]); err != nil {
			return nil, qaMTIOCode(ctx, err)
		}
		words = uint32(extended[0]) | uint32(extended[1])<<8 | uint32(extended[2])<<16
		if words < 127 {
			return nil, "mtproto-frame-invalid"
		}
	}
	if words > qaMTMaxFrame/4 {
		return nil, "mtproto-frame-oversize"
	}
	frame := make([]byte, int(words)*4)
	if _, err := io.ReadFull(r, frame); err != nil {
		clear(frame)
		return nil, qaMTIOCode(ctx, err)
	}
	if len(frame) == 4 && int32(binary.LittleEndian.Uint32(frame)) < 0 {
		clear(frame)
		return nil, "mtproto-transport-error"
	}
	return frame, ""
}

func qaMTValidate(frame []byte, nonce [16]byte, now time.Time) string {
	if len(frame) < 76 || len(frame) > qaMTMaxFrame || len(frame)%4 != 0 || binary.LittleEndian.Uint64(frame[:8]) != 0 || int(binary.LittleEndian.Uint32(frame[16:20])) != len(frame)-20 {
		return "mtproto-envelope-invalid"
	}
	id := binary.LittleEndian.Uint64(frame[8:16])
	seconds := int64(id >> 32)
	if id&3 != 1 || seconds < now.Unix()-300 || seconds > now.Unix()+30 {
		return "mtproto-message-id-invalid"
	}
	body := frame[20:]
	if binary.LittleEndian.Uint32(body[:4]) != qaMTResPQ {
		return "mtproto-constructor-invalid"
	}
	if !bytes.Equal(body[4:20], nonce[:]) {
		return "mtproto-nonce-mismatch"
	}
	// nonce/server_nonce are fixed 16-byte fields; no server identity is inferred.
	n := int(body[36])
	if n < 1 || n > 8 || 37+n > len(body) {
		return "mtproto-pq-invalid"
	}
	pq := body[37 : 37+n]
	if pq[0] == 0 || n == 8 && pq[0]&128 != 0 {
		return "mtproto-pq-invalid"
	}
	var number uint64
	for _, b := range pq {
		number = number<<8 | uint64(b)
	}
	if number < 15 || number&1 == 0 {
		return "mtproto-pq-invalid"
	}
	end := (37 + n + 3) &^ 3
	if end+8 > len(body) {
		return "mtproto-tl-truncated"
	}
	for _, pad := range body[37+n : end] {
		if pad != 0 {
			return "mtproto-tl-padding"
		}
	}
	if binary.LittleEndian.Uint32(body[end:end+4]) != qaMTVector {
		return "mtproto-vector-invalid"
	}
	count := binary.LittleEndian.Uint32(body[end+4 : end+8])
	if count < 1 || count > qaMTMaxFingerprints {
		return "mtproto-vector-bounds"
	}
	if end+8+int(count)*8 != len(body) {
		return "mtproto-tl-length"
	}
	return ""
}

func qaMTIOCode(ctx context.Context, err error) string {
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return "mtproto-canceled"
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return "mtproto-deadline"
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "mtproto-truncated"
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "mtproto-deadline"
	}
	return "mtproto-io-failed"
}
