//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"
)

const syntheticIPSetSubsystem = 6
const syntheticIPSetTest = 11
const syntheticIPSetGetHeader = 12

type syntheticIPSetSocket struct {
	fd              int
	port, seq       uint32
	messages, bytes int
	closed, failed  bool
}

func openSyntheticIPSetSession(ctx context.Context) (syntheticIPSetSession, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	var seed [4]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, syntheticIPSetFailure("sequence")
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, syntheticIPSetFailure("socket")
	}
	keep := false
	defer func() {
		if !keep {
			_ = unix.Close(fd)
		}
	}()
	if unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}) != nil {
		return nil, syntheticIPSetFailure("bind")
	}
	address, err := unix.Getsockname(fd)
	if err != nil {
		return nil, syntheticIPSetFailure("socket-name")
	}
	local, ok := address.(*unix.SockaddrNetlink)
	if !ok || local.Pid == 0 || local.Groups != 0 {
		return nil, syntheticIPSetFailure("socket-name")
	}
	seq := binary.NativeEndian.Uint32(seed[:])
	if seq == 0 || seq > ^uint32(0)-32 {
		seq = 1
	}
	keep = true
	return &syntheticIPSetSocket{fd: fd, port: local.Pid, seq: seq}, nil
}

func (s *syntheticIPSetSocket) Close() error {
	if s == nil || s.closed {
		return syntheticIPSetFailure("closed")
	}
	s.closed = true
	return unix.Close(s.fd)
}

func syntheticIPSetAttr(kind uint16, value []byte) []byte {
	size := len(value) + 4
	b := make([]byte, (size+3)&^3)
	binary.NativeEndian.PutUint16(b[:2], uint16(size))
	binary.NativeEndian.PutUint16(b[2:4], kind)
	copy(b[4:], value)
	return b
}

// Closed ABI: HEADER and TEST only. Neither arbitrary flags/attributes nor a
// mutation command can be represented by this builder.
func syntheticIPSetRequest(command uint16, seq, port uint32, set string, address netip.Addr, nomatch bool) ([]byte, error) {
	if !syntheticIPSetName(set) || seq == 0 || port == 0 || command != syntheticIPSetTest && command != syntheticIPSetGetHeader {
		return nil, syntheticIPSetFailure("request")
	}
	attrs := syntheticIPSetAttr(1, []byte{6})
	attrs = append(attrs, syntheticIPSetAttr(2, append([]byte(set), 0))...)
	if command == syntheticIPSetTest {
		if !address.Is4() || address.Is4In6() {
			return nil, syntheticIPSetFailure("address")
		}
		ip := address.As4()
		// Linux 4.9 utest hardcodes command flags to zero. Its userspace
		// extension defaults leave counters untouched; do not supply packet/
		// byte extensions. CADT_NOMATCH is the separate negative-entry query.
		data := syntheticIPSetAttr(1|0x8000, syntheticIPSetAttr(1|0x4000, ip[:]))
		if nomatch {
			var flags [4]byte
			binary.BigEndian.PutUint32(flags[:], 4)
			data = append(data, syntheticIPSetAttr(8|0x4000, flags[:])...)
		}
		attrs = append(attrs, syntheticIPSetAttr(7|0x8000, data)...)
	} else if address.IsValid() || nomatch {
		return nil, syntheticIPSetFailure("request")
	}
	request := make([]byte, 20+len(attrs))
	binary.NativeEndian.PutUint32(request[:4], uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:6], syntheticIPSetSubsystem<<8|command)
	binary.NativeEndian.PutUint16(request[6:8], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.NativeEndian.PutUint32(request[8:12], seq)
	binary.NativeEndian.PutUint32(request[12:16], port)
	// nfgenmsg: AF_INET, nfnetlink version 0, resource id 0.
	request[16] = unix.AF_INET
	copy(request[20:], attrs)
	return request, nil
}

func syntheticIPSetAttrs(data []byte) (map[uint16][]byte, error) {
	out := map[uint16][]byte{}
	for len(data) > 0 {
		if len(data) < 4 {
			return nil, syntheticIPSetFailure("attribute")
		}
		n := int(binary.NativeEndian.Uint16(data[:2]))
		kind := binary.NativeEndian.Uint16(data[2:4])
		aligned := (n + 3) &^ 3
		if n < 4 || aligned > len(data) || kind == 0 || kind > 5 || out[kind] != nil {
			return nil, syntheticIPSetFailure("attribute")
		}
		if !bytes.Equal(data[n:aligned], make([]byte, aligned-n)) {
			return nil, syntheticIPSetFailure("attribute-padding")
		}
		out[kind] = append([]byte{}, data[4:n]...)
		data = data[aligned:]
	}
	return out, nil
}

func syntheticIPSetDecodeHeader(body []byte) (syntheticIPSetHeader, error) {
	var h syntheticIPSetHeader
	if len(body) < 4 || body[0] != unix.AF_INET || body[1] != 0 || body[2] != 0 || body[3] != 0 {
		return h, syntheticIPSetFailure("header")
	}
	attrs, err := syntheticIPSetAttrs(body[4:])
	if err != nil {
		return h, err
	}
	if len(attrs) != 5 || len(attrs[1]) != 1 || len(attrs[4]) != 1 || len(attrs[5]) != 1 {
		return h, syntheticIPSetFailure("header-attributes")
	}
	text := func(b []byte) (string, bool) {
		if len(b) < 2 || len(b) > 32 || b[len(b)-1] != 0 || bytes.IndexByte(b[:len(b)-1], 0) >= 0 {
			return "", false
		}
		return string(b[:len(b)-1]), true
	}
	var ok bool
	h.name, ok = text(attrs[2])
	if !ok || !syntheticIPSetName(h.name) {
		return h, syntheticIPSetFailure("header-name")
	}
	h.kind, ok = text(attrs[3])
	if !ok {
		return h, syntheticIPSetFailure("header-type")
	}
	h.protocol, h.revision, h.family = attrs[1][0], attrs[4][0], attrs[5][0]
	return h, nil
}

type syntheticIPSetReply struct {
	header                 syntheticIPSetHeader
	gotHeader, ack, member bool
}

func syntheticIPSetConsume(packet, request []byte, reply *syntheticIPSetReply) error {
	for len(packet) > 0 {
		if len(packet) < 16 {
			return syntheticIPSetFailure("message")
		}
		size := int(binary.NativeEndian.Uint32(packet[:4]))
		aligned := (size + 3) &^ 3
		if size < 16 || aligned > len(packet) || !bytes.Equal(packet[8:16], request[8:16]) || !bytes.Equal(packet[size:aligned], make([]byte, aligned-size)) {
			return syntheticIPSetFailure("message-identity")
		}
		kind := binary.NativeEndian.Uint16(packet[4:6])
		body := packet[16:size]
		flags := binary.NativeEndian.Uint16(packet[6:8])
		// Modern kernels mark their header-only ACK with NLM_F_CAPPED.
		// It does not permit missing echoed request headers or ACK TLVs.
		if flags != 0 && !(flags == 0x100 && kind == unix.NLMSG_ERROR && len(body) == 20) {
			return syntheticIPSetFailure("message-flags")
		}
		switch kind {
		case unix.NLMSG_ERROR:
			if reply.ack || len(body) < 20 || !bytes.Equal(body[4:20], request[:16]) || len(body) > 4+len(request) {
				return syntheticIPSetFailure("ack")
			}
			if len(body) > 20 && !bytes.Equal(body[20:], request[16:len(body)-4]) {
				return syntheticIPSetFailure("ack-echo")
			}
			code := int32(binary.NativeEndian.Uint32(body[:4]))
			switch {
			case code == 0:
				reply.member = true
			case code == -4103 && binary.NativeEndian.Uint16(request[4:6]) == syntheticIPSetSubsystem<<8|syntheticIPSetTest:
				reply.member = false
			case code == -int32(unix.ENOENT):
				return syntheticIPSetFailure("set-absent")
			default:
				return syntheticIPSetFailure("kernel-result")
			}
			reply.ack = true
		case syntheticIPSetSubsystem<<8 | syntheticIPSetGetHeader:
			if reply.gotHeader || binary.NativeEndian.Uint16(request[4:6]) != kind {
				return syntheticIPSetFailure("unexpected-header")
			}
			h, err := syntheticIPSetDecodeHeader(body)
			if err != nil {
				return err
			}
			reply.header = h
			reply.gotHeader = true
		default:
			return syntheticIPSetFailure("message-type")
		}
		packet = packet[aligned:]
	}
	return nil
}

func (s *syntheticIPSetSocket) exchange(ctx context.Context, command uint16, set string, address netip.Addr, nomatch bool) (reply syntheticIPSetReply, resultErr error) {
	defer func() {
		if resultErr != nil && s != nil {
			s.failed = true
		}
	}()
	if s == nil || s.closed || s.failed || ctx == nil || ctx.Err() != nil {
		return reply, syntheticIPSetFailure("session")
	}
	deadline, finite := ctx.Deadline()
	if !finite || time.Until(deadline) > 2*time.Second {
		return reply, syntheticIPSetFailure("deadline")
	}
	request, err := syntheticIPSetRequest(command, s.seq, s.port, set, address, nomatch)
	if err != nil {
		return reply, err
	}
	s.seq++
	if unix.Sendto(s.fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}) != nil {
		return reply, syntheticIPSetFailure("send")
	}
	buffer := make([]byte, 8192)
	for !reply.ack || command == syntheticIPSetGetHeader && !reply.gotHeader {
		if ctx.Err() != nil {
			return reply, errors.Join(syntheticIPSetFailure("timeout"), ctx.Err())
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return reply, syntheticIPSetFailure("timeout")
		}
		poll := []unix.PollFd{{Fd: int32(s.fd), Events: unix.POLLIN}}
		n, err := unix.Poll(poll, min(20, int((remaining+time.Millisecond-1)/time.Millisecond)))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return reply, syntheticIPSetFailure("poll")
		}
		if n == 0 {
			continue
		}
		if poll[0].Revents != unix.POLLIN {
			return reply, syntheticIPSetFailure("poll-state")
		}
		n, _, flags, from, err := unix.Recvmsg(s.fd, buffer, nil, unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
			continue
		}
		peer, ok := from.(*unix.SockaddrNetlink)
		if err != nil || !ok || peer.Pid != 0 || peer.Groups != 0 || flags != 0 || n <= 0 || n > len(buffer) {
			return reply, syntheticIPSetFailure("receive")
		}
		s.messages++
		s.bytes += n
		if s.messages > 32 || s.bytes > 64<<10 {
			return reply, syntheticIPSetFailure("budget")
		}
		if err := syntheticIPSetConsume(buffer[:n], request, &reply); err != nil {
			return reply, err
		}
	}
	// No stale/duplicate record may remain queued for the next request.
	n, _, _, _, err := unix.Recvmsg(s.fd, buffer, nil, unix.MSG_DONTWAIT)
	if !errors.Is(err, unix.EAGAIN) || n > 0 {
		return reply, syntheticIPSetFailure("trailing-record")
	}
	return reply, ctx.Err()
}

func (s *syntheticIPSetSocket) header(ctx context.Context, set string) (syntheticIPSetHeader, error) {
	r, err := s.exchange(ctx, syntheticIPSetGetHeader, set, netip.Addr{}, false)
	return r.header, err
}
func (s *syntheticIPSetSocket) test(ctx context.Context, set string, address netip.Addr, nomatch bool) (bool, error) {
	r, err := s.exchange(ctx, syntheticIPSetTest, set, address, nomatch)
	return r.member, err
}
