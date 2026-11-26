//go:build linux && razvilka_native_fixture

package app

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Independent diagnostic subscriber only. It never supplies facts to the
// authoritative physical scope, drains its socket or changes a link. All
// names below are fixed public fixture names; no raw address/attribute body,
// source path, command line or configuration is printed.
func traceManagedProbeNativeLinks(t *testing.T, parent context.Context) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal("diagnostic link subscriber socket", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: unix.RTMGRP_LINK}); err != nil {
		t.Fatal("diagnostic link subscriber bind", errors.Join(err, unix.Close(fd)))
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan error, 1)
	started := time.Now()
	go func() {
		done <- readManagedProbeNativeLinks(ctx, fd, func(kind uint16, family byte, index int32, linkType uint16, flags, change uint32, label string, attrs []uint16) {
			t.Logf("actual diagnostic link notification elapsed=%s kind=%d family=%d ifindex=%d linktype=%d flags=%08x change=%08x fixture=%s attr_types=%v", time.Since(started), kind, family, index, linkType, flags, change, label, attrs)
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err := errors.Join(err, unix.Close(fd)); err != nil {
				t.Error("diagnostic link subscriber joined refusal", err)
			}
		case <-time.After(2 * time.Second):
			closeErr := unix.Close(fd)
			select {
			case err := <-done:
				t.Error("diagnostic subscriber late join", errors.Join(err, closeErr))
			case <-time.After(time.Second):
				t.Error("diagnostic subscriber did not join", closeErr)
			}
		}
	})
}

func readManagedProbeNativeLinks(ctx context.Context, fd int, record func(uint16, byte, int32, uint16, uint32, uint32, string, []uint16)) error {
	buffer := make([]byte, 256<<10)
	count := 0
	for ctx.Err() == nil {
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		_, err := unix.Poll(poll, 100)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return errors.New("diagnostic link poll failure")
		}
		if poll[0].Revents&unix.POLLIN == 0 {
			continue
		}
		n, _, flags, from, err := unix.Recvmsg(fd, buffer, nil, unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		peer, ok := from.(*unix.SockaddrNetlink)
		if !ok || peer.Pid != 0 || flags&unix.MSG_TRUNC != 0 {
			return errors.New("diagnostic link datagram source/length")
		}
		messages, err := syscall.ParseNetlinkMessage(buffer[:n])
		if err != nil {
			return err
		}
		for _, m := range messages {
			if m.Header.Type != unix.RTM_NEWLINK && m.Header.Type != unix.RTM_DELLINK {
				return errors.New("diagnostic unexpected link message")
			}
			if len(m.Data) < 16 {
				return errors.New("diagnostic short link message")
			}
			label := "other"
			var attrs []uint16
			for data := m.Data[16:]; len(data) > 0; {
				if len(data) < 4 {
					return errors.New("diagnostic short link attribute")
				}
				size := int(binary.NativeEndian.Uint16(data[:2]))
				kind := binary.NativeEndian.Uint16(data[2:4]) & 0x3fff
				aligned := (size + 3) &^ 3
				if size < 4 || aligned > len(data) {
					return errors.New("diagnostic link attribute length")
				}
				if len(attrs) < 64 {
					attrs = append(attrs, kind)
				}
				if kind == unix.IFLA_IFNAME {
					name := strings.TrimRight(string(data[4:size]), "\x00")
					switch name {
					case "lo", "rzhome", "rzwan", "rzport10", "rzport20":
						label = name
					}
				}
				data = data[aligned:]
			}
			if count < 64 {
				record(m.Header.Type, m.Data[0], int32(binary.NativeEndian.Uint32(m.Data[4:8])), binary.NativeEndian.Uint16(m.Data[2:4]), binary.NativeEndian.Uint32(m.Data[8:12]), binary.NativeEndian.Uint32(m.Data[12:16]), label, attrs)
			}
			count++
		}
	}
	return nil
}
