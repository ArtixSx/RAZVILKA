//go:build linux

package systemprobe

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const epochMaxDumpBytes = 1 << 20

type dnsEpochWatch struct {
	directory bool
	names     map[string]bool
}

type linuxEpochSource struct {
	netlink, inotify int
	watches          map[int]*dnsEpochWatch
	watchPaths       map[string]int
	links            map[uint32]string
	addresses        map[string]bool
	routes           map[string]bool
	lastReason       string
}

func (s *linuxEpochSource) ChangeReason() string {
	if s.lastReason == "" {
		return "observed-event"
	}
	return s.lastReason
}

func newPlatformEpochSource(ctx context.Context) (epochSource, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s := &linuxEpochSource{netlink: -1, inotify: -1, watches: map[int]*dnsEpochWatch{}, watchPaths: map[string]int{}}
	var err error
	s.netlink, err = unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	groups := uint32(unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR | unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV6_ROUTE)
	if err = unix.Bind(s.netlink, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: groups}); err != nil {
		s.Close()
		return nil, err
	}
	// Do not enable NETLINK_NO_ENOBUFS: losing notifications must break proof
	// continuity, even if the next snapshot happens to look identical.
	if err = unix.SetsockoptInt(s.netlink, unix.SOL_SOCKET, unix.SO_RCVBUF, 256<<10); err != nil {
		s.Close()
		return nil, err
	}
	s.inotify, err = unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *linuxEpochSource) Close() {
	if s.netlink >= 0 {
		_ = unix.Close(s.netlink)
		s.netlink = -1
	}
	if s.inotify >= 0 {
		_ = unix.Close(s.inotify)
		s.inotify = -1
	}
}

func (s *linuxEpochSource) Snapshot(ctx context.Context) (epochSnapshot, error) {
	var result epochSnapshot
	boot, _, err := epochReadFile(ctx, "/proc/sys/kernel/random/boot_id", 128)
	if err != nil {
		return result, err
	}
	result.bootID = strings.TrimSpace(string(boot))
	decoded, err := hex.DecodeString(strings.ReplaceAll(result.bootID, "-", ""))
	if err != nil || len(decoded) != 16 || len(result.bootID) != 36 {
		return result, ErrNetworkUnavailable
	}
	routeMessages, err := epochDump(ctx, unix.RTM_GETROUTE)
	if err != nil {
		return result, err
	}
	var defaults []epochRoute
	result.interfaces = map[uint32]bool{}
	routes := map[string]bool{}
	for _, message := range routeMessages {
		if message.kind != unix.RTM_NEWROUTE {
			return result, ErrNetworkUnavailable
		}
		route, err := decodeEpochRoute(message, binary.NativeEndian)
		if err != nil {
			return result, err
		}
		if route.canonical == "" {
			continue
		}
		if len(defaults) >= 64 {
			return result, ErrNetworkUnavailable
		}
		defaults = append(defaults, route)
		routes[route.canonical] = true
		for _, index := range route.interfaces {
			result.interfaces[index] = true
		}
	}
	if len(defaults) == 0 {
		return result, ErrNetworkUnavailable
	}
	linkMessages, err := epochDump(ctx, unix.RTM_GETLINK)
	if err != nil {
		return result, err
	}
	if len(linkMessages) > 256 {
		return result, ErrNetworkUnavailable
	}
	links := map[uint32]epochLink{}
	for _, message := range linkMessages {
		if message.kind != unix.RTM_NEWLINK {
			return result, ErrNetworkUnavailable
		}
		link, err := decodeEpochLink(message, binary.NativeEndian)
		if err != nil {
			return result, err
		}
		links[link.index] = link
	}
	// Track lower layers too, so eth down/up invalidates a VLAN/PPP uplink.
	for depth := 0; depth < 8; depth++ {
		added := false
		for index := range result.interfaces {
			link, exists := links[index]
			if !exists || !link.up {
				return result, ErrNetworkUnavailable
			}
			for _, parent := range []uint32{link.parent, link.master} {
				if parent != 0 && parent != index && !result.interfaces[parent] {
					result.interfaces[parent] = true
					added = true
				}
			}
		}
		if !added {
			break
		}
		if depth == 7 {
			return result, ErrNetworkUnavailable
		}
	}
	sort.Slice(defaults, func(i, j int) bool {
		if defaults[i].family != defaults[j].family {
			return defaults[i].family < defaults[j].family
		}
		if defaults[i].metric != defaults[j].metric {
			return defaults[i].metric < defaults[j].metric
		}
		return defaults[i].canonical < defaults[j].canonical
	})
	result.wanInterface = links[defaults[0].interfaces[0]].name
	linkStates := map[uint32]string{}
	for index := range result.interfaces {
		linkStates[index] = links[index].canonical
		result.parts = append(result.parts, links[index].canonical)
	}
	for value := range routes {
		result.parts = append(result.parts, value)
	}
	addressMessages, err := epochDump(ctx, unix.RTM_GETADDR)
	if err != nil {
		return result, err
	}
	if len(addressMessages) > 1024 {
		return result, ErrNetworkUnavailable
	}
	addresses := map[string]bool{}
	for _, message := range addressMessages {
		if message.kind != unix.RTM_NEWADDR {
			return result, ErrNetworkUnavailable
		}
		index, address, err := decodeEpochAddress(message, binary.NativeEndian)
		if err != nil {
			return result, err
		}
		if result.interfaces[index] && address != "" {
			addresses[address] = true
		}
	}
	if len(addresses) == 0 {
		return result, ErrNetworkUnavailable
	}
	for value := range addresses {
		result.parts = append(result.parts, value)
	}
	for _, path := range []string{"/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf"} {
		value, err := s.dnsIdentity(ctx, path, path == "/etc/resolv.conf")
		if err != nil {
			return result, err
		}
		result.parts = append(result.parts, value)
	}
	s.links, s.addresses, s.routes = linkStates, addresses, routes
	return result, nil
}

func (s *linuxEpochSource) Drain(ctx context.Context, interfaces map[uint32]bool) (bool, error) {
	changed := false
	buffer := make([]byte, 64<<10)
	bytesRead, messagesRead := 0, 0
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		n, _, flags, sender, err := unix.Recvmsg(s.netlink, buffer, nil, unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			break
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return false, err
		}
		from, ok := sender.(*unix.SockaddrNetlink)
		if n == 0 || flags&unix.MSG_TRUNC != 0 || !ok || from.Pid != 0 {
			return false, ErrNetworkUnavailable
		}
		bytesRead += n
		messages, err := epochMessages(buffer[:n], binary.NativeEndian)
		if err != nil {
			return false, err
		}
		messagesRead += len(messages)
		if bytesRead > epochMaxDumpBytes || messagesRead > 8192 {
			return false, ErrNetworkUnavailable
		}
		for _, message := range messages {
			relevant, err := s.event(message, interfaces)
			if err != nil {
				return false, err
			}
			changed = changed || relevant
			if relevant {
				switch message.kind {
				case unix.RTM_NEWLINK, unix.RTM_DELLINK:
					s.lastReason = "underlay-link-event"
				case unix.RTM_NEWADDR, unix.RTM_DELADDR:
					s.lastReason = "underlay-address-event"
				case unix.RTM_NEWROUTE, unix.RTM_DELROUTE:
					s.lastReason = "underlay-default-route-event"
				}
			}
		}
	}
	dnsChanged, err := s.drainDNS(ctx)
	if dnsChanged {
		s.lastReason = "dns-file-event"
	}
	return changed || dnsChanged, err
}

func (s *linuxEpochSource) event(message epochMessage, interfaces map[uint32]bool) (bool, error) {
	switch message.kind {
	case unix.NLMSG_ERROR, unix.NLMSG_OVERRUN:
		return false, ErrNetworkUnavailable
	case unix.RTM_NEWLINK, unix.RTM_DELLINK:
		if len(message.data) < 16 {
			return false, ErrNetworkUnavailable
		}
		index := binary.NativeEndian.Uint32(message.data[4:8])
		if !interfaces[index] {
			return false, nil
		}
		if message.kind == unix.RTM_DELLINK {
			delete(s.links, index)
			return true, nil
		}
		link, err := decodeEpochLink(message, binary.NativeEndian)
		if err != nil {
			return false, err
		}
		old := s.links[index]
		if s.links == nil {
			s.links = map[uint32]string{}
		}
		s.links[index] = link.canonical
		return old != link.canonical, nil
	case unix.RTM_NEWADDR, unix.RTM_DELADDR:
		index, value, err := decodeEpochAddress(message, binary.NativeEndian)
		if err != nil {
			return false, err
		}
		if !interfaces[index] || value == "" {
			return false, nil
		}
		if message.kind == unix.RTM_DELADDR {
			delete(s.addresses, value)
			return true, nil
		}
		old := s.addresses[value]
		if s.addresses == nil {
			s.addresses = map[string]bool{}
		}
		s.addresses[value] = true
		return !old, nil
	case unix.RTM_NEWROUTE, unix.RTM_DELROUTE:
		route, err := decodeEpochRoute(message, binary.NativeEndian)
		if err != nil {
			return false, err
		}
		// Underlay scope: main-table defaults. Engine/candidate tables and
		// connected TUN routes are not mistaken for a WAN reconnect. No name
		// prefix grants an exclusion: even an rz-* main default is observed.
		if route.canonical == "" {
			return false, nil
		}
		if message.kind == unix.RTM_DELROUTE {
			delete(s.routes, route.canonical)
			return true, nil
		}
		old := s.routes[route.canonical]
		if s.routes == nil {
			s.routes = map[string]bool{}
		}
		s.routes[route.canonical] = true
		return !old, nil
	}
	return false, nil
}

func epochDump(ctx context.Context, kind uint16) ([]epochMessage, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	request := make([]byte, 20)
	binary.NativeEndian.PutUint32(request[:4], 17)
	binary.NativeEndian.PutUint16(request[4:6], kind)
	binary.NativeEndian.PutUint16(request[6:8], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(request[8:12], 1)
	if err := unix.Sendto(fd, request[:17], 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	buffer := make([]byte, 64<<10)
	var result []epochMessage
	bytesRead := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, _, flags, sender, err := unix.Recvmsg(fd, buffer, nil, unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			_, err = unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, 25)
			if err != nil && !errors.Is(err, unix.EINTR) {
				return nil, err
			}
			continue
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, err
		}
		from, ok := sender.(*unix.SockaddrNetlink)
		if n == 0 || flags&unix.MSG_TRUNC != 0 || !ok || from.Pid != 0 {
			return nil, ErrNetworkUnavailable
		}
		bytesRead += n
		if bytesRead > epochMaxDumpBytes {
			return nil, ErrNetworkUnavailable
		}
		data := append([]byte(nil), buffer[:n]...)
		messages, err := epochMessages(data, binary.NativeEndian)
		if err != nil {
			return nil, err
		}
		for _, message := range messages {
			if message.seq != 1 || message.flags&unix.NLM_F_DUMP_INTR != 0 {
				return nil, ErrNetworkUnavailable
			}
			switch message.kind {
			case unix.NLMSG_DONE:
				if len(message.data) >= 4 && binary.NativeEndian.Uint32(message.data[:4]) != 0 {
					return nil, ErrNetworkUnavailable
				}
				return result, nil
			case unix.NLMSG_ERROR, unix.NLMSG_OVERRUN:
				return nil, ErrNetworkUnavailable
			default:
				result = append(result, message)
				if len(result) > 8192 {
					return nil, ErrNetworkUnavailable
				}
			}
		}
	}
}

func epochReadFile(ctx context.Context, path string, max int64) ([]byte, unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := ctx.Err(); err != nil {
		return nil, stat, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, stat, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, stat, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, stat, ErrNetworkUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil || int64(len(data)) > max {
		return nil, stat, ErrNetworkUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, stat, err
	}
	return data, stat, nil
}

func (s *linuxEpochSource) watchDNS(path string, directory bool, name string) error {
	wd, exists := s.watchPaths[path]
	if !exists {
		if len(s.watchPaths) >= 32 {
			return ErrNetworkUnavailable
		}
		mask := uint32(unix.IN_ATTRIB | unix.IN_CLOSE_WRITE | unix.IN_DELETE_SELF | unix.IN_MOVE_SELF)
		if directory {
			mask |= unix.IN_CREATE | unix.IN_DELETE | unix.IN_MOVED_FROM | unix.IN_MOVED_TO
		} else {
			mask |= unix.IN_MODIFY
		}
		var err error
		wd, err = unix.InotifyAddWatch(s.inotify, path, mask)
		if err != nil {
			return err
		}
		s.watchPaths[path] = wd
		if s.watches[wd] == nil {
			s.watches[wd] = &dnsEpochWatch{directory: directory, names: map[string]bool{}}
		}
	}
	if directory {
		s.watches[wd].names[name] = true
	}
	return nil
}

func (s *linuxEpochSource) dnsIdentity(ctx context.Context, path string, required bool) (string, error) {
	if err := s.watchDNS(filepath.Dir(path), true, filepath.Base(path)); err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		if !required && errors.Is(err, os.ErrNotExist) {
			return "dns=" + path + "|absent", nil
		}
		return "", err
	}
	if err := s.watchDNS(filepath.Dir(resolved), true, filepath.Base(resolved)); err != nil {
		return "", err
	}
	if err := s.watchDNS(resolved, false, ""); err != nil {
		return "", err
	}
	data, stat, err := epochReadFile(ctx, resolved, 64<<10)
	if err != nil {
		return "", err
	}
	if required && !validEpochDNSConfig(data) {
		return "", ErrNetworkUnavailable
	}
	digest := sha256.Sum256(data)
	return fmt.Sprintf("dns=%s|target=%s|dev=%d|ino=%d|mtime=%d.%d|sha=%x", path, resolved, stat.Dev, stat.Ino, stat.Mtim.Sec, stat.Mtim.Nsec, digest), nil
}

func (s *linuxEpochSource) drainDNS(ctx context.Context) (bool, error) {
	buffer := make([]byte, 16<<10)
	changed, bytesRead := false, 0
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		n, err := unix.Read(s.inotify, buffer)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			return changed, nil
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || n == 0 {
			return false, ErrNetworkUnavailable
		}
		bytesRead += n
		if bytesRead > 256<<10 {
			return false, ErrNetworkUnavailable
		}
		for data := buffer[:n]; len(data) > 0; {
			if len(data) < 16 {
				return false, ErrNetworkUnavailable
			}
			wd := int(int32(binary.NativeEndian.Uint32(data[:4])))
			mask := binary.NativeEndian.Uint32(data[4:8])
			size := uint64(binary.NativeEndian.Uint32(data[12:16]))
			if size > uint64(len(data)-16) || mask&(unix.IN_Q_OVERFLOW|unix.IN_IGNORED|unix.IN_UNMOUNT|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF) != 0 {
				return false, ErrNetworkUnavailable
			}
			watch := s.watches[wd]
			if watch == nil {
				return false, ErrNetworkUnavailable
			}
			name := strings.TrimRight(string(data[16:16+size]), "\x00")
			if !watch.directory || watch.names[name] {
				changed = true
			}
			data = data[16+size:]
		}
	}
}
