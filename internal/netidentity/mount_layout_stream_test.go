package netidentity

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
)

// Measurement-only candidate. Production remains mountLayoutOK until paired
// native evidence and independent review justify changing the parser.
func mountLayoutStreamCandidate(data []byte, rootID uint64, paths []string) bool {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return false
	}
	rootSeen := false
	lines := strings.Split(string(data[:len(data)-1]), "\n")
	if len(lines) > 8192 {
		return false
	}
	for _, line := range lines {
		if len(line) > 65536 {
			return false
		}
		var idText, rootText, pointText, fsType string
		count, separator := 0, -1
		for field := range strings.FieldsSeq(line) {
			switch count {
			case 0:
				idText = field
			case 3:
				rootText = field
			case 4:
				pointText = field
			}
			if count >= 6 && separator == -1 && field == "-" {
				separator = count
			} else if separator >= 6 && count == separator+1 {
				fsType = field
			}
			count++
		}
		if count < 10 {
			return false
		}
		id, err := strconv.ParseUint(idText, 10, 64)
		if err != nil || id == 0 {
			return false
		}
		if separator < 6 || count != separator+4 {
			return false
		}
		root, ok := mountUnescape(rootText)
		if !ok {
			return false
		}
		point, ok := mountUnescape(pointText)
		if !ok || !strings.HasPrefix(point, "/") {
			return false
		}
		if id == rootID {
			if rootSeen || root != "/" || point != "/proc" || fsType != "proc" {
				return false
			}
			rootSeen = true
			continue
		}
		if point != "/proc" && !strings.HasPrefix(point, "/proc/") {
			continue
		}
		for _, path := range paths {
			if path == point || strings.HasPrefix(path, point+"/") ||
				(strings.HasSuffix(path, "/fdinfo") && strings.HasPrefix(point, path+"/")) {
				return false
			}
		}
	}
	return rootSeen
}

func TestMountLayoutStreamCandidateParity(t *testing.T) {
	root := "1 0 0:1 / /proc rw - proc proc rw\n"
	other := "2 1 0:2 / /other rw shared:3 - tmpfs tmpfs rw\n"
	paths := []string{"/proc/17/task/18/ns", "/proc/17/fdinfo", "/proc/sys/kernel/random/boot_id"}
	cases := [][]byte{nil, []byte(root), []byte(root + other), []byte(root + root), []byte(root[:len(root)-1]), []byte("\n"), []byte(strings.Repeat(other, 8192) + root), []byte(root + strings.Repeat(" ", 65537) + "\n")}
	cases = append(cases, []byte(strings.Repeat(other, 8191)+root), []byte(root+strings.Repeat(" ", 65536-len(other)+1)+other))
	for _, point := range []string{"/proc", "/proc/17/task/18/ns", "/proc/17/fdinfo/4", "/proc/17", "/proc/170", "/other", "/proc/17/fdinfox", `/proc/17/\134ns`, `/proc/17/\040ns`, `/proc/17/\999ns`} {
		cases = append(cases, []byte(root+strings.Replace(other, "/other", point, 1)))
	}
	for _, line := range []string{
		"1 - - / /proc rw - proc proc rw", "1 0 0:1 / /proc rw optional - proc proc rw", "1 0 0:1 / /proc rw - proc - rw", "1 0 0:1 / /proc rw - - proc rw", "1 0 0:1 / /proc rw - proc proc", "1 0 0:1 / /proc rw - proc proc rw extra", "1 0 0:1 / /proc rw - proc proc rw -", "1 0 0:1 / /proc rw optional", "0 0 0:1 / /proc rw - proc proc rw", "18446744073709551616 0 0:1 / /proc rw - proc proc rw", "1 0 0:1 / /proc rw - tmpfs proc rw",
	} {
		cases = append(cases, []byte(line+"\n"))
	}
	for _, space := range []string{" ", "\t", "\v", "\f", "\r", "\u0085", "\u00a0", "\u2003", "\u2028", "\u3000"} {
		cases = append(cases, []byte(strings.ReplaceAll(root, " ", space)))
	}
	for b := 0; b < 256; b++ {
		cases = append(cases, bytes.Replace([]byte(root), []byte(" rw "), []byte{' ', byte(b), ' '}, 1))
	}
	for i, data := range cases {
		for _, id := range []uint64{0, 1, 2, ^uint64(0)} {
			if before, after := mountLayoutOK(data, id, paths), mountLayoutStreamCandidate(data, id, paths); before != after {
				t.Fatalf("case %d id %d boolean differs", i, id)
			}
		}
	}
}

func FuzzMountLayoutStreamCandidateParity(f *testing.F) {
	for _, data := range [][]byte{[]byte("1 0 0:1 / /proc rw - proc proc rw\n"), []byte("1\u2003x\u2003x\u2003/\u2003/proc\u2003rw\u2003-\u2003proc\u2003proc\u2003rw\n"), {0xff, 0, 10}} {
		f.Add(data, uint64(1), "/proc/17/fdinfo")
	}
	f.Fuzz(func(t *testing.T, data []byte, id uint64, path string) {
		if len(data) > maxMountBytes+1 || len(path) > 65536 {
			t.Skip()
		}
		paths := []string{path, "/proc/17/task/18/ns"}
		if mountLayoutOK(data, id, paths) != mountLayoutStreamCandidate(data, id, paths) {
			t.Fatal("parser boolean differs")
		}
	})
}
