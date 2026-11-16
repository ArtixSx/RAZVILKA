package netidentity

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestMountFieldsPreserveOriginalTokens(t *testing.T) {
	cases := []string{"", " ", "\x00", "1 0 0:1 / /proc rw - proc proc rw", strings.Repeat("field ", 40)}
	for _, space := range []string{" ", "\t", "\n", "\v", "\f", "\r", "\u0085", "\u00a0", "\u2003", "\u2028", "\u3000"} {
		cases = append(cases, space+strings.Join([]string{"1", "0", "0:1", "/", "/proc", "rw", "-", "proc", "proc", "rw"}, space)+space)
	}
	for b := 0; b < 256; b++ {
		cases = append(cases, "a "+string([]byte{byte(b)})+" z", "a"+string([]byte{byte(b)})+"z")
	}
	var storage [16]string
	for _, data := range cases {
		for capacity := 0; capacity <= len(storage); capacity++ {
			got := mountFields(data, storage[:0:capacity])
			if !slices.Equal(got, strings.Fields(data)) {
				t.Fatalf("tokens differ, capacity%d input%q", capacity, data)
			}
		}
	}
}

func FuzzMountFieldsOriginalTokens(f *testing.F) {
	for _, data := range []string{"1 0 0:1 / /proc rw - proc proc rw", "a\u2003b", "\xff a\x00"} {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data string) {
		if len(data) > 65536 {
			t.Skip("original mount line bound")
		}
		var storage [16]string
		if !slices.Equal(mountFields(data, storage[:0]), strings.Fields(data)) {
			t.Fatal("original field sequence differs")
		}
	})
}

func BenchmarkMountFields(b *testing.B) {
	data := "1491 1425 0:35 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw"
	for _, name := range []string{"before_fields", "ascii_scratch"} {
		b.Run(name, func(b *testing.B) {
			var storage [16]string
			b.ReportAllocs()
			for b.Loop() {
				var fields []string
				if name == "before_fields" {
					fields = strings.Fields(data)
				} else {
					fields = mountFields(data, storage[:0])
				}
				if len(fields) != 10 {
					b.Fatal(len(fields))
				}
			}
		})
	}
}

// Frozen original parser; only field collection differs from production.
func mountLayoutFieldsBefore(data []byte, rootID uint64, paths []string) bool {
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
		fields := strings.Fields(line)
		if len(fields) < 10 {
			return false
		}
		id, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || id == 0 {
			return false
		}
		separator := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				separator = i
				break
			}
		}
		if separator < 6 || len(fields) != separator+4 {
			return false
		}
		root, ok := mountUnescape(fields[3])
		if !ok {
			return false
		}
		point, ok := mountUnescape(fields[4])
		if !ok || !strings.HasPrefix(point, "/") {
			return false
		}
		if id == rootID {
			if rootSeen || root != "/" || point != "/proc" || fields[separator+1] != "proc" {
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

func BenchmarkMountLayoutFields(b *testing.B) {
	for _, count := range []int{24, 257} {
		var image strings.Builder
		image.WriteString("1 0 0:1 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n")
		for i := 1; i < count; i++ {
			image.WriteString(strconv.Itoa(i+1) + " 0 0:2 / /unrelated/" + strconv.Itoa(i) + " rw,nosuid,nodev,relatime shared:1 - tmpfs tmpfs rw,size=1024k\n")
		}
		data := []byte(image.String())
		paths := []string{"/proc/self", "/proc/thread-self", "/proc/123", "/proc/123/task/456/ns", "/proc/123/fdinfo", "/proc/sys/kernel/random/boot_id"}
		for _, sample := range []struct {
			name  string
			parse func([]byte, uint64, []string) bool
		}{{"before_fields", mountLayoutFieldsBefore}, {"ascii_scratch", mountLayoutOK}} {
			b.Run(strconv.Itoa(count)+"/"+sample.name, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if !sample.parse(data, 1, paths) {
						b.Fatal("valid complete captured image refused")
					}
				}
			})
		}
	}
}
