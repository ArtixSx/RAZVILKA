//go:build linux && (amd64 || arm64)

package netidentity

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
)

// Frozen original stat parser, including values returned alongside false.
func taskStartParseBefore(data []byte, tid int) (uint64, bool) {
	text := string(data)
	left, right := strings.IndexByte(text, '('), strings.LastIndex(text, ") ")
	if left < 1 || right <= left {
		return 0, false
	}
	actual, err := strconv.Atoi(strings.TrimSpace(text[:left]))
	if err != nil || actual != tid {
		return 0, false
	}
	fields := strings.Fields(text[right+2:])
	if len(fields) < 20 {
		return 0, false
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	return start, err == nil
}

func taskStartParseImage(start string) []byte {
	return []byte("123 (worker (name) ) R " + strings.Repeat("0 ", 18) + start + " " + strings.Repeat("0 ", 30) + "\n")
}

func TestTaskStartParseParity(t *testing.T) {
	valid := taskStartParseImage("7654321")
	if value, ok := taskStartFromStat(valid, 123); !ok || value != 7654321 {
		t.Fatal("valid original field22", value, ok)
	}
	cases := [][]byte{nil, {}, []byte("123 (worker) "), valid, []byte("123 (worker) " + strings.Repeat("0 ", 19)), []byte("123 (worker) " + strings.Repeat("0 ", 20))}
	for _, number := range []string{"0", "+1", "-1", "01", "18446744073709551615", "18446744073709551616", "0x10", "1_0", "garbage", "1\x00", "١", ""} {
		cases = append(cases, taskStartParseImage(number))
	}
	for _, space := range []string{" ", "\t", "\n", "\v", "\f", "\r", "\u0085", "\u00a0", "\u2003", "\u2028", "\u3000"} {
		cases = append(cases, []byte("123 (worker) "+strings.ReplaceAll("R "+strings.Repeat("0 ", 18)+"7654321 "+strings.Repeat("0 ", 30), " ", space)))
		cases = append(cases, append([]byte(space), valid...))
	}
	for b := 0; b < 256; b++ {
		cases = append(cases, bytes.Replace(valid, []byte(" R "), []byte{' ', byte(b), ' '}, 1))
	}
	for _, pid := range []string{"123", "+123", "0123", "-123", "0", "9223372036854775808", "\xff123", "123\x00"} {
		cases = append(cases, append([]byte(pid), valid[3:]...))
	}
	for i, data := range cases {
		for _, tid := range []int{-123, 0, 123, 124} {
			want, wantOK := taskStartParseBefore(data, tid)
			got, gotOK := taskStartFromStat(data, tid)
			if got != want || gotOK != wantOK {
				t.Fatalf("case%d tid%d: (%d,%v), want (%d,%v)", i, tid, got, gotOK, want, wantOK)
			}
		}
	}
}

func FuzzTaskStartParseParity(f *testing.F) {
	for _, data := range [][]byte{taskStartParseImage("7654321"), taskStartParseImage("18446744073709551616"), []byte("123 (a) )\u2003R 0\xff")} {
		f.Add(data, 123)
	}
	f.Fuzz(func(t *testing.T, data []byte, tid int) {
		if len(data) > 16384 {
			t.Skip("original stat read bound")
		}
		want, wantOK := taskStartParseBefore(data, tid)
		got, gotOK := taskStartFromStat(data, tid)
		if got != want || gotOK != wantOK {
			t.Fatalf("(%d,%v), want (%d,%v)", got, gotOK, want, wantOK)
		}
	})
}

func BenchmarkTaskStartParse(b *testing.B) {
	for _, sample := range []struct {
		name  string
		parse func([]byte, int) (uint64, bool)
	}{{"before_fields", taskStartParseBefore}, {"bounded_fields", taskStartFromStat}} {
		b.Run(sample.name, func(b *testing.B) {
			data := taskStartParseImage("7654321")
			b.ReportAllocs()
			for b.Loop() {
				if value, ok := sample.parse(data, 123); !ok || value != 7654321 {
					b.Fatal(value, ok)
				}
			}
		})
	}
}
