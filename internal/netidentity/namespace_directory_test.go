package netidentity

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

//go:embed parse.go
var namespaceDirectoryParserSource string

//go:embed namespace_directory_linux.go
var namespaceDirectoryFDSource string

//go:embed namespace_directory_test.go
var namespaceDirectoryTestSource string

// Frozen original body; both Linux measurement and fault parity use this
// actual pre-refactor implementation, not the new shared parser as baseline.
func namespaceDirectoryOriginal(ctx context.Context, read func([]byte) (int, error)) ([]string, bool, bool, bool) {
	names := []string{}
	seen := map[string]bool{}
	unknown, dot, dotdot := false, false, false
	buf := make([]byte, 4096)
	total := 0
	var cookie uint64
	for calls := 0; calls < maxDirectoryCalls; calls++ {
		if ctx.Err() != nil || total >= maxDirectoryBytes {
			return names, unknown, false, false
		}
		chunk := buf
		if remaining := maxDirectoryBytes - total; remaining < len(chunk) {
			chunk = chunk[:remaining]
		}
		n, err := read(chunk)
		if err != nil || n < 0 || n > len(chunk) {
			return names, unknown, false, false
		}
		if n == 0 {
			return names, unknown, true, dot && dotdot
		}
		total += n
		for off := 0; off < n; {
			if n-off < 20 {
				return names, unknown, false, false
			}
			recordLength := int(binary.LittleEndian.Uint16(chunk[off+16 : off+18]))
			if recordLength < 24 || recordLength%8 != 0 || recordLength > n-off {
				return names, unknown, false, false
			}
			record := chunk[off : off+recordLength]
			next := binary.LittleEndian.Uint64(record[8:16])
			if next != cookie+1 {
				return names, unknown, false, false
			}
			cookie = next
			end := bytes.IndexByte(record[19:], 0)
			if end < 1 || end > 64 {
				return names, unknown, false, false
			}
			name := string(record[19 : 19+end])
			if seen[name] {
				return names, unknown, false, false
			}
			seen[name] = true
			switch name {
			case ".":
				if cookie != 1 {
					return names, unknown, false, false
				}
				dot = true
			case "..":
				if cookie != 2 {
					return names, unknown, false, false
				}
				dotdot = true
			default:
				if !dot || !dotdot || len(names) >= maxNames {
					return names, unknown, false, false
				}
				for i := 0; i < len(name); i++ {
					b := name[i]
					if !((b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_') {
						return names, unknown, false, false
					}
				}
				names = append(names, name)
				if record[18] == 0 {
					unknown = true
				}
			}
			off += recordLength
		}
	}
	return names, unknown, false, false
}

func namespaceDirectoryFunction(t *testing.T, source, name string) string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "source.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == name {
			var b bytes.Buffer
			if err := format.Node(&b, fset, fn); err != nil {
				t.Fatal(err)
			}
			return b.String()
		}
	}
	t.Fatal("missing function", name)
	return ""
}

func namespaceDirectoryFormat(t *testing.T, source string) string {
	t.Helper()
	b, err := format.Source([]byte("package p\n" + source))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(strings.TrimPrefix(string(b), "package p"))
}

func TestNamespaceDirectorySourceParity(t *testing.T) {
	old := namespaceDirectoryFunction(t, namespaceDirectoryTestSource, "namespaceDirectoryOriginal")
	old = strings.Replace(old, "namespaceDirectoryOriginal", "readNamespaceDirectory", 1)
	digest := sha256.Sum256([]byte(old))
	if hex.EncodeToString(digest[:]) != "19539364b80a7126dcdb51c68a99575dfa42a356cbeb87b0aaff940fae890304" {
		t.Fatalf("original body changed: %x", digest)
	}
	current := namespaceDirectoryFunction(t, namespaceDirectoryParserSource, "readNamespaceDirectory")
	consume := namespaceDirectoryFunction(t, namespaceDirectoryParserSource, "consume")
	start := strings.Index(consume, "\n\tfor off :=")
	end := strings.LastIndex(consume, "\n\treturn true")
	if start < 0 || end < start {
		t.Fatal("parser extraction shape")
	}
	chunk := consume[start+1 : end]
	for _, field := range []string{"names", "seen", "unknown", "dotdot", "dot", "cookie"} {
		chunk = strings.ReplaceAll(chunk, "s."+field, field)
	}
	chunk = strings.ReplaceAll(chunk, "return false", "return names, unknown, false, false")
	current = strings.Replace(current, "state := newNamespaceDirectoryState()", "names := []string{}\nseen := map[string]bool{}\nunknown, dot, dotdot := false, false, false", 1)
	current = strings.Replace(current, "total := 0", "total := 0\nvar cookie uint64", 1)
	needle := "if !state.consume(chunk, n) {\n\t\t\treturn state.names, state.unknown, false, false\n\t\t}"
	if strings.Count(current, needle) != 1 {
		t.Fatal("loop extraction shape")
	}
	current = strings.Replace(current, needle, chunk, 1)
	current = strings.ReplaceAll(current, "state.", "")
	if namespaceDirectoryFormat(t, current) != namespaceDirectoryFormat(t, old) {
		t.Fatal("original parser/order/bounds changed")
	}
	fd := namespaceDirectoryFunction(t, namespaceDirectoryFDSource, "readNamespaceDirectoryFD")
	fd = strings.Replace(fd, "readNamespaceDirectoryFD(ctx context.Context, fd int)", "readNamespaceDirectory(ctx context.Context, read func([]byte) (int, error))", 1)
	fd = strings.Replace(fd, "syscall.ReadDirent(fd, chunk)", "read(chunk)", 1)
	if fd != namespaceDirectoryFunction(t, namespaceDirectoryParserSource, "readNamespaceDirectory") {
		t.Fatal("fixed FD changed more than dispatch")
	}
}

type namespaceDirectoryResult struct {
	names                    []string
	unknown, complete, valid bool
}

func namespaceDirectoryRun(ctx context.Context, read func([]byte) (int, error), original bool) namespaceDirectoryResult {
	var r namespaceDirectoryResult
	if original {
		r.names, r.unknown, r.complete, r.valid = namespaceDirectoryOriginal(ctx, read)
	} else {
		r.names, r.unknown, r.complete, r.valid = readNamespaceDirectory(ctx, read)
	}
	return r
}

func TestNamespaceDirectoryParserContracts(t *testing.T) {
	good := append(dirent(".", 1, 1, 4), dirent("..", 2, 1, 4)...)
	good = append(good, dirent("net", 3, 0, 0)...)
	good = append(good, dirent("mnt", 4, 1, 10)...)
	type fault struct {
		chunks              [][]byte
		final               error
		n                   int
		cancelAt            int
		override, cancelled bool
	}
	cases := map[string]fault{
		"good": {chunks: [][]byte{good}}, "split": {chunks: [][]byte{good[:48], good[48:]}},
		"empty": {}, "error": {chunks: [][]byte{good}, final: errors.New("read")},
		"negative": {override: true, n: -1}, "oversize": {override: true, n: 4097}, "cancelled": {cancelled: true},
		"cancel-in-read": {chunks: [][]byte{good}, cancelAt: 1}, "cancel-in-eof": {chunks: [][]byte{good}, cancelAt: 2},
		"bytes-and-error": {override: true, n: 1, final: errors.New("read")},
	}
	for i := range good {
		b := bytes.Clone(good)
		b[i] ^= 0xff
		cases["mutated-"+strconv.Itoa(i)] = fault{chunks: [][]byte{b}}
	}
	var many [][]byte
	for i := 0; i < 66; i++ {
		name := "x" + strconv.Itoa(i)
		if i == 0 {
			name = "."
		}
		if i == 1 {
			name = ".."
		}
		many = append(many, dirent(name, uint64(i+1), 1, 10))
	}
	cases["call-bound"] = fault{chunks: many}
	// Oversized padded records exercise the byte ceiling without reaching the name cap.
	var large [][]byte
	for i := 0; i < 16; i++ {
		b := make([]byte, 4096)
		name := "x" + strconv.Itoa(i)
		if i == 0 {
			name = "."
		}
		if i == 1 {
			name = ".."
		}
		copy(b, dirent(name, uint64(i+1), 1, 10))
		binary.LittleEndian.PutUint16(b[16:], 4096)
		large = append(large, b)
	}
	cases["byte-bound"] = fault{chunks: large}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			var results [2]namespaceDirectoryResult
			var counts [2]int
			for variant := range 2 {
				ctx, cancel := context.WithCancel(context.Background())
				if f.cancelled {
					cancel()
				}
				reader := func(buf []byte) (int, error) {
					counts[variant]++
					if counts[variant] == f.cancelAt {
						cancel()
					}
					if f.override {
						return f.n, f.final
					}
					i := counts[variant] - 1
					if i < len(f.chunks) {
						return copy(buf, f.chunks[i]), nil
					}
					return 0, f.final
				}
				results[variant] = namespaceDirectoryRun(ctx, reader, variant == 0)
				cancel()
			}
			if !reflect.DeepEqual(results[0], results[1]) || counts[0] != counts[1] {
				t.Fatal("original/result/read count drift", results, counts)
			}
			if name == "good" || name == "split" {
				if !results[1].valid || !results[1].complete || !results[1].unknown {
					t.Fatal("positive refused")
				}
			}
			if name == "call-bound" && counts[1] != 64 || name == "byte-bound" && counts[1] != 16 {
				t.Fatal("bound read count", counts)
			}
		})
	}
}

func TestNamespaceDirectoryCallbackIsolation(t *testing.T) {
	data := append(append(dirent(".", 1, 1, 4), dirent("..", 2, 1, 4)...), dirent("net", 3, 1, 0)...)
	var retained [][]byte
	var outputs [][]string
	for range 2 {
		calls := 0
		names, unknown, complete, valid := readNamespaceDirectory(context.Background(), func(buf []byte) (int, error) {
			calls++
			if calls == 1 {
				retained = append(retained, buf)
				return copy(buf, data), nil
			}
			clear(buf)
			return 0, nil
		})
		if !unknown || !complete || !valid || !reflect.DeepEqual(names, []string{"net"}) {
			t.Fatal("reused input changed owned name")
		}
		outputs = append(outputs, names)
	}
	if &retained[0][0] == &retained[1][0] {
		t.Fatal("generic callback buffers shared")
	}
	for _, buf := range retained {
		for i := range buf {
			buf[i] = 'z'
		}
	}
	if !reflect.DeepEqual(outputs, [][]string{{"net"}, {"net"}}) {
		t.Fatal("returned names alias scratch")
	}
}
