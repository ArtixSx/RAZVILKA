package startuptools

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

var outputReadFailure = errors.New("original partial read failure")

type outputChunkReader struct {
	remaining int
	chunk     int
	final     error
	reads     []int
}

func (r *outputChunkReader) Read(p []byte) (int, error) {
	r.reads = append(r.reads, len(p))
	n := min(len(p), r.chunk, r.remaining)
	for i := 0; i < n; i++ {
		p[i] = 'x'
	}
	r.remaining -= n
	if r.remaining == 0 {
		return n, r.final
	}
	return n, nil
}

func TestOutputReaderCopyParity(t *testing.T) {
	for _, tc := range []struct {
		name               string
		size, chunk, limit int
		last               error
		limited            int64
	}{
		{"large", 98317, 32768, 100000, io.EOF, -1},
		{"partial-error", 17, 5, 100, outputReadFailure, -1},
		{"write-before-read-error", 17, 32768, 16, outputReadFailure, -1},
		{"exact-limit", 65536, 32768, 65536, io.EOF, -1},
		{"overflow", 65537, 32768, 65536, io.EOF, -1},
		{"empty", 0, 32768, 0, io.EOF, -1},
		{"limited-short", 99, 32768, 100, io.EOF, 7},
		{"limited-zero", 99, 32768, 100, io.EOF, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			type outcome struct {
				n        int64
				err      string
				data     string
				overflow bool
				cancels  int
				reads    []int
			}
			run := func(pooled bool) outcome {
				r := &outputChunkReader{remaining: tc.size, chunk: tc.chunk, final: tc.last}
				var source io.Reader = r
				if tc.limited >= 0 {
					source = io.LimitReader(r, tc.limited)
				}
				got := outcome{}
				out := &output{limit: tc.limit, cancel: func() { got.cancels++ }}
				var destination io.Writer = outputWriterOnly{out}
				if pooled {
					destination = out
				}
				var err error
				got.n, err = io.Copy(destination, source)
				if err != nil {
					got.err = err.Error()
				}
				got.data, got.overflow, got.reads = string(out.data), out.overflow, r.reads
				return got
			}
			before, after := run(false), run(true)
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("copy behavior changed: before=%+v after=%+v", before, after)
			}
		})
	}
}

type outputFastReader struct{ called bool }

func (*outputFastReader) Read([]byte) (int, error) { panic("WriterTo precedence lost") }
func (r *outputFastReader) WriteTo(w io.Writer) (int64, error) {
	r.called = true
	n, err := w.Write([]byte("original fast path"))
	return int64(n), err
}

func TestOutputReaderPreservesWriterTo(t *testing.T) {
	for _, direct := range []bool{false, true} {
		r, w := &outputFastReader{}, &output{limit: 100}
		var n int64
		var err error
		if direct {
			n, err = w.ReadFrom(r)
		} else {
			n, err = io.Copy(w, r)
		}
		if err != nil || n != 18 || !r.called || string(w.data) != "original fast path" {
			t.Fatal(n, err, r.called, string(w.data))
		}
	}
}

type outputScratchReader struct {
	held      []byte
	panicRead bool
}

func (r *outputScratchReader) Read(p []byte) (int, error) {
	r.held = p
	for i := range p {
		p[i] = 0xa7
	}
	if r.panicRead {
		panic("original read panic")
	}
	return 0, outputReadFailure
}

func TestOutputReaderClearsOnErrorAndPanic(t *testing.T) {
	for _, panics := range []bool{false, true} {
		r := &outputScratchReader{panicRead: panics}
		func() {
			defer func() {
				got := recover()
				if panics && got != "original read panic" || !panics && got != nil {
					t.Fatalf("panic changed: %v", got)
				}
			}()
			_, err := (&output{limit: 10}).ReadFrom(r)
			if !errors.Is(err, outputReadFailure) {
				t.Fatal(err)
			}
		}()
		// No other borrower runs until this assertion; the slice is test-only.
		if len(r.held) != 32768 || !bytes.Equal(r.held, make([]byte, 32768)) {
			t.Fatal("scratch retained source bytes")
		}
	}
}

func TestOutputReaderConcurrentCombinedWriter(t *testing.T) {
	w := &output{limit: 16 * 65536}
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			r := &outputChunkReader{remaining: 65536, chunk: 8192, final: io.EOF}
			if n, err := w.ReadFrom(r); err != nil || n != 65536 {
				t.Error(n, err)
			}
		}()
	}
	workers.Wait()
	if len(w.data) != w.limit || w.overflow {
		t.Fatal("combined output changed")
	}
}

func TestOutputReaderChild(t *testing.T) {
	mode := os.Getenv("RAZVILKA_OUTPUT_READER_TEST_CHILD")
	if mode == "" {
		return
	}
	size := 98317
	if mode == "hold" {
		size = 5
	}
	if mode == "version" {
		size = 80
	}
	_, a := os.Stdout.Write(bytes.Repeat([]byte{'o'}, size))
	_, b := os.Stderr.Write(bytes.Repeat([]byte{'e'}, size))
	if a != nil || b != nil {
		os.Exit(9)
	}
	if mode == "hold" {
		time.Sleep(30 * time.Second)
	}
	os.Exit(0)
}

func outputReaderCommand(ctx context.Context, mode string, stdout, stderr io.Writer) *exec.Cmd {
	c := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOutputReaderChild$")
	c.Env = append(os.Environ(), "RAZVILKA_OUTPUT_READER_TEST_CHILD="+mode)
	c.Stdout, c.Stderr, c.WaitDelay = stdout, stderr, 100*time.Millisecond
	return c
}

func TestOutputReaderActualChild(t *testing.T) {
	for _, pooled := range []bool{false, true} {
		for _, mode := range []string{"large", "exact", "overflow", "hold"} {
			t.Run(map[bool]string{false: "before", true: "after"}[pooled]+"/"+mode, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				limit := 100000
				if mode == "exact" {
					limit = 98317
				}
				if mode == "overflow" {
					limit = 256
				}
				out, errOut := &output{limit: limit, cancel: cancel}, &output{limit: limit, cancel: cancel}
				var stdout, stderr io.Writer = outputWriterOnly{out}, outputWriterOnly{errOut}
				if pooled {
					stdout, stderr = out, errOut
				}
				cmd := outputReaderCommand(ctx, mode, stdout, stderr)
				joined := make(chan struct{})
				if mode == "hold" {
					go func() {
						defer close(joined)
						ticker := time.NewTicker(time.Millisecond)
						defer ticker.Stop()
						for {
							out.mu.Lock()
							received := len(out.data) != 0
							out.mu.Unlock()
							if received {
								cancel()
								return
							}
							select {
							case <-ctx.Done():
								return
							case <-ticker.C:
							}
						}
					}()
				} else {
					close(joined)
				}
				err := cmd.Run()
				<-joined
				if cmd.Process == nil || cmd.ProcessState == nil {
					t.Fatal("actual child not joined", err)
				}
				if second := cmd.Wait(); second == nil {
					t.Fatal("sole Wait was not retained")
				}
				switch mode {
				case "large", "exact":
					if err != nil || out.overflow || errOut.overflow || string(out.data) != strings.Repeat("o", 98317) || string(errOut.data) != strings.Repeat("e", 98317) {
						t.Fatal("actual separate streams changed", err, len(out.data), len(errOut.data))
					}
				case "overflow":
					if err == nil || ctx.Err() == nil || !out.overflow || len(out.data) > limit || len(errOut.data) > limit {
						t.Fatal("overflow did not cancel/join", err)
					}
				case "hold":
					if err == nil || !errors.Is(ctx.Err(), context.Canceled) || len(out.data) == 0 {
						t.Fatal("canceled child not joined", err, ctx.Err())
					}
				}
			})
		}
	}
}

func BenchmarkOutputReader(b *testing.B) {
	for _, pooled := range []bool{false, true} {
		b.Run(map[bool]string{false: "before", true: "after"}[pooled], func(b *testing.B) {
			w := &output{limit: 256, data: make([]byte, 0, 256)}
			var destination io.Writer = outputWriterOnly{w}
			if pooled {
				destination = w
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				w.data = w.data[:0]
				r := &outputChunkReader{remaining: 80, chunk: 32768, final: io.EOF}
				if _, err := io.Copy(destination, r); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkOutputReaderChild(b *testing.B) {
	for _, pooled := range []bool{false, true} {
		b.Run(map[bool]string{false: "before", true: "after"}[pooled], func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				out, errOut := &output{limit: 256, cancel: cancel}, &output{limit: 256, cancel: cancel}
				var stdout, stderr io.Writer = outputWriterOnly{out}, outputWriterOnly{errOut}
				if pooled {
					stdout, stderr = out, errOut
				}
				cmd := outputReaderCommand(ctx, "version", stdout, stderr)
				err := cmd.Run()
				cancel()
				if err != nil || cmd.ProcessState == nil || len(out.data) != 80 || len(errOut.data) != 80 {
					b.Fatal("actual child copy", err)
				}
			}
		})
	}
}
