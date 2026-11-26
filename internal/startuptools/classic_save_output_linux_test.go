//go:build linux && (amd64 || arm64)

package startuptools

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

func classicSaveTestWriter(w *classicSaveOutput, pooled bool) io.Writer {
	if pooled {
		return w
	}
	return outputWriterOnly{w}
}

func TestOutputReaderClassicSaveCopyParity(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		size, chunk, limit, budget int
		final                      error
		limited                    int64
	}{
		{"large", 98317, 32768, 100000, 100000, io.EOF, -1},
		{"partial-error", 17, 5, 100, 100, outputReadFailure, -1},
		{"sink-refusal-before-read-error", 17, 32768, 16, 100, outputReadFailure, -1},
		{"shared-refusal-before-read-error", 17, 32768, 100, 16, outputReadFailure, -1},
		{"exact", 65536, 32768, 65536, 65536, io.EOF, -1},
		{"overflow", 65537, 32768, 100000, 65536, io.EOF, -1},
		{"limited-short", 99, 32768, 100, 100, io.EOF, 7},
		{"limited-zero", 99, 32768, 100, 100, io.EOF, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			type outcome struct {
				n                      int64
				err, data              string
				remaining, cancels     int
				overflow, sinkOverflow bool
				reads                  []int
			}
			run := func(pooled bool) outcome {
				got := outcome{}
				cancel := func() { got.cancels++ }
				budget := &classicSaveBudget{remaining: tc.budget, cancel: cancel}
				sink := &output{limit: tc.limit, cancel: cancel}
				r := &outputChunkReader{remaining: tc.size, chunk: tc.chunk, final: tc.final}
				var src io.Reader = r
				if tc.limited >= 0 {
					src = io.LimitReader(r, tc.limited)
				}
				var err error
				got.n, err = io.Copy(classicSaveTestWriter(&classicSaveOutput{sink, budget}, pooled), src)
				if err != nil {
					got.err = err.Error()
				}
				got.data, got.remaining, got.overflow, got.sinkOverflow, got.reads = string(sink.data), budget.remaining, budget.overflow, sink.overflow, r.reads
				return got
			}
			before, after := run(false), run(true)
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("shared debit/copy changed: before=%+v after=%+v", before, after)
			}
		})
	}
}

func TestOutputReaderClassicSaveWriterToCannotBypassBudget(t *testing.T) {
	for _, direct := range []bool{false, true} {
		budget := &classicSaveBudget{remaining: 17, cancel: func() {}}
		w := &classicSaveOutput{&output{limit: 100}, budget}
		r := &outputFastReader{}
		var n int64
		var err error
		if direct {
			n, err = w.ReadFrom(r)
		} else {
			n, err = io.Copy(w, r)
		}
		if !r.called || n != 0 || err == nil || !budget.overflow || budget.remaining != 17 || len(w.sink.data) != 0 {
			t.Fatal("fast path bypassed wrapper", n, err)
		}
	}
	budget := &classicSaveBudget{remaining: 3, cancel: func() {}}
	w := &classicSaveOutput{&output{limit: 100}, budget}
	if n, err := io.Copy(w, strings.NewReader("four")); n != 0 || err == nil || !budget.overflow {
		t.Fatal("WriteString bypassed shared cap", n, err)
	}
}

func TestOutputReaderClassicSaveClearsScratch(t *testing.T) {
	for _, panics := range []bool{false, true} {
		r := &outputScratchReader{panicRead: panics}
		func() {
			defer func() {
				got := recover()
				if panics && got != "original read panic" || !panics && got != nil {
					t.Fatalf("panic changed:%v", got)
				}
			}()
			_, err := (&classicSaveOutput{&output{limit: 10}, &classicSaveBudget{remaining: 10, cancel: func() {}}}).ReadFrom(r)
			if !errors.Is(err, outputReadFailure) {
				t.Fatal(err)
			}
		}()
		if len(r.held) != 32768 || !bytes.Equal(r.held, make([]byte, 32768)) {
			t.Fatal("shared scratch retained bytes")
		}
	}
}

func TestOutputReaderClassicSaveActualFamilies(t *testing.T) {
	for _, pooled := range []bool{false, true} {
		for _, limit := range []int{320, 240} {
			t.Run(map[bool]string{false: "before", true: "after"}[pooled]+"/"+map[int]string{320: "exact", 240: "overflow"}[limit], func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				budget := &classicSaveBudget{remaining: limit, cancel: cancel}
				total := 0
				for family := 0; family < 2; family++ {
					out, errOut := &output{limit: 256, cancel: cancel}, &output{limit: 256, cancel: cancel}
					cmd := outputReaderCommand(ctx, "version", classicSaveTestWriter(&classicSaveOutput{out, budget}, pooled), classicSaveTestWriter(&classicSaveOutput{errOut, budget}, pooled))
					err := cmd.Run()
					if cmd.ProcessState == nil || cmd.Wait() == nil {
						t.Fatal("actual child not joined once", err)
					}
					total += len(out.data) + len(errOut.data)
					if limit == 240 && family == 1 {
						if err == nil || ctx.Err() != context.Canceled || !budget.overflow || total != 240 || budget.remaining != 0 {
							t.Fatal("second family bypassed shared budget", err, total, budget.remaining)
						}
					} else if err != nil || string(out.data) != strings.Repeat("o", 80) || string(errOut.data) != strings.Repeat("e", 80) {
						t.Fatal("separate original streams changed", err)
					}
				}
				if limit == 320 && (total != 320 || budget.remaining != 0 || budget.overflow) {
					t.Fatal("exact family budget changed")
				}
			})
		}
	}
}

func TestOutputReaderClassicSaveActualCancellationJoins(t *testing.T) {
	for _, pooled := range []bool{false, true} {
		t.Run(map[bool]string{false: "before", true: "after"}[pooled], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			budget := &classicSaveBudget{remaining: 100, cancel: cancel}
			out, errOut := &output{limit: 100, cancel: cancel}, &output{limit: 100, cancel: cancel}
			joined := make(chan struct{})
			go func() {
				defer close(joined)
				tick := time.NewTicker(time.Millisecond)
				defer tick.Stop()
				for {
					out.mu.Lock()
					seen := len(out.data) > 0
					out.mu.Unlock()
					if seen {
						cancel()
						return
					}
					select {
					case <-ctx.Done():
						return
					case <-tick.C:
					}
				}
			}()
			cmd := outputReaderCommand(ctx, "hold", classicSaveTestWriter(&classicSaveOutput{out, budget}, pooled), classicSaveTestWriter(&classicSaveOutput{errOut, budget}, pooled))
			err := cmd.Run()
			<-joined
			if err == nil || ctx.Err() != context.Canceled || cmd.ProcessState == nil || cmd.Wait() == nil || len(out.data) == 0 || budget.overflow || len(out.data)+len(errOut.data)+budget.remaining != 100 {
				t.Fatal("cancellation lost joined child or shared debit", err)
			}
		})
	}
}

func BenchmarkClassicSaveOutputChild(b *testing.B) {
	for _, pooled := range []bool{false, true} {
		b.Run(map[bool]string{false: "before", true: "after"}[pooled], func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				budget := &classicSaveBudget{remaining: 320, cancel: cancel}
				for family := 0; family < 2; family++ {
					out, errOut := &output{limit: 256, cancel: cancel}, &output{limit: 256, cancel: cancel}
					cmd := outputReaderCommand(ctx, "version", classicSaveTestWriter(&classicSaveOutput{out, budget}, pooled), classicSaveTestWriter(&classicSaveOutput{errOut, budget}, pooled))
					err := cmd.Run()
					if err != nil || cmd.ProcessState == nil || len(out.data) != 80 || len(errOut.data) != 80 {
						cancel()
						b.Fatal("actual family child", err)
					}
				}
				cancel()
				if budget.remaining != 0 || budget.overflow {
					b.Fatal("actual family aggregate budget")
				}
			}
		})
	}
}
