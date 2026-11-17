package startuptools

import (
	"io"
	"sync"
)

// Only transient copy storage: no child, descriptor, output or observation is
// retained. Each synchronous reader exclusively owns and clears its scratch.
var outputCopyScratch = sync.Pool{New: func() any { return new([32 * 1024]byte) }}

// Hide ReadFrom to avoid recursively dispatching back from io.CopyBuffer.
// Keep the original reader's WriterTo fast path and the existing Write method.
type outputWriterOnly struct{ io.Writer }

// ReadFrom lets os/exec's original pipe copier reuse its temporary storage.
// Start, pipe ownership, cancellation and the sole Wait remain with os/exec.
func (w *output) ReadFrom(r io.Reader) (int64, error) {
	scratch := outputCopyScratch.Get().(*[32 * 1024]byte)
	defer func() {
		clear(scratch[:])
		outputCopyScratch.Put(scratch)
	}()
	size := len(scratch)
	// Match io.copyBuffer's initial slice even for direct LimitedReader calls.
	if limited, ok := r.(*io.LimitedReader); ok && int64(size) > limited.N {
		if limited.N < 1 {
			size = 1
		} else {
			size = int(limited.N)
		}
	}
	return io.CopyBuffer(outputWriterOnly{w}, r, scratch[:size])
}
