# Original bounded tool output copy storage candidate

Source audit: local pinned Go1.26 distribution at C:/Projects/RAZVILKA/tools/go/src.

- os/exec/exec.go:580 writerDescriptor(*output): creates actual pipe and registers goroutine io.Copy(w, pr), then closes original pipe. Cmd retains Start/Wait and cancellation.
- os/file.go:265 WriteTo: Linux zero-copy candidate then genericWriteTo if unsupported.
- os/zero_copy_linux.go:18,124: private *output lacks syscall.Conn, so no zero-copy handoff.
- os/file.go:294 genericWriteTo hides File.WriteTo using fileWithoutWriteTo, then io.Copy reaches destination.ReaderFrom.
- io/io.go:407: source WriterTo first; destination ReaderFrom next; default 32KiB buffer, with exact LimitedReader min32KiB,N/min1 sizing.

Actual6df managed manual profile:240.86MB cumulative io.copyBuffer,196.50MB File.WriteTo edge (81.58%). This does not attribute all196.50MB to version children. Actual measured1240 IP child Starts each use two original bounded *output streams and therefore this audited pipe-copy path; larger inventory/tool streams use it too.

Candidate adds only private output.ReadFrom. It calls io.CopyBuffer with writer-only destination and original source. Every existing output.Write lock/bounds/error/cancel path and subprocess Start/Wait/metadata observation remains unchanged. Each synchronous borrower owns one32KiB scratch, clears full buffer before returning it, including error/panic. Pool holds no descriptors, identities, results or output references. stdout/stderr remain separate at every unchanged callsite; combined existing output retains its mutex.

Tests: deterministic chunk/read-error/write-error/EOF/output-limit cancellation parity; source WriterTo precedence; error/panic clearing; concurrent combined writer; actual child pipes for large/exact-bound/overflow/canceled cases with joined ProcessState and sole-Wait refusal. Paired normal/race microbenchmark and actualchild benchmark needed. No localGo builds allowed; native and full lifecycle evidence pending. Pool random race drops and32KiB zeroing may trade CPU for allocation; no improvement claim yet.
