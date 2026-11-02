# Compatibility hash byte scratch

Source `ef8df297`; integrated source `6fefa0bc`. An exclusive cleared32KiB buffer replaces the temporary `io.Copy` allocation. Every compatibility check still opens and hashes the whole file and performs the same size/EOF and original FD/path checks. No digest, descriptor, permission or result is retained.

Go1.26.5, Windows AMD64, Ryzen7 7800X3D; one command ran three samples per variant on the same machine. The65,537-byte memory-copy/hash benchmark measured32,968→200–201 allocated bytes/op,4→3 allocations/op and33.595–33.805→29.987–30.433 microseconds/op. These are microbenchmark results; full native workflow acceleration or router RAM reduction is not established. [All samples](results.json).

Validation: concurrent actual file writes and fresh hashes around32KiB boundaries, oversize refusal, preservation of the original partial-read error and full scratch clearing passed. Existing compatibility file/asset tests also ran. Linux tagged vet passed; Linux race and complete native measurements run in CI.

Reproduce from the repository with `go test ./internal/strategylab -run 'TestCompatibilityFileScratch|TestCompatibilitySupervised' -bench '^BenchmarkCompatibilityFileCopyScratch$' -benchmem -count=3`.
