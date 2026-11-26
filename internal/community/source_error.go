package community

// SourceError identifies the failed part without exposing URLs or response data.
// A failed required part must not produce an importable partial service.
type SourceError struct {
	Part string
	Err  error
}

func (e *SourceError) Error() string { return e.Part + " source: " + e.Err.Error() }
func (e *SourceError) Unwrap() error { return e.Err }
