package app

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// The embedded panel is about 2 MB in 42 files and compresses to about a
// third. The files never change while the process runs, so each compressed
// body is built once per path. Ranges, other methods and non-text types pass
// through unchanged.
type gzipStaticCache struct {
	mu    sync.Mutex
	items map[string]gzipStaticItem
}

type gzipStaticItem struct {
	body        []byte
	contentType string
}

const gzipStaticMaxBody = 4 << 20

func gzipStatic(next http.Handler) http.Handler {
	cache := &gzipStaticCache{items: map[string]gzipStaticItem{}}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead || r.Header.Get("Range") != "" || !acceptsGzip(r.Header.Get("Accept-Encoding")) {
			next.ServeHTTP(w, r)
			return
		}
		key := r.URL.Path
		cache.mu.Lock()
		item, ok := cache.items[key]
		cache.mu.Unlock()
		if !ok {
			recorder := &staticRecorder{header: http.Header{}, status: http.StatusOK}
			next.ServeHTTP(recorder, r.Clone(r.Context()))
			contentType := recorder.header.Get("Content-Type")
			if recorder.overflow {
				next.ServeHTTP(w, r)
				return
			}
			if recorder.status != http.StatusOK || !compressibleType(contentType) || r.Method == http.MethodHead {
				recorder.replay(w)
				return
			}
			var compressed bytes.Buffer
			zw, _ := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
			_, _ = zw.Write(recorder.body.Bytes())
			if zw.Close() != nil {
				recorder.replay(w)
				return
			}
			item = gzipStaticItem{body: compressed.Bytes(), contentType: contentType}
			cache.mu.Lock()
			cache.items[key] = item
			cache.mu.Unlock()
		}
		h := w.Header()
		h.Set("Content-Type", item.contentType)
		h.Set("Content-Encoding", "gzip")
		h.Add("Vary", "Accept-Encoding")
		h.Set("Content-Length", strconv.Itoa(len(item.body)))
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(item.body)
		}
	})
}

func acceptsGzip(value string) bool {
	for _, part := range strings.Split(value, ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if !strings.EqualFold(strings.TrimSpace(name), "gzip") {
			continue
		}
		for _, param := range strings.Split(params, ";") {
			if key, raw, ok := strings.Cut(strings.TrimSpace(param), "="); ok && strings.EqualFold(key, "q") {
				q, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
				return err == nil && q > 0
			}
		}
		return true
	}
	return false
}

func compressibleType(value string) bool {
	value = strings.ToLower(value)
	for _, prefix := range []string{"text/", "application/javascript", "application/json", "image/svg+xml"} {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

// staticRecorder captures one embedded file response, bounded by size.
type staticRecorder struct {
	header   http.Header
	status   int
	body     bytes.Buffer
	overflow bool
}

func (s *staticRecorder) Header() http.Header    { return s.header }
func (s *staticRecorder) WriteHeader(status int) { s.status = status }
func (s *staticRecorder) Write(p []byte) (int, error) {
	if s.body.Len()+len(p) > gzipStaticMaxBody {
		s.overflow = true
		return len(p), nil
	}
	return s.body.Write(p)
}

func (s *staticRecorder) replay(w http.ResponseWriter) {
	for key, values := range s.header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(s.status)
	_, _ = w.Write(s.body.Bytes())
}
