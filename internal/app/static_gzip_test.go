package app

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestGzipStaticCompressesTextOnlyForGzipClients(t *testing.T) {
	script := strings.Repeat("function panel(){return 'razvilka';}\n", 400)
	files := fstest.MapFS{"app.js": {Data: []byte(script)}, "icon.png": {Data: bytes.Repeat([]byte{0x89, 'P', 'N', 'G'}, 300)}}
	h := gzipStatic(http.FileServer(http.FS(files)))
	get := func(path, encoding, rng string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		if encoding != "" {
			r.Header.Set("Accept-Encoding", encoding)
		}
		if rng != "" {
			r.Header.Set("Range", rng)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for i := 0; i < 2; i++ { // the second read comes from the cache
		w := get("/app.js?v=0.20.0", "gzip, deflate, br", "")
		if w.Code != 200 || w.Header().Get("Content-Encoding") != "gzip" || !strings.Contains(w.Header().Get("Vary"), "Accept-Encoding") || !strings.Contains(w.Header().Get("Content-Type"), "javascript") {
			t.Fatal(w.Code, w.Header())
		}
		zr, err := gzip.NewReader(w.Body)
		if err != nil {
			t.Fatal(err)
		}
		plain, _ := io.ReadAll(zr)
		if string(plain) != script || w.Body.Len() >= len(script) {
			t.Fatal("compressed body differs or is not smaller")
		}
	}
	for _, c := range []struct{ path, encoding, rng string }{{"/app.js", "", ""}, {"/app.js", "gzip;q=0", ""}, {"/app.js", "gzip", "bytes=0-9"}, {"/icon.png", "gzip", ""}} {
		w := get(c.path, c.encoding, c.rng)
		if w.Header().Get("Content-Encoding") != "" || w.Body.Len() == 0 {
			t.Fatal("unexpected compression", c, w.Header())
		}
	}
	if w := get("/missing.js", "gzip", ""); w.Code != http.StatusNotFound || w.Header().Get("Content-Encoding") != "" {
		t.Fatal("missing file", w.Code, w.Header())
	}
}
