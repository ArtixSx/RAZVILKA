package app

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func TestGzipStaticPreservesAPIAuthenticationAndOriginRefusal(t *testing.T) {
	a := panelTestApp(t)
	if err := a.Security.ConfigureCredentials(filepath.Join(t.TempDir(), "credentials.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Security.Setup("admin", "fixture-password"); err != nil {
		t.Fatal(err)
	}
	h := a.Handler(http.FileServer(http.FS(fstest.MapFS{"app.js": {Data: []byte("const panel=true;")}})))
	for _, tc := range []struct {
		method, target, origin string
		status                 int
	}{
		{http.MethodGet, "/nonce%2f..%2fapp.js", "", http.StatusOK},
		{http.MethodGet, "/missing.js", "", http.StatusNotFound},
		{http.MethodGet, "/api/v1/panel/doctor", "", http.StatusUnauthorized},
		{http.MethodPost, "/api/v1/self-update/apply", "https://foreign.invalid", http.StatusForbidden},
	} {
		r := httptest.NewRequest(tc.method, tc.target, strings.NewReader("{}"))
		r.Header.Set("Accept-Encoding", "gzip")
		if tc.method == http.MethodPost {
			r.Header.Set("Content-Type", "application/json")
		}
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("%s: got=%d want=%d", tc.target, w.Code, tc.status)
		}
		if tc.status == http.StatusOK {
			if w.Header().Get("Content-Encoding") != "gzip" || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
				t.Fatal(w.Header())
			}
		} else if w.Header().Get("Content-Encoding") != "" {
			t.Fatalf("error/auth response compressed: %s %v", tc.target, w.Header())
		}
	}
}

func TestGzipStaticCanonicalizesEscapedAliasesBeforeCaching(t *testing.T) {
	files := fstest.MapFS{"app.js": {Data: []byte(strings.Repeat("const panel='same embedded asset';\n", 100))}}
	fs := http.FileServer(http.FS(files))
	reads := 0
	mux := http.NewServeMux()
	mux.Handle("/", noStoreUI(gzipStatic(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads++
		fs.ServeHTTP(w, r)
	}))))
	for i := 0; i < 20; i++ {
		r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/nonce%d%%2f..%%2fapp.js?v=%d", i, i), nil)
		r.Header.Set("Accept-Encoding", "gzip")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusOK || w.Header().Get("Content-Encoding") != "gzip" || !strings.Contains(w.Header().Get("Vary"), "Accept-Encoding") || !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
			t.Fatalf("alias changed response policy: %d %v", w.Code, w.Header())
		}
	}
	if reads != 1 {
		t.Fatalf("one embedded asset retained %d independent aliases", reads)
	}
}

func TestGzipStaticBoundsEvenAHandlerThatServesEveryPath(t *testing.T) {
	reads := map[string]int{}
	h := gzipStatic(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads[r.URL.Path]++
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte("const embedded = true;"))
	}))
	get := func(name string) {
		r := httptest.NewRequest(http.MethodGet, name, nil)
		r.Header.Set("Accept-Encoding", "gzip")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatal(w.Code)
		}
	}
	for i := 0; i < gzipStaticMaxEntries+5; i++ {
		get(fmt.Sprintf("/asset-%d.js", i))
	}
	for i := 0; i < gzipStaticMaxEntries+5; i++ {
		get(fmt.Sprintf("/asset-%d.js", i))
	}
	for i := 0; i < gzipStaticMaxEntries+5; i++ {
		want := 1
		if i >= gzipStaticMaxEntries {
			want = 2
		}
		if got := reads[fmt.Sprintf("/asset-%d.js", i)]; got != want {
			t.Fatalf("asset %d reads=%d want=%d", i, got, want)
		}
	}
}

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
