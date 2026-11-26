package providerprofile

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// This contract is pinned to Xray v26.3.27, not the moving upstream main.
// downloadSettings introduces a second endpoint outside the exact-node pin;
// it and H3 are explicitly unsupported until that path has its own proof.
const xhttpExtraFields = "headers xPaddingBytes xPaddingObfsMode xPaddingKey xPaddingHeader xPaddingPlacement xPaddingMethod uplinkHTTPMethod sessionPlacement sessionKey seqPlacement seqKey uplinkDataPlacement uplinkDataKey uplinkChunkSize noGRPCHeader noSSEHeader scMaxEachPostBytes scMinPostsIntervalMs scMaxBufferedPosts scStreamUpServerSecs serverMaxHeaderBytes xmux"

const XHTTPXrayVersion = "26.3.27"

// SingBoxSupportsOutbound is a transport capability gate, not a substitute
// for validation. Canonical XHTTP material must never reach Sing-box runtime.
func SingBoxSupportsOutbound(out map[string]any) bool {
	t, _ := out["transport"].(map[string]any)
	kind, _ := t["type"].(string)
	return kind != "xhttp" && kind != "splithttp"
}

func outboundEngine(out map[string]any) string {
	if !SingBoxSupportsOutbound(out) {
		return "xray"
	}
	return "sing-box"
}

// ParseCanonicalURI returns a private import envelope, not an engine config.
func ParseCanonicalURI(raw string) (Result, error) {
	out, preview, err := parseURIOutbound(raw)
	if err != nil {
		return Result{}, err
	}
	if err := validateCanonicalEngineCapabilities(out); err != nil {
		return Result{}, err
	}
	data, err := buildCanonicalConfig([]map[string]any{out})
	return Result{Preview: preview, Config: data}, err
}

func validateCanonicalEngineCapabilities(out map[string]any) error {
	if SingBoxSupportsOutbound(out) {
		return nil
	}
	p, err := VLESSProfileFromOutbound(out)
	if err != nil {
		return err
	}
	config, _, err := CompileXrayConfig(p)
	clear(config)
	return err
}

func buildCanonicalConfig(outbounds []map[string]any) ([]byte, error) {
	for i, out := range outbounds {
		out["tag"] = "proxy"
		if len(outbounds) > 1 {
			out["tag"] = fmt.Sprintf("node-%02d", i+1)
		}
	}
	return json.Marshal(map[string]any{"outbounds": outbounds})
}

func xhttpURITransport(q url.Values) (map[string]any, error) {
	m := map[string]any{"type": "xhttp"}
	for _, key := range []string{"host", "path", "mode"} {
		if q.Has(key) {
			m[key] = q.Get(key)
		}
	}
	if q.Has("extra") {
		raw := []byte(q.Get("extra"))
		if validateJSONFields(raw) != nil {
			return nil, importError("INVALID_PARAMETERS")
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		var extra map[string]any
		var trailing any
		if d.Decode(&extra) != nil || extra == nil || d.Decode(&trailing) != io.EOF {
			return nil, importError("INVALID_PARAMETERS")
		}
		m["extra"] = extra
	}
	return m, validateXHTTPTransport(m)
}

func cloneXHTTPTransport(m map[string]any) map[string]any {
	// The validated shape contains only JSON values; detach nested maps so a
	// caller cannot change the compiled transport by mutating the source map.
	data, _ := json.Marshal(m)
	defer clear(data)
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var copy map[string]any
	_ = d.Decode(&copy)
	return copy
}

func validateXHTTPTransport(m map[string]any) error {
	bad := importError("INVALID_PARAMETERS")
	if m == nil || onlyProfileFields(m, "type host path mode extra") != nil || m["type"] != "xhttp" {
		return bad
	}
	for _, field := range []string{"host", "path", "mode"} {
		if value, exists := m[field]; exists && !xhttpText(value) {
			return bad
		}
	}
	if host, _ := m["host"].(string); host != "" {
		u, err := url.Parse("https://" + host)
		if err != nil || u.Host != host || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || strings.ContainsAny(host, " \\") {
			return bad
		}
	}
	if path, _ := m["path"].(string); path != "" {
		u, err := url.ParseRequestURI(path)
		if err != nil || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || u.IsAbs() || u.Host != "" || strings.Contains(path, "#") {
			return bad
		}
	}
	mode, _ := m["mode"].(string)
	switch mode {
	case "", "auto", "packet-up", "stream-up", "stream-one":
	default:
		return bad
	}
	extra, exists := m["extra"]
	if !exists {
		return nil
	}
	e, ok := extra.(map[string]any)
	if !ok || e == nil || onlyProfileFields(e, xhttpExtraFields) != nil {
		return bad
	}
	for field, value := range e {
		switch field {
		case "headers":
			if !xhttpHeaders(value) {
				return bad
			}
		case "xmux":
			if !xhttpXMux(value) {
				return bad
			}
		case "xPaddingObfsMode", "noGRPCHeader", "noSSEHeader":
			if _, ok := value.(bool); !ok {
				return bad
			}
		case "xPaddingBytes", "uplinkChunkSize", "scMaxEachPostBytes", "scMinPostsIntervalMs", "scStreamUpServerSecs":
			lo, hi, ok := xhttpRange(value)
			if !ok || lo < 0 || (field == "xPaddingBytes" || field == "scMaxEachPostBytes" || field == "uplinkChunkSize") && lo == 0 && hi != 0 {
				return bad
			}
		case "scMaxBufferedPosts", "serverMaxHeaderBytes":
			n, ok := xhttpInteger(value)
			if !ok || n < 0 || n > math.MaxInt32 {
				return bad
			}
		default:
			if !xhttpText(value) {
				return bad
			}
		}
	}
	for field, choices := range map[string]string{
		"xPaddingPlacement": "cookie header query queryInHeader", "xPaddingMethod": "repeat-x tokenish",
		"sessionPlacement": "path cookie header query", "seqPlacement": "path cookie header query",
		"uplinkDataPlacement": "auto body cookie header",
	} {
		if text, _ := e[field].(string); text != "" && !stringIn(text, strings.Fields(choices)) {
			return bad
		}
	}
	placement, _ := e["uplinkDataPlacement"].(string)
	if (placement == "cookie" || placement == "header") && mode != "packet-up" {
		return bad
	}
	if method, _ := e["uplinkHTTPMethod"].(string); method != "" {
		// Other methods are not accepted as an exact supported combination.
		if method != "POST" && method != "GET" || method == "GET" && mode != "packet-up" {
			return bad
		}
	}
	for _, field := range []string{"xPaddingHeader", "sessionKey", "seqKey", "uplinkDataKey", "xPaddingKey"} {
		if text, _ := e[field].(string); text != "" && !xhttpToken(text) {
			return bad
		}
	}
	return nil
}

func xhttpALPNSupported(p VLESSProfile) bool {
	if !xhttpText(p.ServerName) || strings.ContainsAny(p.ServerName, " /\\:@") {
		return false
	}
	if p.Fingerprint != "" && !stringIn(p.Fingerprint, strings.Fields("chrome firefox safari ios android edge 360 qq random randomized")) {
		return false
	}
	if p.Security == "reality" {
		key, err := base64.RawURLEncoding.DecodeString(p.RealityPublicKey)
		if err != nil || len(key) != 32 || len(p.RealityShortID) > 16 {
			return false
		}
		if _, err := hex.DecodeString(p.RealityShortID); err != nil {
			return false
		}
	}
	// v26.3.27 selects H3 only for the single ALPN "h3". Reject any H3
	// request here rather than silently ignoring it in a mixed ALPN list.
	for _, protocol := range p.ALPN {
		if protocol != "h2" && protocol != "http/1.1" {
			return false
		}
	}
	if len(p.ALPN) == 1 && p.ALPN[0] == "http/1.1" {
		mode, _ := p.XHTTP["mode"].(string)
		if mode == "stream-up" || mode == "stream-one" {
			return false
		}
	}
	return true
}

func xhttpXMux(value any) bool {
	m, ok := value.(map[string]any)
	if !ok || m == nil || onlyProfileFields(m, "maxConcurrency maxConnections cMaxReuseTimes hMaxRequestTimes hMaxReusableSecs hKeepAlivePeriod") != nil {
		return false
	}
	for field, value := range m {
		if field == "hKeepAlivePeriod" {
			n, ok := xhttpInteger(value)
			if !ok || n < -1 || n > math.MaxInt32 {
				return false
			}
		} else if lo, _, ok := xhttpRange(value); !ok || lo < 0 {
			return false
		}
	}
	_, connections, _ := xhttpRange(m["maxConnections"])
	_, concurrency, _ := xhttpRange(m["maxConcurrency"])
	return connections == 0 || concurrency == 0
}

func xhttpInteger(value any) (int64, bool) {
	switch n := value.(type) {
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	case float64:
		return int64(n), n >= math.MinInt32 && n <= math.MaxInt32 && math.Trunc(n) == n
	case int:
		return int64(n), true
	case int64:
		return n, true
	}
	return 0, false
}

func xhttpRange(value any) (int64, int64, bool) {
	if n, ok := xhttpInteger(value); ok {
		return n, n, n >= math.MinInt32 && n <= math.MaxInt32
	}
	text, ok := value.(string)
	if !ok || text == "" {
		return 0, 0, false
	}
	parts := strings.Split(text, "-")
	if len(parts) > 2 {
		return 0, 0, false
	}
	lo, err := strconv.ParseInt(parts[0], 10, 32)
	if err != nil || lo < 0 {
		return 0, 0, false
	}
	hi := lo
	if len(parts) == 2 {
		hi, err = strconv.ParseInt(parts[1], 10, 32)
	}
	return lo, hi, err == nil && hi >= lo
}

func xhttpText(value any) bool {
	s, ok := value.(string)
	return ok && len(s) <= 4096 && utf8.ValidString(s) && strings.IndexFunc(s, func(r rune) bool { return r < 32 || r == 127 }) < 0
}

func xhttpToken(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c > 127 || !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
			return false
		}
	}
	return true
}

func xhttpHeaders(value any) bool {
	m, ok := value.(map[string]any)
	if !ok || m == nil || len(m) > 64 {
		return false
	}
	seen := map[string]bool{}
	for key, value := range m {
		name := strings.ToLower(key)
		if !xhttpToken(key) || !xhttpText(value) || seen[name] || stringIn(name, []string{"host", "connection", "content-length", "transfer-encoding"}) {
			return false
		}
		seen[name] = true
	}
	return true
}

func stringIn(value string, list []string) bool {
	for _, item := range list {
		if value == item {
			return true
		}
	}
	return false
}
