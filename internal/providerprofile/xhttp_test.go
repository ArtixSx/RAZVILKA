package providerprofile

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

const xhttpExtraFixture = `{"headers":{"Authorization":"private-extra-token","X-Test":"fixture"},"xPaddingBytes":"100-200","xPaddingObfsMode":true,"xPaddingKey":"pad","xPaddingHeader":"X-Pad","xPaddingPlacement":"header","xPaddingMethod":"tokenish","uplinkHTTPMethod":"POST","sessionPlacement":"query","sessionKey":"session","seqPlacement":"query","seqKey":"seq","uplinkDataPlacement":"body","uplinkDataKey":"data","uplinkChunkSize":4096,"noGRPCHeader":true,"noSSEHeader":false,"scMaxEachPostBytes":8192,"scMinPostsIntervalMs":"10-20","scMaxBufferedPosts":16,"scStreamUpServerSecs":"20-30","serverMaxHeaderBytes":8192,"xmux":{"maxConnections":"1-2","cMaxReuseTimes":2,"hMaxRequestTimes":"10-20","hMaxReusableSecs":30,"hKeepAlivePeriod":-1}}`

func xhttpURI(extra string) string {
	return testVLESS + "security=tls&sni=front.example&type=xhttp&host=front.example&path=" + url.QueryEscape("/tunnel?token=private-path") + "&mode=packet-up&extra=" + url.QueryEscape(extra)
}

func xhttpCompiledSettings(t *testing.T, raw string) (map[string]any, XrayResult) {
	t.Helper()
	doc, result := compileXrayURI(t, raw)
	stream := doc["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
	if stream["network"] != "xhttp" || stream["security"] != "tls" || stream["tcpSettings"] != nil {
		t.Fatal("transport was changed or weakened")
	}
	return stream["xhttpSettings"].(map[string]any), result
}

func TestXHTTPURIAndCanonicalJSONPreserveEveryAcceptedParameter(t *testing.T) {
	raw := xhttpURI(xhttpExtraFixture)
	canonical, err := ParseCanonicalURI(raw)
	if err != nil || canonical.Preview.EngineID != "xray" {
		t.Fatalf("canonical import: %v", err)
	}
	var envelope struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if json.Unmarshal(canonical.Config, &envelope) != nil || len(envelope.Outbounds) != 1 {
		t.Fatal("canonical envelope invalid")
	}
	native := envelope.Outbounds[0]
	delete(native, "tag")
	material, _ := json.Marshal(native)
	p, err := VLESSProfileFromJSON(material)
	if err != nil || p.Transport != "xhttp" || p.ServerName != "front.example" {
		t.Fatalf("canonical projection: %v", err)
	}
	transport := native["transport"].(map[string]any)
	transport["mode"] = "stream-one"
	if p.XHTTP["mode"] != "packet-up" {
		t.Fatal("profile aliases caller transport")
	}
	settings, result := xhttpCompiledSettings(t, raw)
	var wantExtra any
	_ = json.Unmarshal([]byte(xhttpExtraFixture), &wantExtra)
	if settings["host"] != "front.example" || settings["path"] != "/tunnel?token=private-path" || settings["mode"] != "packet-up" || !reflect.DeepEqual(settings["extra"], wantExtra) {
		t.Fatal("required transport parameters lost")
	}
	settingsJSON, _ := json.Marshal(settings)
	_, roundtrip := xhttpCompiledSettings(t, string(canonical.Config))
	if !strings.Contains(string(roundtrip.Config), "private-extra-token") || len(settingsJSON) == 0 {
		t.Fatal("JSON re-import lost extra")
	}
	preview, _ := json.Marshal(result.Preview)
	for _, secret := range []string{xrayUUID, "private-extra-token", "private-path"} {
		if strings.Contains(string(preview), secret) {
			t.Fatal("private connection parameter leaked")
		}
	}
}

func TestXHTTPCompilerSupportsPinnedModesAndAliases(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, security := range []string{"tls", "reality"} {
		for _, transport := range []string{"xhttp", "splithttp"} {
			for _, mode := range []string{"", "auto", "packet-up", "stream-up", "stream-one"} {
				query := "security=" + security + "&type=" + transport + "&mode=" + mode
				if security == "reality" {
					query += "&pbk=" + key + "&sid=abcd"
				}
				result, err := ParseXrayProfile(testVLESS+query, 0)
				if err != nil || !strings.Contains(string(result.Config), `"network": "xhttp"`) {
					t.Fatalf("%s/%s/%s: %v", security, transport, mode, err)
				}
			}
		}
	}
}

func TestXHTTPNeverEntersSingBoxDraft(t *testing.T) {
	raw := xhttpURI(`{}`)
	for _, input := range []string{raw, base64.StdEncoding.EncodeToString([]byte(raw))} {
		result, err := ParseProfile(input)
		if ErrorCode(err) != "UNSUPPORTED_TRANSPORT" || len(result.Config) != 0 {
			t.Fatal("XHTTP became a Sing-box draft")
		}
	}
	if result, err := ParseURI(raw); ErrorCode(err) != "UNSUPPORTED_TRANSPORT" || len(result.Config) != 0 {
		t.Fatal("URI became a Sing-box draft")
	}
	if canonical, err := ParseCanonicalProfile(raw); err != nil || canonical.Preview.EngineID != "canonical" || strings.Contains(string(canonical.Config), `"route"`) || strings.Contains(string(canonical.Config), `"direct"`) {
		t.Fatal("import envelope has runtime authority")
	}
	// A mixed generic draft rejects the incompatible entry, with accounting.
	result, err := ParseProfile(raw + "\n" + testVLESS + "security=tls")
	if err != nil || result.Preview.NodeCount != 1 || len(result.Preview.Rejected) != 1 || strings.Contains(string(result.Config), `"xhttp"`) {
		t.Fatal("incompatible transport entered the compatible pool")
	}
}

func TestXHTTPRejectsUnknownAmbiguousAndUnsafeExtra(t *testing.T) {
	for _, extra := range []string{
		`null`, `[]`, `{"downloadSettings":{}}`, `{"unknown":"secret-canary"}`,
		`{"sessionIDPlacement":"query"}`, `{"extra":{}}`, `{"path":"/ignored"}`,
		`{"noSSEHeader":"true"}`, `{"xPaddingBytes":null}`, `{"xPaddingBytes":0.5}`,
		`{"xPaddingBytes":"0-100"}`, `{"xPaddingBytes":"2147483648"}`, `{"xPaddingBytes":"2-1"}`,
		`{"scMaxEachPostBytes":-1}`, `{"serverMaxHeaderBytes":-1}`, `{"scMaxBufferedPosts":1.1}`,
		`{"headers":{"Host":"shadow.example"}}`, `{"headers":{"X-Test":"a","x-test":"b"}}`,
		`{"headers":{"X-Test":["value"]}}`, `{"headers":{"X-Test":"bad\r\nInjected: yes"}}`,
		`{"headers":{"Content-Length":"0"}}`, `{"xmux":{"maxConcurrency":1,"maxConnections":2}}`,
		`{"xmux":{"hKeepAlivePeriod":-2}}`, `{"xmux":{"unknown":1}}`,
		`{"noSSEHeader":true,"noSSEHeader":false}`, `{"uplinkDataPlacement":"header"}`, // valid only with explicit packet-up below
	} {
		raw := xhttpURI(extra)
		if strings.Contains(extra, "uplinkDataPlacement") {
			raw = strings.Replace(raw, "mode=packet-up", "mode=auto", 1)
		}
		result, err := ParseXrayProfile(raw, 0)
		if err == nil || len(result.Config) != 0 || strings.Contains(err.Error(), "secret-canary") {
			t.Fatalf("invalid extra accepted: %s", extra)
		}
	}
	for _, suffix := range []string{
		"&mode=stream-one", "&serviceName=gate", "&flow=xtls-rprx-vision", "&alpn=h3", "&alpn=h2,h3", "&fp=unknown-secret", "&packet_encoding=packetaddr",
	} {
		if result, err := ParseXrayProfile(xhttpURI(`{}`)+suffix, 0); err == nil || len(result.Config) != 0 {
			t.Fatalf("unsupported combination accepted: %s", suffix)
		}
	}
	for _, change := range [][2]string{{"security=tls", "security=none"}, {"mode=packet-up", "mode=stream-one&alpn=http/1.1"}, {"path=" + url.QueryEscape("/tunnel?token=private-path"), "path=" + url.QueryEscape("https://other.example/path")}} {
		if result, err := ParseXrayProfile(strings.Replace(xhttpURI(`{}`), change[0], change[1], 1), 0); err == nil || len(result.Config) != 0 {
			t.Fatal("unsupported mode/security/path accepted")
		}
	}
}

func TestXHTTPNativeXrayJSONPreservesTopLevelExtraAndRejectsShadowing(t *testing.T) {
	settings := `{"host":"front.example","path":"/x","mode":"packet-up","noSSEHeader":true,"xPaddingBytes":"64-128","xmux":{"maxConcurrency":2}}`
	source := func(settings string) string {
		return `{"outbounds":[{"protocol":"vless","tag":"ignored-name","settings":{"vnext":[{"address":"edge.example","port":443,"users":[{"id":"` + xrayUUID + `","encryption":"none"}]}]},"streamSettings":{"network":"xhttp","security":"tls","tlsSettings":{"serverName":"front.example","alpn":["h2"]},"xhttpSettings":` + settings + `}}]}`
	}
	compiled, _ := xhttpCompiledSettings(t, source(settings))
	if compiled["extra"].(map[string]any)["noSSEHeader"] != true {
		t.Fatal("top-level Xray option lost")
	}
	for _, invalid := range []string{
		`{"mode":"packet-up","extra":{},"noSSEHeader":true}`,
		`{"mode":"packet-up","extra":{"downloadSettings":{}}}`,
		`{"mode":"packet-up","unknown":123}`,
		`{"mode":null}`, `{"path":null}`, `{"host":null}`,
	} {
		if result, err := ParseXrayProfile(source(invalid), 0); err == nil || len(result.Config) != 0 {
			t.Fatal("ambiguous native source accepted")
		}
	}
	for _, mutation := range []string{
		strings.Replace(source(settings), `"alpn":["h2"]`, `"alpn":["h2"],"pinnedPeerCertSha256":"PIN"`, 1),
		strings.Replace(source(settings), `"network":"xhttp"`, `"network":"xhttp","sockopt":{"mark":123}`, 1),
		strings.Replace(source(settings), `"encryption":"none"`, `"encryption":"none","level":1`, 1),
	} {
		if _, err := ParseXrayProfile(mutation, 0); err == nil {
			t.Fatal("required source constraint lost")
		}
	}
	if ValidateXrayXHTTPSettings(nil) == nil || ValidateXrayXHTTPSettings(map[string]any{"extra": map[string]any{"downloadSettings": map[string]any{}}}) == nil {
		t.Fatal("adapter validator allowed unsupported settings")
	}
	cycle := map[string]any{}
	cycle["extra"] = cycle
	if ValidateXrayXHTTPSettings(cycle) == nil {
		t.Fatal("non-JSON settings accepted")
	}
}
