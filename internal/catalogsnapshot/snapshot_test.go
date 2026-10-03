package catalogsnapshot

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestRoundTripKeepsOriginalTimeAndBytes(t *testing.T) {
	now := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	body := []byte(" {\n\"entries\": [1]} ")
	b, e := Encode("https://source.example/index", body, now)
	if e != nil {
		t.Fatal(e)
	}
	got, e := Decode(b, "https://source.example/index", now.Add(time.Hour), 24*time.Hour)
	if e != nil || !bytes.Equal(body, got.Body) || !got.CapturedAt.Equal(now) {
		t.Fatal(got, e)
	}
	body[1] = 'X'
	if bytes.Equal(body, got.Body) {
		t.Fatal("alias")
	}
}
func TestRejectsCorruptionOriginFutureAndExpired(t *testing.T) {
	now := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	b, _ := Encode("origin", []byte(`{}`), now)
	for _, name := range []string{"origin", "future", "expired", "digest", "body", "schema", "trailing", "unknown"} {
		t.Run(name, func(t *testing.T) {
			var s Snapshot
			_ = json.Unmarshal(b, &s)
			want := "origin"
			at := now
			raw := b
			switch name {
			case "origin":
				want = "other"
			case "future":
				at = now.Add(-time.Second)
			case "expired":
				at = now.Add(25 * time.Hour)
			case "digest":
				s.SHA256 = "bad"
				raw, _ = json.Marshal(s)
			case "body":
				s.Body = []byte(`[]`)
				raw, _ = json.Marshal(s)
			case "schema":
				s.Schema = 2
				raw, _ = json.Marshal(s)
			case "trailing":
				raw = append(append([]byte{}, b...), []byte(`{}`)...)
			case "unknown":
				raw = append([]byte(`{"unexpected":true,`), b[1:]...)
			}
			if _, err := Decode(raw, want, at, 24*time.Hour); err == nil {
				t.Fatal("invalid checkpoint accepted")
			}
		})
	}
}
func TestSizeLimitsAndZeroTime(t *testing.T) {
	now := time.Now()
	if _, e := Encode("origin", make([]byte, MaxBody+1), now); e == nil {
		t.Fatal("oversize body")
	}
	if _, e := Encode("origin", []byte(`{}`), time.Time{}); e == nil {
		t.Fatal("zero time")
	}
	if _, e := Decode(make([]byte, MaxEnvelope+1), "origin", now, time.Hour); e == nil {
		t.Fatal("oversize envelope")
	}
}
