package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ArtixSx/razvilka/internal/community"
)

func TestCommunityErrorShowsFailedPartWithoutSourceDetails(t *testing.T) {
	for _, tc := range []struct {
		part   string
		err    error
		status int
	}{
		{"cidrs", context.DeadlineExceeded, 504},
		{"domains", errors.New("https://private.example/token?secret=hidden"), 502},
	} {
		w := httptest.NewRecorder()
		writeCommunityFailure(w, &community.SourceError{Part: tc.part, Err: tc.err})
		var body map[string]any
		if json.Unmarshal(w.Body.Bytes(), &body) != nil || w.Code != tc.status || body["source_part"] != tc.part || body["not_started"] != true || body["live_applied"] != false {
			t.Fatalf("wrong error response: %d %s", w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "private.example") || strings.Contains(w.Body.String(), "hidden") {
			t.Fatal("raw source error exposed")
		}
	}
}
