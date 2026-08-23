package routes

import (
	"strings"
	"testing"
)

func TestValidWithOptions(t *testing.T) {
	options := []Option{
		{ID: "auto", Selectable: true, Ready: true},
		{ID: "direct", Selectable: true, Ready: true},
		{ID: "nfqws2", Selectable: true, Ready: true},
		{ID: "sing-box", Selectable: true, Ready: true},
		{ID: "usque", Selectable: true, Ready: true},
		{ID: "xray", Installed: true, Selectable: false},
	}
	tests := []struct {
		id   string
		want bool
	}{
		{id: "auto", want: true},
		{id: "direct", want: true},
		{id: "nfqws2", want: true},
		{id: "sing-box:ai-primary", want: false},
		{id: "usque:warp_1.2", want: false},
		{id: "xray", want: false},
		{id: "missing", want: false},
		{id: "nfqws2:profile", want: false},
		{id: "sing-box:", want: false},
		{id: "sing-box:.hidden", want: false},
		{id: "sing-box:a/b", want: false},
		{id: "sing-box:a:b", want: false},
		{id: "sing-box:a b", want: false},
		{id: "sing-box:" + strings.Repeat("a", 65), want: false},
	}
	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			if got := ValidWithOptions(tc.id, options); got != tc.want {
				t.Fatalf("ValidWithOptions(%q)=%v, want %v", tc.id, got, tc.want)
			}
		})
	}
}
