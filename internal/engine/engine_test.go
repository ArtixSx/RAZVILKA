package engine

import "testing"

func TestProcessListHasExactName(t *testing.T) {
	output := `PID USER COMMAND
12 root /opt/bin/nfqws2-helper --serve
13 root /usr/bin/grep nfqws2
14 root /opt/bin/unrelated --name=nfqws2
`
	if processListHasName(output, "nfqws2") {
		t.Fatal("substring or argument was treated as a running process")
	}
	output += "15 root /opt/bin/nfqws2 --dpi-desync=fake\n"
	if !processListHasName(output, "nfqws2") {
		t.Fatal("exact executable name was not detected")
	}
	if !processListHasName("16 root [nfqws2]\n", "nfqws2") {
		t.Fatal("kernel-style process name was not detected")
	}
}

func TestStatusLooksRunning(t *testing.T) {
	tests := []struct {
		status string
		want   bool
	}{
		{status: "service is running", want: true},
		{status: "started", want: true},
		{status: "active (running)", want: true},
		{status: "not running", want: false},
		{status: "inactive", want: false},
		{status: "not started", want: false},
		{status: "failed", want: false},
		{status: "", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.status, func(t *testing.T) {
			if got := statusLooksRunning(tc.status); got != tc.want {
				t.Fatalf("statusLooksRunning(%q)=%v, want %v", tc.status, got, tc.want)
			}
		})
	}
}
