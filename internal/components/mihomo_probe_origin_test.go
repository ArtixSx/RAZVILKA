package components

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestMihomoParentOriginLegacyReferenceEncodingAndStrictReader(t *testing.T) {
	legacy := MihomoProbeReference{Version: "1.19.33", BinarySHA256: strings.Repeat("a", 64), BinarySize: 10, ReviewSHA256: strings.Repeat("b", 64), ConfigSHA256: strings.Repeat("c", 64), ServerHost: "edge.example", SOCKSPort: 18090}
	raw, err := json.Marshal(legacy)
	if err != nil || bytes.Contains(raw, []byte("parent_origin")) {
		t.Fatal("legacy zero origin changed format", string(raw), err)
	}
	origin := MihomoProbeParentOrigin{Schema: 1, BootID: "11111111-2222-4333-8444-555555555555", PID: 2, StartTicks: 3, ExecutableInode: 4, ExecutableSize: 10, ExecutableSHA256: strings.Repeat("d", 64), PIDNamespaceInode: 5, ProcInode: 6, DeathSignal: "linux-pdeathsig-sigkill-v1"}
	if err := origin.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, boot := range []string{"00000000-0000-0000-0000-000000000000", "11111111-2222-4333-8444-ABCDEFABCDEF"} {
		bad := origin
		bad.BootID = boot
		if bad.Validate() == nil {
			t.Fatal("noncanonical boot accepted", boot)
		}
	}
	legacy.ParentOrigin = origin
	raw, err = json.Marshal(legacy)
	if err != nil || !bytes.Contains(raw, []byte("parent_origin")) {
		t.Fatal("new origin missing", err)
	}
	// The old strict decoder must refuse the new field rather than silently
	// accepting a process/death interpretation it never implemented.
	var old struct {
		Version      string `json:"version"`
		BinarySHA256 string `json:"binary_sha256"`
		BinarySize   int64  `json:"binary_size"`
		ReviewSHA256 string `json:"review_sha256"`
		ConfigSHA256 string `json:"config_sha256"`
		ServerHost   string `json:"server_host"`
		Endpoint     any    `json:"endpoint"`
		SOCKSPort    int    `json:"socks_port"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&old) == nil {
		t.Fatal("reader4 accepted parent origin")
	}
}
