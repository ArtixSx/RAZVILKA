package nodestore

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/providerprofile"
)

func TestRequiredImportReadVersionUsesExactCanonicalAndPartialContract(t *testing.T) {
	xhttp := xhttpStoreURI("tls", "packet-up")
	canonical, err := providerprofile.ParseCanonicalProfile(xhttp)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(canonical.Config)
	bad := strings.Replace(xhttp, "mode=packet-up", "mode=unsupported", 1)
	for _, c := range []struct {
		name, raw string
		partial   bool
		required  int
		err       error
	}{
		{"RAW", good, false, 1, nil},
		{"XHTTP-URI", xhttp, false, 3, nil},
		{"XHTTP-canonical", string(canonical.Config), false, 3, nil},
		{"mixed-accepted", good + "\n" + xhttp, false, 3, nil},
		{"unsupported", bad, false, 0, ErrImport},
		{"partial-unconfirmed", good + "\n" + bad, false, 0, ErrPartial},
		{"partial-RAW", good + "\n" + bad, true, 1, nil},
		{"partial-XHTTP", xhttp + "\n" + bad, true, 3, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			version, err := RequiredImportReadVersion(c.raw, c.partial)
			if version != c.required || !errors.Is(err, c.err) {
				t.Fatal("incorrect incoming capability or partial confirmation", version, err)
			}
			// The actual writer must use exactly the same acceptance boundary.
			s, _ := setup(t)
			_, importErr := s.Import(context.Background(), manual, c.raw, testTime, time.Hour, c.partial)
			if !errors.Is(importErr, c.err) {
				t.Fatal("capability inspector disagrees with writer", importErr)
			}
		})
	}
}

func TestRequiredImportReadVersionDoesNotWriteOrUpgradeRAWEvidenceMinimum(t *testing.T) {
	s, path := setup(t)
	id := importGood(t, s).Nodes[0].ID
	before := readBytes(t, path)
	if version, err := RequiredImportReadVersion(xhttpStoreURI("reality", "stream-one"), false); err != nil || version != 3 || !bytes.Equal(before, readBytes(t, path)) {
		t.Fatal("incoming inspection changed live bytes", version, err)
	}
	if XrayHistoryReadVersion != 2 {
		t.Fatal("RAW Xray history minimum changed")
	}
	if _, err := s.RecordCheck(context.Background(), id, enginePass(id, "xray", "exported-minimum", testTime), testTime); err != nil {
		t.Fatal(err)
	}
	if version, err := s.RequiredHistoryReadVersion(context.Background()); err != nil || version != XrayHistoryReadVersion {
		t.Fatal("RAW record was over-fenced with supported reader 3", version, err)
	}
}
