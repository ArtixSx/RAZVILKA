package nodestore

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestXHTTPRequiredReaderFencesMaterialBeforeAnyCheckAndRetainedBackupAfterDelete(t *testing.T) {
	if ExactHistoryReadVersion != 3 {
		t.Fatal("supported XHTTP reader capability must be 3")
	}
	ctx := context.Background()
	s, path := setup(t)
	rawID := importGood(t, s).Nodes[0].ID
	if _, err := s.RecordCheck(ctx, rawID, enginePass(rawID, "xray", "raw-history", testTime), testTime); err != nil {
		t.Fatal(err)
	}
	if version, err := s.RequiredHistoryReadVersion(ctx); err != nil || version != 2 {
		t.Fatal("RAW Xray history was upgraded to XHTTP capability", version, err)
	}
	rawBackup, err := s.ExportPrivate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	xhttp, err := s.Import(ctx, manual, xhttpStoreURI("tls", "packet-up"), testTime, time.Hour, false)
	if err != nil || len(xhttp.Nodes) != 2 {
		t.Fatal(err)
	}
	id := xhttp.Nodes[1].ID
	if xhttp.Nodes[1].Health.State != "not_checked" || len(xhttp.Nodes[1].Health.History) != 0 {
		t.Fatal("fixture gained check authority")
	}
	before := readBytes(t, path)
	if version, err := s.RequiredHistoryReadVersion(ctx); err != nil || version != 3 {
		t.Fatal("unchecked XHTTP granted reader2 compatibility", version, err)
	}
	if !bytes.Equal(before, readBytes(t, path)) {
		t.Fatal("compatibility inspection wrote/migrated state")
	}
	backup, err := s.ExportPrivate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if version, err := s.RequiredHistoryReadVersion(ctx); err != nil || version != 3 || !bytes.Equal(before, readBytes(t, path)) {
		t.Fatal("reopen lost XHTTP reader fence", version, err)
	}
	if _, err := s.Delete(ctx, id, testTime); err != nil {
		t.Fatal(err)
	}
	if version, err := s.RequiredHistoryReadVersion(ctx); err != nil || version != 2 {
		t.Fatal("remaining RAW history capability changed", version, err)
	}
	if version, err := RequiredPrivateHistoryReadVersion(rawBackup); err != nil || version != 2 {
		t.Fatal("old retained RAW backup was upgraded", version, err)
	}
	if version, err := RequiredPrivateHistoryReadVersion(backup); err != nil || version != 3 {
		t.Fatal("retained XHTTP secret lost downgrade fence after live deletion", version, err)
	}
	if _, err := s.Delete(ctx, rawID, testTime); err != nil {
		t.Fatal(err)
	}
	if version, err := s.RequiredHistoryReadVersion(ctx); err != nil || version != 1 {
		t.Fatal("empty legacy store capability changed", version, err)
	}
	// Restoring the retained image must restore both identity and the fence.
	session, err := s.BeginRestore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, restoreErr := executeNodes(t, session, backup)
	closeErr := session.Close()
	if restoreErr != nil || closeErr != nil {
		t.Fatal(restoreErr, closeErr)
	}
	if version, err := s.RequiredHistoryReadVersion(ctx); err != nil || version != 3 {
		t.Fatal("restore did not reinstate XHTTP capability", version, err)
	}
}

func TestXHTTPRequiredReaderDoesNotDependOnHealthOrFreshness(t *testing.T) {
	for _, state := range []string{"unchecked", "xray-pass", "xray-failed", "sing-box-proof", "disabled", "expired"} {
		t.Run(state, func(t *testing.T) {
			ctx := context.Background()
			s, _ := setup(t)
			snap, err := s.Import(ctx, manual, xhttpStoreURI("reality", "stream-one"), testTime, time.Hour, false)
			if err != nil {
				t.Fatal(err)
			}
			id := snap.Nodes[0].ID
			switch state {
			case "xray-pass", "xray-failed", "sing-box-proof":
				engine := "xray"
				if state == "sing-box-proof" {
					engine = "sing-box"
				}
				record := enginePass(id, engine, "capability-state", testTime)
				if state == "xray-failed" {
					record.Verdict, record.State, record.TestLevel, record.Stage = "ERROR", "unavailable", "dns", "dns"
				}
				if _, err := s.RecordCheck(ctx, id, record, testTime); err != nil {
					t.Fatal(err)
				}
			case "disabled":
				if _, err := s.SetDisabled(ctx, id, true, testTime); err != nil {
					t.Fatal(err)
				}
			case "expired":
				if snap, err := s.Snapshot(ctx, testTime.Add(2*time.Hour)); err != nil || snap.Nodes[0].State != "expired" {
					t.Fatal(err)
				}
			}
			if version, err := s.RequiredHistoryReadVersion(ctx); err != nil || version != 3 {
				t.Fatal("retained secret depends on health/freshness", version, err)
			}
			backup, err := s.ExportPrivate(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if version, err := RequiredPrivateHistoryReadVersion(backup); err != nil || version != 3 {
				t.Fatal("private XHTTP image lost reader requirement", version, err)
			}
		})
	}
}
