package nodestore

import (
	"context"
	"testing"
)

func TestRequiredHistoryReadVersionFencesXrayAcrossReopen(t *testing.T) {
	ctx := context.Background()
	s, path := setup(t)
	id := importGood(t, s).Nodes[0].ID
	if version, err := s.RequiredHistoryReadVersion(ctx); err != nil || version != 1 {
		t.Fatal(version, err)
	}
	if _, err := s.RecordCheck(ctx, id, enginePass(id, "sing-box", "sb-capability", testTime), testTime); err != nil {
		t.Fatal(err)
	}
	if version, err := s.RequiredHistoryReadVersion(ctx); err != nil || version != 1 {
		t.Fatal(version, err)
	}
	if _, err := s.RecordCheck(ctx, id, enginePass(id, "xray", "xr-capability", testTime), testTime); err != nil {
		t.Fatal(err)
	}
	if version, err := s.RequiredHistoryReadVersion(ctx); err != nil || version != 2 {
		t.Fatal(version, err)
	}
	backup, err := s.ExportPrivate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if version, err := RequiredPrivateHistoryReadVersion(backup); err != nil || version != 2 {
		t.Fatal(version, err)
	}
	backup.SHA256 = "invalid"
	if version, err := RequiredPrivateHistoryReadVersion(backup); err == nil || version != 0 {
		t.Fatal("corrupt retained image granted compatibility", version, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if version, err := s.RequiredHistoryReadVersion(ctx); err != nil || version != 2 {
		t.Fatal(version, err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if version, err := s.RequiredHistoryReadVersion(cancelled); err == nil || version != 0 {
		t.Fatal("cancelled inspection granted compatibility", version, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if version, err := s.RequiredHistoryReadVersion(ctx); err == nil || version != 0 {
		t.Fatal("closed inspection granted compatibility", version, err)
	}
}
