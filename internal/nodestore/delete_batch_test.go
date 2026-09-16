package nodestore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func batchFixture(t *testing.T, count int) (*Store, string, Snapshot, []string) {
	t.Helper()
	s, path := setup(t)
	profiles := []string{}
	for i := 0; i < count; i++ {
		profiles = append(profiles, fmt.Sprintf("vless://123e4567-e89b-12d3-a456-426614174000@n%d.example:443?security=tls", i))
	}
	snap, e := s.Import(context.Background(), manual, strings.Join(profiles, "\n"), testTime, time.Hour, false)
	if e != nil {
		t.Fatal(e)
	}
	ids := []string{}
	for _, n := range snap.Nodes {
		ids = append(ids, n.ID)
	}
	return s, path, snap, ids
}
func TestDeleteBatchOneCommitAndPrivateSecrets(t *testing.T) {
	s, path, before, ids := batchFixture(t, 100)
	after, e := s.DeleteBatch(context.Background(), ids[:99], before.Generation, testTime)
	if e != nil || after.Generation != before.Generation+1 || len(after.Nodes) != 1 || after.Nodes[0].ID != ids[99] {
		t.Fatal(after, e)
	}
	for _, id := range ids[:99] {
		if e := s.WithSecret(context.Background(), id, func([]byte) error { return nil }); !errors.Is(e, ErrNotFound) {
			t.Fatal("deleted secret remains")
		}
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	last, e := reopened.Snapshot(context.Background(), testTime)
	if e != nil || len(last.Nodes) != 1 {
		t.Fatal("not durable", e)
	}
	empty, e := reopened.DeleteBatch(context.Background(), []string{ids[99]}, last.Generation, testTime)
	if e != nil || len(empty.Nodes) != 0 {
		t.Fatal("last node failed", e)
	}
}
func TestDeleteBatchRejectsAllBeforeWriting(t *testing.T) {
	for _, kind := range []string{"stale", "duplicate", "invalid", "missing", "group", "canceled", "empty", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			s, path, snap, ids := batchFixture(t, 4)
			ctx := context.Background()
			want := append([]string{}, ids[:3]...)
			gen := snap.Generation
			switch kind {
			case "stale":
				gen++
			case "duplicate":
				want[1] = want[0]
			case "invalid":
				want[1] = "bad"
			case "missing":
				want[1] = "node-" + strings.Repeat("a", 64)
			case "group":
				if _, e := s.CreateGroup(ctx, "Reserve", "fallback", []string{ids[2]}, "", time.Minute, testTime); e != nil {
					t.Fatal(e)
				}
				snap, _ = s.Snapshot(ctx, testTime)
				gen = snap.Generation
			case "canceled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			case "empty":
				want = nil
			case "oversized":
				want = make([]string, MaxNodes+1)
			}
			before := readBytes(t, path)
			if _, e := s.DeleteBatch(ctx, want, gen, testTime); e == nil {
				t.Fatal("bad batch accepted")
			}
			if !bytes.Equal(before, readBytes(t, path)) {
				t.Fatal("failed batch partially wrote")
			}
		})
	}
}
