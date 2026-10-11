package config

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func autonomyCommitFixture(t *testing.T) (*Store, context.Context) {
	t.Helper()
	s, err := Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSafeMode(false); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"target", "foreign"} {
		if err := s.UpdateService(id, ServiceState{Enabled: true, Route: "nfqws2", Sources: []string{"192.168.1.40"}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.ApplyDraft(); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateService("foreign", ServiceState{Enabled: true, Route: "usque", Sources: []string{"192.168.1.41"}}); err != nil {
		t.Fatal(err)
	}
	policy := DefaultServicePolicy("target", s.Get().Services["target"])
	policy.AllowedNodeIDs = []string{"node-" + strings.Repeat("a", 64)}
	if _, err := s.UpdateServicePolicy(policy, s.Get().Revision, 0); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	clients := &NetworkPolicy{Schema: 2, Revision: 1, Clients: ClientScope{Mode: "lan_except", SegmentIDs: []string{"home"}, NewDevices: "inherit"}, Traffic: TrafficSelection{Mode: "selected_services", Unavailable: "retain"}}
	if _, err := s.ApproveDefaultRouteConsent(ctx, s.Get(), clients, nil, strings.Repeat("a", 32), 1); err != nil {
		t.Fatal(err)
	}
	manual := []ResourceMatch{{Kind: "exact", Value: "excluded.example"}}
	if _, err := s.UpdateResourceExclusions(ctx, s.Get(), &manual, nil); err != nil {
		t.Fatal(err)
	}
	return s, ctx
}

func TestAutonomyCommitReviewConsumesOnlyActualWriterAndOriginalUndo(t *testing.T) {
	s, ctx := autonomyCommitFixture(t)
	before := s.Get()
	route := "xray:node-" + strings.Repeat("a", 64)
	undo, r, err := s.ApplyAutonomyRouteReviewedWithRollback("target", route, []string{"192.168.1.40"}, before.Revision)
	if err != nil || !r.MatchesStore(s) {
		t.Fatal("actual reviewed publication", err)
	}
	after := s.Get()
	at, err := time.Parse(time.RFC3339, after.LastAppliedAt)
	if err != nil {
		t.Fatal(err)
	}
	predicted, err := ReviewedAutonomyRouteCommitImage(before, "target", route, []string{"192.168.1.40"}, at)
	if err != nil || !reflect.DeepEqual(predicted, after) {
		t.Fatal("writer diverged from full single-service image", err)
	}
	if !reflect.DeepEqual(before.Services["foreign"], after.Services["foreign"]) || !reflect.DeepEqual(before.AppliedServices["foreign"], after.AppliedServices["foreign"]) ||
		!reflect.DeepEqual(before.NetworkPolicy, after.NetworkPolicy) || !reflect.DeepEqual(before.AppliedNetworkPolicy, after.AppliedNetworkPolicy) || !reflect.DeepEqual(before.DefaultRouteConsent, after.DefaultRouteConsent) || after.ServicePolicies["target"].Enabled {
		t.Fatal("foreign intent, negatives or approval changed")
	}
	from, to, err := r.CommittedImages(ctx)
	if err != nil || !reflect.DeepEqual(from, before) || !reflect.DeepEqual(to, after) {
		t.Fatal("actual publication receipt refused", err)
	}
	from.Services["foreign"] = ServiceState{}
	to.NetworkPolicy.Clients.SegmentIDs[0] = "modified-dto"
	from, to, err = r.CommittedImages(ctx)
	if err != nil || !reflect.DeepEqual(from, before) || !reflect.DeepEqual(to, after) {
		t.Fatal("detached comparison mutated original receipt", err)
	}
	if _, _, err := r.RestoredImages(ctx); err == nil {
		t.Fatal("preimage DTO granted an undo that never ran")
	}
	copy := &AutonomyRouteCommitReview{self: r, store: s}
	if _, _, err := copy.CommittedImages(ctx); err == nil {
		t.Fatal("copied producer granted publication")
	}
	if _, _, err := r.CommittedImages(context.Background()); err == nil {
		t.Fatal("unbounded receipt read granted")
	}
	if err := undo(); err != nil || !reflect.DeepEqual(s.Get(), before) {
		t.Fatal("original undo did not restore exact preimage", err)
	}
	if _, _, err := r.CommittedImages(ctx); err == nil {
		t.Fatal("restored producer still granted committed phase")
	}
	from, to, err = r.RestoredImages(ctx)
	if err != nil || !reflect.DeepEqual(from, after) || !reflect.DeepEqual(to, before) {
		t.Fatal("actual undo receipt lost original revision/time", err)
	}
	if err := undo(); err != nil {
		t.Fatal("original undo lost idempotence", err)
	}
}

func TestAutonomyCommitReviewCannotAdoptForeignCASOrInvalidNodeSyntax(t *testing.T) {
	for _, route := range []string{"xray:node-a", "Xray:node-" + strings.Repeat("a", 64), "xray:node-" + strings.Repeat("a", 64) + " ", "xray:group-" + strings.Repeat("a", 32), "sing-box:group-" + strings.Repeat("a", 32), "xray:opaque"} {
		s, _ := autonomyCommitFixture(t)
		before := s.Get()
		if _, r, err := s.ApplyAutonomyRouteReviewedWithRollback("target", route, nil, before.Revision); err == nil || r != nil || !reflect.DeepEqual(before, s.Get()) {
			t.Fatal("noncanonical node syntax acquired actual receipt", route, err)
		}
	}
	s, ctx := autonomyCommitFixture(t)
	undo, r, err := s.ApplyAutonomyRouteReviewedWithRollback("target", "xray:node-"+strings.Repeat("a", 64), []string{"192.168.1.40"}, s.Get().Revision)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateService("foreign", ServiceState{Enabled: false, Route: "direct"}); err != nil {
		t.Fatal(err)
	}
	changed := s.Get()
	if _, _, err := r.CommittedImages(ctx); err == nil {
		t.Fatal("receipt adopted unrelated draft")
	}
	if err := undo(); !errors.Is(err, ErrRevisionChanged) || !reflect.DeepEqual(s.Get(), changed) {
		t.Fatal("original undo clobbered foreign CAS", err)
	}
	if _, _, err := r.RestoredImages(ctx); err == nil {
		t.Fatal("failed undo granted restored phase")
	}
}
