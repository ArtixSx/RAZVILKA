package app

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArtixSx/razvilka/internal/nodestore"
	"github.com/ArtixSx/razvilka/internal/operationgate"
	"github.com/ArtixSx/razvilka/internal/privatebackup"
)

type restoreHistoryContextKey struct{}

func privateRestoreHistoryPayload(t *testing.T, version int) privatebackup.Payload {
	t.Helper()
	source := privateRestoreNodeApp(t, filepath.Join(t.TempDir(), "source"))
	uri := "vless://123e4567-e89b-12d3-a456-426614174000@incoming-private.example:443?security=tls&sni=front.example"
	if version == 3 {
		uri += "&type=xhttp&mode=packet-up&path=%2Fincoming-private"
	}
	now := time.Now().UTC()
	snapshot, err := source.Nodes.Import(context.Background(), nodestore.Source{ID: "manual", Kind: "manual"}, uri, now, time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	if version == 2 {
		_, err = source.Nodes.RecordCheck(context.Background(), snapshot.Nodes[0].ID, nodestore.CheckRecord{ProbeID: "restore-raw-history", ServiceID: "youtube", NetworkProfile: "wan-0123456789ab", RoutePathID: "xray:" + snapshot.Nodes[0].ID, TestLevel: "service", Verdict: "ERROR", State: "unavailable", Stage: "service", CheckedAt: now, ExpiresAt: now.Add(time.Hour)}, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	image, err := source.Nodes.ExportPrivate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	payload := privatebackup.NewPayload("0.18.1-dev")
	payload.NodeSnapshot = &image
	if err := privatebackup.Seal(&payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestPrivateRestoreHistoryAdmissionPrecedesEveryRestoreWrite(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		payload := privateRestoreHistoryPayload(t, version)
		for _, mode := range []string{"missing", "reject", "panic", "cancel-nil", "allow"} {
			t.Run(strings.Join([]string{string(rune('0' + version)), mode}, "/"), func(t *testing.T) {
				target := privateRestoreNodeApp(t, filepath.Join(t.TempDir(), "target"))
				before := target.Store.Get()
				beforeNodes, err := target.Nodes.ExportPrivateIfPresent(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.WithValue(context.Background(), restoreHistoryContextKey{}, "original"))
				defer cancel()
				calls := 0
				if mode != "missing" {
					target.NodeHistoryWriteGuard = func(c context.Context, required int) error {
						calls++
						if required != version || c.Value(restoreHistoryContextKey{}) != "original" || !reflect.DeepEqual(before, target.Store.Get()) {
							t.Fatal("restore lost typed minimum, context or pre-write boundary")
						}
						if release, err := target.Operations.Exclusive(c); !errors.Is(err, operationgate.ErrBusy) {
							if release != nil {
								release()
							}
							t.Fatal("restore admission probe ran outside exclusive operation", err)
						}
						switch mode {
						case "reject":
							return errors.New("incoming-private.example refused")
						case "panic":
							panic("incoming-private.example panic")
						case "cancel-nil":
							cancel()
						}
						return nil
					}
				}
				err = target.restorePrivateDraft(ctx, payload)
				allowed := mode == "allow" || mode == "missing" && version == 1
				if allowed {
					if err != nil {
						var failure *privateRestoreFailure
						errors.As(err, &failure)
						if failure != nil {
							t.Fatalf("compatible restore refused: phase=%s calls=%d", failure.phase, calls)
						}
						t.Fatal("compatible restore refused")
					}
					if required, err := target.Nodes.RequiredHistoryReadVersion(context.Background()); err != nil || required != version {
						t.Fatal("admitted restore lost typed history", required, err)
					}
				} else {
					var failure *privateRestoreFailure
					if !errors.As(err, &failure) || !failure.notStarted || failure.recoveryRequired {
						t.Fatal("unsafe history restore did not refuse before writes", err)
					}
					w := httptest.NewRecorder()
					writePrivateRestoreFailure(w, err)
					if strings.Contains(w.Body.String(), "incoming-private") {
						t.Fatal("private admission failure escaped")
					}
					afterNodes, readErr := target.Nodes.ExportPrivateIfPresent(context.Background())
					nodesEqual := beforeNodes == nil && afterNodes == nil || beforeNodes != nil && afterNodes != nil && bytes.Equal(beforeNodes.Content, afterNodes.Content)
					if readErr != nil || !nodesEqual || !reflect.DeepEqual(before, target.Store.Get()) || len(target.CustomServices.List()) != 0 || len(target.Devices.Known()) != 0 {
						t.Fatal("refused restore changed private/config/metadata state", readErr)
					}
				}
				wantCalls := 1
				if mode == "missing" {
					wantCalls = 0
				}
				if calls != wantCalls {
					t.Fatal("admission probe replayed", calls)
				}
			})
		}
	}
}
