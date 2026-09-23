package nodestore

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestReserveSelectionDoesNotCountKeysPortsOrLabelsAsDifferentServers(t *testing.T) {
	s, path := setup(t)
	var ids []string
	for i, raw := range []string{
		good,
		strings.Replace(good, "174000", "174001", 1),
		strings.Replace(good, ":443?", ":8443?", 1),
		strings.Replace(good, "private-host.example", "different.example", 1),
	} {
		snapshot, err := s.Import(context.Background(), manual, raw, testTime, time.Hour, false)
		if err != nil {
			t.Fatal(i, err)
		}
		for _, n := range snapshot.Nodes {
			known := false
			for _, id := range ids {
				known = known || id == n.ID
			}
			if !known {
				ids = append(ids, n.ID)
			}
		}
	}
	before := readBytes(t, path)
	selected, err := s.SelectReserveIDs(context.Background(), ids, 4)
	if err != nil || !reflect.DeepEqual(selected, []string{ids[0], ids[3]}) {
		t.Fatal(selected, err)
	}
	if string(before) != string(readBytes(t, path)) {
		t.Fatal("selection changed stored material or proof")
	}
	selected, err = s.SelectReserveIDs(context.Background(), []string{ids[1], ids[0], ids[3]}, 3)
	if err != nil || !reflect.DeepEqual(selected, []string{ids[1], ids[3]}) {
		t.Fatal("primary displaced", selected, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = s.SelectReserveIDs(ctx, ids, 3); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err = s.SelectReserveIDs(context.Background(), []string{"missing"}, 3); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestReserveSelectionPrefersTransportAndSourceVarietyAfterPrimary(t *testing.T) {
	s, _ := setup(t)
	var ids []string
	for _, entry := range []struct {
		raw    string
		source Source
	}{
		{good, manual},
		{strings.Replace(good, "private-host.example", "second.example", 1), manual},
		{strings.Replace(good, "private-host.example", "third.example", 1), Source{ID: "other", Kind: "subscription"}},
		{strings.Replace(good, "private-host.example", "fourth.example", 1), manual},
	} {
		raw := entry.raw
		if strings.Contains(raw, "fourth.example") {
			raw = strings.Replace(raw, "#SECRET_ALIAS", "&type=ws&path=%2Fwebsocket#WS", 1)
		}
		snapshot, err := s.Import(context.Background(), entry.source, raw, testTime, time.Hour, false)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range snapshot.Nodes {
			known := false
			for _, id := range ids {
				known = known || id == n.ID
			}
			if !known {
				ids = append(ids, n.ID)
			}
		}
	}
	selected, err := s.SelectReserveIDs(context.Background(), ids, 4)
	if err != nil || !reflect.DeepEqual(selected, []string{ids[0], ids[3], ids[2], ids[1]}) {
		t.Fatal(selected, err)
	}
}
