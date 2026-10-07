package providerfeed

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenWithDependenciesRefusesMissingInputsAndCopiesClient(t *testing.T) {
	root := filepath.Join(t.TempDir(), "feeds")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return time.Now().UTC() }
	for _, deps := range []struct {
		client *http.Client
		now    func() time.Time
	}{
		{nil, clock}, {&http.Client{}, nil}, {&http.Client{}, func() time.Time { return time.Time{} }},
	} {
		if m, err := OpenWithDependencies(nil, root, deps.client, deps.now); m != nil || !errors.Is(err, ErrRequest) {
			t.Fatal("invalid dependencies accepted", err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, FileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refusal wrote manifest", err)
	}
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	m, err := OpenWithDependencies(nil, root, client, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	client.Transport = nil
	client.Timeout = time.Hour
	if m.client == client || m.client.Transport != transport || m.client.Timeout != time.Second {
		t.Fatal("caller client reassignment changed captured dependencies")
	}
}
