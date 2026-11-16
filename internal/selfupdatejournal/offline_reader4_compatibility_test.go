package selfupdatejournal

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The workflow builds only the fixture entry point against unmodified sources
// at 4cc9f869974713c9cebd833fccca383c03c102b7. This is an actual historical
// LIBRARY executable, with modeled archive evidence; not an old main/router.
func TestPairedOfflineRetryActualHistoricalReader4(t *testing.T) {
	binary := os.Getenv("RAZVILKA_HISTORICAL_READER4_PROBE")
	if binary == "" {
		t.Skip("requires pinned historical reader4 library executable")
	}
	info, err := os.Lstat(binary)
	if err != nil || !filepath.IsAbs(binary) || filepath.Clean(binary) != binary || !info.Mode().IsRegular() {
		t.Fatal("invalid pinned historical reader probe")
	}
	f, ctx, b, _ := pairedJournalFixture(t)
	sealPairedFixture(t, f, ctx, b)
	original, err := os.ReadFile(filepath.Join(f.journal, transaction, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	prove := func(mode, want string) {
		t.Helper()
		before := historicalReaderTree(t, f.installation, f.journal)
		request, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		command := exec.CommandContext(request, binary, mode, f.installation, f.journal)
		output, diagnostic := &historicalReaderOutput{}, &historicalReaderOutput{}
		command.Stdout, command.Stderr = output, diagnostic
		err := command.Run() // Sole process Wait; fixed helper cannot publish effects.
		if err != nil || request.Err() != nil || string(output.data) != want+"\n" || len(diagnostic.data) != 0 {
			t.Fatalf("historical library %s proof failed (output=%d diagnostic=%d; raw omitted)", mode, len(output.data), len(diagnostic.data))
		}
		after := historicalReaderTree(t, f.installation, f.journal)
		if len(before) != len(after) {
			t.Fatal("historical reader changed retained namespace")
		}
		for name, data := range before {
			fresh, exists := after[name]
			if !exists || !bytes.Equal(data.data, fresh.data) || !os.SameFile(data.info, fresh.info) || data.info.Mode() != fresh.info.Mode() || data.info.Size() != fresh.info.Size() || !data.info.ModTime().Equal(fresh.info.ModTime()) {
				t.Fatal("historical reader changed retained bytes")
			}
		}
	}
	prove("paired4", "historical-library-reader4 paired4 readable")
	cut := errors.New("known pending cut")
	err = f.store.WithPairedOfflineRetry(ctx, transaction, okay, okay, pairedAdmission, func(_ context.Context, _ Receipt, _ []byte, _ bool, _ Check, bind func([]byte, Check) error) error {
		if err := bind([]byte(`{"schema":1,"model":"archive evidence only"}`), nil); err != nil {
			return err
		}
		return cut
	})
	if !errors.Is(err, cut) {
		t.Fatal(err)
	}
	if required, err := f.store.RequiredReadVersion(ctx); err != nil || required != 5 {
		t.Fatal("new actual reader did not see genuine pending5", required, err)
	}
	prove("pending5", "historical-library-reader4 pending5 refused")
	err = f.store.WithPairedOfflineRetry(ctx, transaction, okay, okay, pairedAdmission, func(c context.Context, _ Receipt, _ []byte, verifyOnly bool, check Check, _ func([]byte, Check) error) error {
		if verifyOnly {
			t.Fatal("pending5 lost its bound plan")
		}
		return check(c)
	})
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := os.ReadFile(filepath.Join(f.journal, transaction, "receipt.json"))
	if err != nil || !bytes.Equal(original, terminal) {
		t.Fatal("terminal receipt is not exact original4", err)
	}
	prove("paired4", "historical-library-reader4 paired4 readable")
	t.Log("actual pinned historical reader4 library: paired4 readable, genuine pending5 refused, exact terminal4 readable; modeled archive, no application/router acceptance")
}

type historicalReaderOutput struct{ data []byte }

func (o *historicalReaderOutput) Write(data []byte) (int, error) {
	if len(o.data)+len(data) > 256 {
		return 0, io.ErrShortBuffer
	}
	o.data = append(o.data, data...)
	return len(data), nil
}

type historicalReaderRetained struct {
	data []byte
	info os.FileInfo
}

func historicalReaderTree(t *testing.T, roots ...string) map[string]historicalReaderRetained {
	t.Helper()
	result := map[string]historicalReaderRetained{}
	for _, root := range roots {
		if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if len(result) > 1024 {
				return ErrMismatch
			}
			if entry.IsDir() {
				result[path] = historicalReaderRetained{info: info}
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return ErrMismatch
			}
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()
			data, err := io.ReadAll(io.LimitReader(file, 1<<20))
			if err != nil {
				return err
			}
			if len(data) >= 1<<20 {
				return ErrMismatch
			}
			result[path] = historicalReaderRetained{data, info}
			return nil
		}); err != nil {
			t.Fatal("retained fixture read failed", err)
		}
	}
	return result
}
