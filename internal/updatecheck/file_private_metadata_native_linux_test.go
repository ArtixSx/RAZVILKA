//go:build linux

package updatecheck

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ArtixSx/razvilka/internal/restorejournal"
)

func TestNativePrivateMetadataDescriptorAndModes(t *testing.T) {
	a := &SelfUpdateFileAdapter{owned: func(string) error { return nil }} // own TempDir only
	ctx := context.Background()
	root := t.TempDir()
	path := filepath.Join(root, "secret")
	if err := a.verifyPrivateFileMetadata(ctx, path, false); err != nil {
		t.Fatal("prior absence", err)
	}
	if err := os.WriteFile(path, []byte("fixed private fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0600, 0644, 0640, 0400, 0666} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		err := a.verifyPrivateFileMetadata(ctx, path, true)
		if (mode == 0600) != (err == nil) {
			t.Fatal("private mode proof", mode, err)
		}
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.verifyPrivateFileMetadata(ctx, path, false); err == nil {
		t.Fatal("presence accepted as prior absence")
	}
	link := filepath.Join(root, "linked")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := a.verifyPrivateFileMetadata(ctx, link, true); err == nil {
		t.Fatal("symlink accepted")
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(path, 65534, -1); err != nil {
			t.Fatal(err)
		}
		if err := a.verifyPrivateFileMetadata(ctx, path, true); err == nil {
			t.Fatal("foreign descriptor UID accepted")
		}
	}
}

func TestNativePrivateMetadataPinsContentDescriptorThroughReadback(t *testing.T) {
	ctx := context.Background()
	for _, drift := range []string{"leaf-replaced", "mode-widened", "bytes-changed"} {
		t.Run(drift, func(t *testing.T) {
			parent := t.TempDir()
			path := filepath.Join(parent, "secret")
			if err := os.WriteFile(path, []byte("original private bytes"), 0600); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(parent)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			observation, err := observePrivateFile(ctx, root, "secret")
			if err != nil || !bytes.Equal(observation.image.Data, []byte("original private bytes")) {
				t.Fatal("combined descriptor capture", err)
			}
			defer observation.close()
			switch drift {
			case "leaf-replaced":
				// Even equal bytes and mode on a second inode must not certify
				// the original still-open content descriptor.
				next := filepath.Join(parent, "replacement")
				if err := os.WriteFile(next, observation.image.Data, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(next, path); err != nil {
					t.Fatal(err)
				}
			case "mode-widened":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "bytes-changed":
				if err := os.WriteFile(path, []byte("third private bytes"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := observation.verify(ctx); err == nil {
				t.Fatal("stale content descriptor accepted after drift")
			}
		})
	}
}

func TestNativePrivateMetadataDriftAfterPreflightFencesParticipantAndEffect(t *testing.T) {
	ctx := context.Background()
	for _, name := range []string{"admin.token", "admin.credentials.json"} {
		for _, cut := range []string{"participant-noop", "participant-unequal", "effect-admission"} {
			t.Run(name+"/"+cut, func(t *testing.T) {
				parent := t.TempDir()
				path := filepath.Join(parent, name)
				beforeBytes := []byte("candidate private bytes")
				if err := os.WriteFile(path, beforeBytes, 0600); err != nil {
					t.Fatal(err)
				}
				a := &SelfUpdateFileAdapter{owned: func(string) error { return nil }}
				if _, err := a.readPrivateFileImage(ctx, path); err != nil {
					t.Fatal("preflight", err)
				}
				lease, err := restorejournal.OpenFileTarget(path)
				if err != nil {
					t.Fatal(err)
				}
				defer lease.Close()
				root, err := os.OpenRoot(parent)
				if err != nil {
					t.Fatal(err)
				}
				defer root.Close()
				admissions := 0
				target := fileGuardedTarget{Target: lease, root: root, name: name, check: func(context.Context) error { return nil }, admission: func(c context.Context, begin func() error) error {
					admissions++
					if err := os.Chmod(path, 0644); err != nil {
						return err
					}
					return begin()
				}}
				journalRoot := filepath.Join(parent, "restore")
				if err := os.Mkdir(journalRoot, 0700); err != nil {
					t.Fatal(err)
				}
				journal, err := restorejournal.Open(journalRoot, digestBytes([]byte("fixed private mode fixture")), map[string]restorejournal.Target{"token": target})
				if err != nil {
					t.Fatal(err)
				}
				defer journal.Close()
				afterBytes := []byte("restored private bytes")
				if cut == "participant-noop" {
					afterBytes = beforeBytes
				}
				if cut != "effect-admission" {
					if err := os.Chmod(path, 0644); err != nil {
						t.Fatal(err)
					}
				}
				outcome, err := journal.Execute(ctx, map[string]restorejournal.Image{"token": {Exists: true, Data: afterBytes}})
				if err == nil || outcome == restorejournal.Applied {
					t.Fatal("metadata drift bypassed actual participant/CAS", cut, outcome, err)
				}
				data, err := os.ReadFile(path)
				info, statErr := os.Stat(path)
				if err != nil || statErr != nil || !bytes.Equal(data, beforeBytes) || info.Mode().Perm() != 0644 {
					t.Fatal("refusal repaired permissions or replaced private bytes", cut)
				}
				if cut == "effect-admission" {
					if admissions != 1 || outcome != restorejournal.Blocked {
						t.Fatal("actual admission cut did not preserve recovery fence", admissions, outcome)
					}
					data, err := os.ReadFile(filepath.Join(journalRoot, "restore.private.json"))
					var doc retainedRestoreNodeJournal
					if err != nil || json.Unmarshal(data, &doc) != nil || doc.State != "prepared" {
						t.Fatal("uncertain restore record lost", err)
					}
				} else if admissions != 0 {
					t.Fatal("bad participant metadata reached effect admission")
				}
			})
		}
	}
}
