package dataplane

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestWGCommonPostRenameFailureRetainsOriginalPublication(t *testing.T) {
	for _, failure := range []string{"directory-sync", "cancellation"} {
		t.Run(failure, func(t *testing.T) {
			a, _, plan, _, ref, _, _ := committedWGNetworkEffectFixture(t)
			a, owner, original, _, _, _ := wgNetworkCommandOwnerForPlan(t, a, plan)
			compiled, err := a.compileWGNetworkEffects(ref)
			if err != nil {
				t.Fatal(err)
			}
			path := a.wgPolicyGenerationRoot(ref, "")
			ctx := wgCommonWriterContext(original, a, ref, compiled, path)
			s, err := openPolicyEffectSession(ctx, compiled.plan, path, a.policyReceiptOptions)
			if err != nil {
				t.Fatal(err)
			}
			defer s.close()
			if err := s.load(ctx); err != nil {
				t.Fatal(err)
			}
			borrow, err := newPolicyEffectReceiptBorrow(s)
			if err != nil {
				t.Fatal(err)
			}
			defer borrow.close()
			s.borrow = borrow
			borrow.requireDocument()
			if err := s.save(ctx); err != nil {
				t.Fatal("original first publication", err)
			}
			old := owner.common[path].fileInfo
			// An actual prior child attempt retains the native prerequisites;
			// its kernel effects remain this fixture's explicit empty model.
			t.Setenv("RAZVILKA_WG_COMMAND_CLI_MODEL", "1")
			t.Setenv("RAZVILKA_WG_COMMAND_TEST_MARKER", path+"-commands")
			if _, err := a.run(ctx, a.IP, "link", "add", "rz-wg", "type", "wireguard"); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			s.options.fault = func(point string, _ int) error {
				if point != "wg-directory-sync" {
					return nil
				}
				if failure == "cancellation" {
					cancel()
					return nil
				}
				return errors.New("modeled directory fsync refusal after real rename")
			}
			s.doc.Steps[0].State = "cleanup-intent"
			if err := s.save(ctx); err == nil {
				t.Fatal("post-rename failure received ACK")
			}
			p := owner.common[path]
			if p == nil || p.ack || os.SameFile(old, p.fileInfo) || p.currentFiles() != nil {
				t.Fatal("failed publication discarded its original new inode")
			}
			if p.current(original) == nil {
				t.Fatal("forward accepted missing publication ACK")
			}
			cleanup, closeCleanup := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			defer closeCleanup()
			cleanup, err = owner.cleanupContext(cleanup)
			if err != nil {
				t.Fatal(err)
			}
			if p.current(cleanup) != nil || checkWGOriginalLoadedReceipt(cleanup, borrow) != nil || checkWGCommonBeforePublication(cleanup, s.policyAdditionSession) != nil {
				t.Fatal("own post-rename publication blocked original cleanup")
			}
			s.options.fault = nil
			if err := s.save(cleanup); err != nil || !owner.common[path].ack {
				t.Fatal("original cleanup could not publish its own retained inode", err)
			}
		})
	}
}
