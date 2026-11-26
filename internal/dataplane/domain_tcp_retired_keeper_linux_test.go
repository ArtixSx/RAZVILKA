//go:build linux

package dataplane

import (
	"testing"
)

// Real journal/alias/global descriptor transfer, with no native process,
// kernel proof or cleanup grant. This cannot invoke the actual Remove lane.
func TestDomainRetiredKeeperTransfersOnlyOriginalGlobalFD(t *testing.T) {
	for _, change := range []string{"none", "old-alias-close-error", "foreign-global", "copied-owner", "missing-global"} {
		t.Run(change, func(t *testing.T) {
			k, ctx := domainTCPKeeperFilesFixture(t)
			p := &XrayDomainTCPExecutionResource{scope: k.cursor.scope, records: k.records}
			p.self = p
			o := &domainTCPStandbyOwner{process: p}
			o.self = o
			if err := k.records.detachStandbyAlias(ctx, o); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = o.closeGlobalRecord() })
			alias, global := k.records.files[1], o.latest
			if alias == nil || global == nil || alias == global {
				t.Fatal("actual distinct writer descriptors missing")
			}
			switch change {
			case "old-alias-close-error":
				if err := alias.Close(); err != nil {
					t.Fatal(err)
				}
			case "foreign-global":
				if err := k.records.root.WriteAtomic("latest-execution.json", k.image, 0600); err != nil {
					t.Fatal(err)
				}
			case "copied-owner":
				o.self = &domainTCPStandbyOwner{}
			case "missing-global":
				o.latest = nil
				t.Cleanup(func() { _ = global.Close() })
			}
			accepted, err := transferDomainStandbyGlobal(k.records, o, k.image)
			if change == "none" || change == "old-alias-close-error" {
				if !accepted || k.records.files[1] != global || o.latest != nil || k.records.standbyAlias.Load() {
					t.Fatal("actual accepted FD lost on transfer", accepted, err)
				}
				if _, e := global.Stat(); e != nil {
					t.Fatal("accepted global descriptor closed", e)
				}
				if _, e := alias.Stat(); e == nil {
					t.Fatal("actual alias Close ACK missing")
				}
				if change == "old-alias-close-error" {
					if err == nil || k.records.closeErr == nil || k.records.current(ctx, true) == nil {
						t.Fatal("actual Close error hidden", err)
					}
					return
				}
				if err != nil || k.records.current(ctx, true) != nil {
					t.Fatal("original metadata holder not current", err)
				}
				return
			}
			if accepted || err == nil {
				t.Fatal("foreign or absent FD transferred", accepted, err)
			}
			if k.records.files[1] != alias || !k.records.standbyAlias.Load() {
				t.Fatal("refusal changed original alias ownership")
			}
			if _, e := global.Stat(); e != nil {
				t.Fatal("refusal closed original global", e)
			}
		})
	}
}
