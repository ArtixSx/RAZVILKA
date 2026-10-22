package dataplane

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/ArtixSx/razvilka/internal/engineconfig"
	"github.com/ArtixSx/razvilka/internal/systemprobe"
)

var ErrNFQWSFirstStartScope = errors.New("NFQWS2: нельзя подтвердить запуск для всей локальной сети; проверьте политику Keenetic и текущий WAN-интерфейс. Настройки политики и исключённых устройств не изменены")

func (a *NFQWS2Adapter) reviewFirstStartScope(parent context.Context, config []byte, running bool) error {
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	owner, err := a.owner()
	if err != nil {
		return err
	}
	interfaces, err := engineconfig.NFQWSFirstStartScope(config, owner)
	if err != nil || len(interfaces) != 1 {
		return ErrNFQWSFirstStartScope
	}
	var policies []byte
	wan := ""
	if a.firstStartScopeRead != nil {
		policies, wan, err = a.firstStartScopeRead(ctx)
	} else {
		source := a.inactivity
		if source == nil || source.provider == nil || source.current(ctx) != nil {
			return ErrNFQWSFirstStartScope
		}
		policies, err = source.provider.ReadReviewedStockIPPolicies(ctx)
		if err == nil {
			profile, readErr := systemprobe.FreshWANProfile(ctx)
			err = readErr
			wan = profile.WANInterface
		}
		if err == nil {
			err = source.current(ctx)
		}
	}
	if err != nil || interfaces[0] != wan || !nfqws2KnownEmptyStockPolicies(policies) {
		return ErrNFQWSFirstStartScope
	}
	if running {
		overlay, exists, err := nfqws2Read(a.ConfigPath + ".run")
		if err != nil || !exists || engineconfig.NFQWSFirstStartRunningAllLAN(config, owner, overlay) != nil {
			return ErrNFQWSFirstStartScope
		}
	}
	return ctx.Err()
}

// Actual NC1812 stdout for a successful empty policy table is two ESC[K
// clear-to-EOL sequences. Unknown nonempty/truncated text is never absence;
// configured-policy parsing requires a separately reviewed actual formatter.
func nfqws2KnownEmptyStockPolicies(raw []byte) bool {
	return len(raw) == 0 || bytes.Equal(raw, []byte{0x1b, '[', 'K', 0x1b, '[', 'K'})
}
