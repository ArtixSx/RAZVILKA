//go:build linux

package physicalscope

import (
	"context"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"
)

func TestDumpScratchNeverAliasesReturnedKernelMessages(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	original, err := dump(ctx, 18, 0)
	if err != nil || len(original) == 0 {
		t.Fatal("actual route socket link dump", err)
	}
	snapshot := slices.Clone(original)
	for i := range snapshot {
		snapshot[i].data = slices.Clone(snapshot[i].data)
	}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 3 {
				if _, err := dump(ctx, 18, 0); err != nil {
					t.Error("fresh route dump", err)
					return
				}
			}
		})
	}
	workers.Wait()
	if !reflect.DeepEqual(original, snapshot) {
		t.Fatal("later receive modified a retained kernel message")
	}
}
