//go:build linux

package updatecheck

import (
	"context"
	"os"
	"reflect"
	"testing"
	"time"
)

// ROOT opt-in component measurement: actual full /proc executable/argv/birth
// reads on the running test image. This is not an authenticated H/S/C group,
// release-artifact observation, DNS inactivity proof or future-update result.
func TestOrdinaryObservationNativeActualReadComponent(t *testing.T) {
	if os.Getenv("RAZVILKA_ORDINARY_OBSERVATION_NATIVE") != "1" {
		t.Skip("ROOT actual Linux dependency opt-in")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	before, err := bootstrapControllerAt(ctx, os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	for invocation := 0; invocation < 2; invocation++ {
		bounded, stop := context.WithTimeout(ctx, 2*time.Second)
		image, err := newOrdinaryExecutableImage(bounded, before.Process.ExecutableSHA256)
		if err != nil {
			stop()
			t.Fatal(err)
		}
		started := time.Now()
		for fact := 0; fact < 14; fact++ { // 28 real full executable occurrences.
			current, readErr := image.controllerAt(os.Getpid())
			if readErr != nil || !reflect.DeepEqual(before, current) {
				image.clear()
				stop()
				t.Fatal("actual process/exe/argv/birth component changed", fact, readErr)
			}
		}
		readTime, retained := time.Since(started), len(image.image)
		started = time.Now()
		image.clear()
		clearTime := time.Since(started)
		if err := bounded.Err(); err != nil {
			stop()
			t.Fatal("component exceeded original context including clear", err)
		}
		stop()
		t.Logf("actual ordinary read component: invocation=%d full_occurrences=28 retained_bytes=%d reads=%s clear=%s; no whole-DNS acceptance", invocation, retained, readTime, clearTime)
	}
}
