//go:build linux && razvilka_native_fixture

package startuptools

import (
	"context"
	"errors"
	"strings"
	"syscall"
	"testing"
)

type acquireDiagnosticCycle struct{}

func (c *acquireDiagnosticCycle) Error() string { panic("must not inspect free-form error text") }
func (c *acquireDiagnosticCycle) Unwrap() error { return c }

func TestNativeFixtureAcquireDiagnosticsBoundedAndPrivate(t *testing.T) {
	err := at("ACQUIRE", errors.Join(at("CHECK_HELD_FILE", syscall.EBADF), context.DeadlineExceeded, at("PRIVATE_SECRET", errors.New("secret path or command output"))))
	got := nativeFixtureAcquireStages(err)
	for _, expected := range []string{"ACQUIRE", "CHECK_HELD_FILE", "EBADF", "DEADLINE", "TOOLS_STAGE_UNCLASSIFIED"} {
		if !strings.Contains(got, expected) {
			t.Fatal("missing fixed category", expected, got)
		}
	}
	if strings.Contains(got, "SECRET") || strings.Contains(got, "secret") || len(strings.Split(got, "/")) > 16 {
		t.Fatal("unbounded or private diagnostic", got)
	}
	if got := nativeFixtureAcquireStages(&acquireDiagnosticCycle{}); got != "TRUNCATED" {
		t.Fatal("cyclic error walk", got)
	}
	if got := nativeFixtureAcquireStages(at("PATH_OWNER_OPT_WRITE_MODE", nil)); !strings.Contains(got, "PATH_OWNER_OPT_WRITE_MODE") {
		t.Fatal("fixed path category lost", got)
	}
	if got := nativeFixtureAcquireStages(at("PATH_OWNER_SECRET_WRITE_MODE", nil)); strings.Contains(got, "SECRET") {
		t.Fatal("foreign path category leaked", got)
	}
}
