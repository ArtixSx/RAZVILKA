//go:build linux && (amd64 || arm64) && !razvilka_native_fixture

package startuptools

import (
	"os"
	"time"
)

type domainBaselineReadMeasurement struct{}

const domainBaselineReadTimingEnabled = false

func beginDomainBaselineReadMeasurement([]string, bool) *domainBaselineReadMeasurement { return nil }
func (*domainBaselineReadMeasurement) now() time.Time                                  { return time.Time{} }
func (*domainBaselineReadMeasurement) phase(domainBaselineReadStage, time.Time)        {}
func (*domainBaselineReadMeasurement) startResult(time.Time, bool)                     {}
func (*domainBaselineReadMeasurement) waitResult(*os.ProcessState, bool)               {}
func (*domainBaselineReadMeasurement) output(bool, bool, bool)                         {}
func (*domainBaselineReadMeasurement) finish(bool)                                     {}
