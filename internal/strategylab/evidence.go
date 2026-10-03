package strategylab

import "errors"

const (
	OutcomePass         = "pass"
	OutcomeServiceFail  = "service-fail"
	OutcomeLocalError   = "local-error"
	OutcomeInconclusive = "inconclusive"
	LevelPacket         = "packet"
	LevelHTTP           = "http"
	LevelMedia          = "media"
	LevelVoice          = "voice"
	LevelGame           = "game"
)

var scenarioLevels = []string{LevelPacket, LevelHTTP, LevelMedia, LevelVoice, LevelGame}

// Coverage keeps each scenario's freshness independently. A fresh web pass
// cannot refresh an old media/voice/game observation.
type Coverage struct {
	Level        string `json:"level"`
	LastPassedAt string `json:"last_passed_at"`
	Fresh        bool   `json:"fresh"`
}

func validLevel(level string) bool {
	for _, value := range scenarioLevels {
		if level == value {
			return true
		}
	}
	return false
}

func stagePassed(e Evidence, stage string) bool {
	found := false
	for _, s := range e.Stages {
		if s.Stage == stage {
			if s.Status != "pass" {
				return false
			}
			found = true
		}
	}
	return found
}

func localFailure(e Evidence) bool {
	for _, s := range e.Stages {
		if s.Status != "fail" {
			continue
		}
		switch s.Stage {
		case "preflight", "dns", "socket", "nfqws2", "nfqws2-exit", "firewall", "cleanup":
			return true
		}
	}
	return false
}

// Evidence is supplied by trusted executors, never by arbitrary browser input.
// Older stored observations are classified conservatively on read.
func normalizeEvidence(e *Evidence) error {
	if localFailure(*e) {
		e.Outcome = OutcomeLocalError
		e.Success = false
	} else if e.Outcome == "" {
		switch {
		case e.Success && e.RouteConfirmed:
			e.Outcome = OutcomePass
		case !e.Success && e.RouteConfirmed:
			e.Outcome = OutcomeServiceFail
		default:
			e.Outcome = OutcomeInconclusive
		}
	}
	switch e.Outcome {
	case OutcomePass:
		if !e.Success || !e.RouteConfirmed {
			return errors.New("pass requires successful confirmed route")
		}
	case OutcomeServiceFail:
		if e.Success || !e.RouteConfirmed {
			return errors.New("service failure requires a confirmed tested route")
		}
	case OutcomeLocalError, OutcomeInconclusive:
		if e.Success {
			return errors.New("local or inconclusive evidence cannot be successful")
		}
	default:
		return errors.New("unknown evidence outcome")
	}
	levels := evidenceLevels(*e)
	if e.Level != "" {
		if !validLevel(e.Level) {
			return errors.New("unknown evidence level")
		}
		if e.Success && !containsLevel(levels, e.Level) {
			return errors.New("evidence level requires its own passed scenario stage")
		}
	} else if e.Success {
		e.Level = LevelPacket
		if containsLevel(levels, LevelHTTP) {
			e.Level = LevelHTTP
		}
	}
	return nil
}

func reputationEvidence(e Evidence) bool {
	return e.Outcome == OutcomePass || e.Outcome == OutcomeServiceFail
}

func evidenceLevels(e Evidence) []string {
	if !e.Success || !e.RouteConfirmed {
		return nil
	}
	levels := []string{LevelPacket}
	if stagePassed(e, "read") || stagePassed(e, "http") {
		levels = append(levels, LevelHTTP)
	}
	for _, level := range []string{LevelMedia, LevelVoice, LevelGame} {
		if stagePassed(e, level) {
			levels = append(levels, level)
		}
	}
	return levels
}

func containsLevel(levels []string, level string) bool {
	for _, value := range levels {
		if value == level {
			return true
		}
	}
	return false
}
