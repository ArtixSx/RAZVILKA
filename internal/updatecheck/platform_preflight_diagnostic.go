package updatecheck

import "strings"

// Only fixed installer messages select a public failure code. Captured output
// remains bounded and private; paths, config, tokens and subprocess errors are
// never returned or persisted in the public job message.
func installerPreflightFailureCode(output string) string {
	for _, line := range strings.Split(output, "\n") {
		switch strings.TrimSpace(line) {
		case "Target binary has an incompatible self update schema; installation unchanged",
			"Target binary cannot preserve self update recovery; installation unchanged":
			return "installer-preflight-self-update-schema-refused"
		case "Self update metadata is unknown or incompatible; installation unchanged",
			"Self update metadata exceeds its output limit; installation unchanged",
			"Bounded self update metadata probe is unavailable; installation unchanged":
			return "installer-preflight-self-update-metadata-refused"
		case "Target binary cannot read all retained node history; installation unchanged",
			"Retained node history compatibility not confirmed; installation unchanged":
			return "installer-preflight-node-history-refused"
		case "Target version cannot read the current autonomy state; installation unchanged",
			"Autonomy compatibility not confirmed":
			return "installer-preflight-autonomy-refused"
		}
	}
	return "installer-preflight-refused"
}
