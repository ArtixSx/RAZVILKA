package updatecheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

// A release channel only narrows candidate discovery; it never grants install
// permission. Empty persisted policies deliberately retain stable-only behavior.
func ValidChannel(channel string) bool {
	return channel == "" || channel == "stable" || channel == "preview"
}
func NormalizedChannel(channel string) string {
	if channel == "" {
		return "stable"
	}
	return channel
}
func CanUpgradeChannel(current, target, channel string) bool {
	if !ValidChannel(channel) {
		return false
	}
	if NormalizedChannel(channel) == "stable" {
		return CanUpgrade(current, target)
	}
	if _, _, ok := parseComparableVersion(current); !ok {
		return false
	}
	if _, _, ok := parseComparableVersion(target); !ok || strings.Contains(target, "+") {
		return false
	}
	return compareVersions(current, target) < 0
}

// Never infer a channel from the installed RC. Opting into preview is explicit.
// Collection reads are bounded. A release is still pinned by ID and asset
// digest at prepare/apply, not fetched from a moving branch.
func selectChannelMetadata(data []byte, channel string) ([]byte, error) {
	if !ValidChannel(channel) {
		return nil, errors.New("release-channel-invalid")
	}
	if NormalizedChannel(channel) == "stable" {
		return data, nil
	}
	var entries []json.RawMessage
	if json.Unmarshal(data, &entries) != nil || len(entries) > 30 {
		return nil, errors.New("release-collection-invalid")
	}
	var best []byte
	tag := ""
	for _, item := range entries {
		var r struct {
			Tag        string `json:"tag_name"`
			Page       string `json:"html_url"`
			Draft      bool   `json:"draft"`
			Prerelease bool   `json:"prerelease"`
		}
		if json.Unmarshal(item, &r) != nil || r.Draft || r.Page != "https://github.com/"+officialRepository+"/releases/tag/"+r.Tag {
			continue
		}
		_, pre, ok := parseComparableVersion(r.Tag)
		if !ok || strings.Contains(r.Tag, "+") || (pre == "") == r.Prerelease {
			continue
		}
		if best == nil || compareVersions(r.Tag, tag) > 0 {
			best = bytes.Clone(item)
			tag = r.Tag
		}
	}
	if best == nil {
		return nil, errors.New("release-channel-empty")
	}
	return best, nil
}

func comparePrerelease(a, b string) int {
	aa, bb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(aa) && i < len(bb); i++ {
		if aa[i] == bb[i] {
			continue
		}
		an, bn := allDigits(aa[i]), allDigits(bb[i])
		if an && bn {
			if len(aa[i]) < len(bb[i]) {
				return -1
			}
			if len(aa[i]) > len(bb[i]) {
				return 1
			}
		} else if an != bn {
			if an {
				return -1
			}
			return 1
		}
		if aa[i] < bb[i] {
			return -1
		}
		return 1
	}
	if len(aa) < len(bb) {
		return -1
	}
	if len(aa) > len(bb) {
		return 1
	}
	return 0
}
func allDigits(s string) bool { return s != "" && strings.Trim(s, "0123456789") == "" }
