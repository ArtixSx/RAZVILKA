// Package nodecleanup is a conservative, pure filter for proposed cleanup.
// It has no store access and never grants permission to remove referenced nodes.
package nodecleanup

import (
	"sort"
	"time"
)

type Check struct {
	ServiceID, Network, Route, Verdict, Level, Code, State string
	DirectLeak                                             bool
	At, Until                                              time.Time
}

// Eligible requires two separate, fresh transport/egress failures in the same
// context, with a working independent control. An application-specific failure
// does not make a node dead for other services. Unknown/new error codes fail shut.
func Eligible(id, service, network string, checks []Check, now time.Time, control bool) bool {
	if id == "" || service == "" || network == "" || !control {
		return false
	}
	var own []Check
	for _, c := range checks {
		if c.Network != network || c.Route != "sing-box:"+id {
			continue
		}
		if c.At.After(now) {
			return false
		}
		if c.At.IsZero() || !c.Until.After(now) || now.Sub(c.At) > 10*time.Minute {
			continue
		}
		// Any current success protects a node, including success for another service.
		if c.Verdict == "PASS" {
			return false
		}
		if c.ServiceID == service {
			own = append(own, c)
		}
	}
	sort.Slice(own, func(i, j int) bool { return own[i].At.After(own[j].At) })
	if len(own) < 2 || own[0].At.Sub(own[1].At) < 10*time.Second {
		return false
	}
	for _, c := range own[:2] {
		if c.Verdict != "ERROR" && c.Verdict != "BLOCKED" {
			return false
		}
		switch c.Code {
		case "node-transport-failed":
			if c.Level != "transport" {
				return false
			}
		case "node-egress-failed":
			if c.Level != "protocol" {
				return false
			}
		default:
			return false
		}
	}
	return true
}
