// Package evidence defines the shared proof levels used by control-plane
// subsystems. The levels describe what RAZVILKA actually observed; they must
// never be promoted from desired or planned state.
package evidence

import "strings"

// Level is an ordered assurance level. String values are part of the public
// API and are intentionally stable for the Web UI and exported diagnostics.
type Level string

const (
	None       Level = "none"
	Catalog    Level = "catalog"
	Configured Level = "configured"
	Runtime    Level = "runtime"
	Route      Level = "route-confirmed"
	Service    Level = "service-confirmed"
)

var ranks = map[Level]int{
	None: 0, Catalog: 1, Configured: 2, Runtime: 3, Route: 4, Service: 5,
}

// Valid reports whether the level is one of the stable public values.
func (level Level) Valid() bool {
	_, ok := ranks[level]
	return ok
}

// AtLeast compares two assurance levels without relying on lexical ordering.
func (level Level) AtLeast(required Level) bool {
	actualRank, actualOK := ranks[level]
	requiredRank, requiredOK := ranks[required]
	return actualOK && requiredOK && actualRank >= requiredRank
}

// Stronger returns the higher valid level. Invalid values are treated as None.
func Stronger(left, right Level) Level {
	if !left.Valid() {
		left = None
	}
	if !right.Valid() {
		right = None
	}
	if ranks[right] > ranks[left] {
		return right
	}
	return left
}

// FromProbe derives an assurance level from observed probe facts. A successful
// endpoint response on the current path proves runtime reachability, but not a
// particular bypass. Only an isolated, route-confirmed response proves that a
// service works through the named route.
func FromProbe(status string, routeConfirmed bool) Level {
	status = strings.ToLower(strings.TrimSpace(status))
	if status == "not-ready" || status == "pending" || status == "adapter-pending" || status == "" {
		return None
	}
	if routeConfirmed {
		if status == "pass" || status == "partial" {
			return Service
		}
		return Route
	}
	return Runtime
}
