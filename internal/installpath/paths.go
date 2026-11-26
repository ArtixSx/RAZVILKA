// Package installpath defines the fixed layout for clean RAZVILKA 0.20.0
// installations and subsequent updates. Shared Entware /opt/var is outside
// the application's private ownership boundary. There are no runtime overrides.
package installpath

const (
	Root   = "/opt/razvilka"
	State  = Root + "/state"
	Run    = Root + "/run"
	Cache  = Root + "/cache"
	Log    = Root + "/log"
	Config = "/opt/etc/razvilka"

	// ManagedUSQUE is the binary-only installation owned by RAZVILKA.
	ManagedUSQUE = State + "/components/usque"

	// ManagedMASQUESingBox is a private TUN dependency of USQUE.
	ManagedMASQUESingBox = State + "/components/masque-sidecar/sing-box"
)
