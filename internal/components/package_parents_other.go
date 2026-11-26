//go:build !linux

package components

func (m *Manager) withPackageParents(_ []string, run func() ([]byte, error)) ([]byte, error) {
	return run()
}
