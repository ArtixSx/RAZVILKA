package components

import "sync"

type boundedPackageLog struct {
	mu    sync.Mutex
	bytes []byte
}

func (l *boundedPackageLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := len(p)
	if len(p) > 8192 {
		p = p[len(p)-8192:]
	}
	l.bytes = append(l.bytes, p...)
	if len(l.bytes) > 8192 {
		l.bytes = l.bytes[len(l.bytes)-8192:]
	}
	return n, nil
}
func (l *boundedPackageLog) data() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]byte(nil), l.bytes...)
}
