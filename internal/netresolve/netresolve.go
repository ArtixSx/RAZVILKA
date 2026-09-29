// Package netresolve retries name lookups that time out.
//
// KeeneticOS writes "timeout:1 attempts:1" to resolv.conf, so the standard
// resolver sends one query and gives up after a second. The router's DNS
// proxy often misses that second for a name it has not cached yet (for
// example with an encrypted upstream), and the next query is answered from
// its cache. A definite answer, such as a name that does not exist, is not
// retried.
package netresolve

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"
)

const attempts = 3

var lookup = net.DefaultResolver.LookupNetIP

// LookupNetIP is net.DefaultResolver.LookupNetIP with bounded retries of
// timeouts and temporary failures, within the caller's context.
func LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	var err error
	for attempt := 1; ; attempt++ {
		var addresses []netip.Addr
		addresses, err = lookup(ctx, network, host)
		if err == nil || attempt == attempts || !retryable(err) || ctx.Err() != nil {
			return addresses, err
		}
		timer := time.NewTimer(time.Duration(attempt) * 200 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, err
		case <-timer.C:
		}
	}
}

func retryable(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && !dnsErr.IsNotFound && (dnsErr.IsTimeout || dnsErr.IsTemporary)
}
