package dnscontrol

import (
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
)

// Keep HTTP cache metadata separate from the DNS message. In particular, do
// not rewrite SOA data or EDNS flag fields in order to age a DNS answer.
type dohResponse struct {
	wire []byte
	age  uint64
}

func readDoHResponse(response *http.Response) (dohResponse, error) {
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return dohResponse{}, dohStatusError(response.StatusCode)
	}
	media, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || media != "application/dns-message" || len(response.Header.Values("Content-Type")) != 1 {
		return dohResponse{}, errDNSAnswer
	}
	var age uint64
	if values := response.Header.Values("Age"); len(values) > 0 {
		if len(values) != 1 {
			return dohResponse{}, errDNSAnswer
		}
		value := strings.TrimSpace(values[0])
		if value == "" {
			return dohResponse{}, errDNSAnswer
		}
		for _, digit := range value {
			if digit < '0' || digit > '9' {
				return dohResponse{}, errDNSAnswer
			}
		}
		age, err = strconv.ParseUint(value, 10, 64)
		if err != nil {
			return dohResponse{}, errDNSAnswer
		}
	}
	wire, err := io.ReadAll(io.LimitReader(response.Body, 65536))
	if err != nil {
		return dohResponse{}, err
	}
	if len(wire) > 65535 {
		return dohResponse{}, errDNSAnswer
	}
	return dohResponse{wire: wire, age: age}, nil
}

func remainingDNSTTL(ttl *uint32, age uint64) *uint32 {
	if ttl == nil {
		return nil
	}
	remaining := uint32(0)
	if uint64(*ttl) > age {
		remaining = *ttl - uint32(age)
	}
	return &remaining
}
