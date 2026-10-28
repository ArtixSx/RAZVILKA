//go:build !linux

package main

func exactNodeIPv6Unavailable() bool { return false }
