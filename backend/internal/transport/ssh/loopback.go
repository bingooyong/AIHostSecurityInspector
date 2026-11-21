package ssh

import (
	"errors"
	"net/netip"
)

var ErrNonLoopback = errors.New("ssh target must be a loopback address")

func ParseLoopbackAddress(address string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(address)
	if err != nil || !ip.IsLoopback() {
		return netip.Addr{}, ErrNonLoopback
	}
	return ip, nil
}
