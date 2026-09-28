package daita

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/qdm12/gluetun/internal/wireguard"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Settings struct {
	// Wireguard contains the settings for the DAITA relay, which is
	// the entry relay if Exit is set.
	Wireguard wireguard.Settings
	// Exit is the exit relay to reach through the DAITA entry relay.
	// It is nil for a single hop connection.
	Exit *Exit
	// PostQuantum upgrades the tunnels to quantum-resistant tunnels,
	// using pre-shared keys negotiated with post-quantum key encapsulation.
	PostQuantum bool
}

type Exit struct {
	// PublicKey is the exit relay public key in base 64 format.
	PublicKey string
	// Endpoint is the exit relay IPv4 address and port, reached
	// from within the entry relay tunnel.
	Endpoint netip.AddrPort
}

func (s *Settings) SetDefaults() {
	s.Wireguard.SetDefaults()
}

var (
	errExitEndpointNotIPv4      = errors.New("exit endpoint is not IPv4")
	errExitEndpointPortMissing  = errors.New("exit endpoint port is missing")
	errInterfaceIPv4AddrMissing = errors.New("interface IPv4 address is missing")
)

func (s Settings) Check() (err error) {
	err = s.Wireguard.Check()
	if err != nil {
		return fmt.Errorf("wireguard settings: %w", err)
	}

	if s.Exit == nil {
		return nil
	}

	_, err = wgtypes.ParseKey(s.Exit.PublicKey)
	if err != nil {
		return fmt.Errorf("parsing exit public key: %w", err)
	}

	switch {
	case !s.Exit.Endpoint.Addr().Is4():
		return fmt.Errorf("%w: %s", errExitEndpointNotIPv4, s.Exit.Endpoint.Addr())
	case s.Exit.Endpoint.Port() == 0:
		return errExitEndpointPortMissing
	}

	_, err = tunnelIPv4(s.Wireguard.Addresses)
	if err != nil {
		return err
	}

	return nil
}

// tunnelIPv4 returns the first IPv4 address of the addresses given,
// used as source address of the packets sent to the exit relay.
func tunnelIPv4(addresses []netip.Prefix) (address netip.Addr, err error) {
	for _, prefix := range addresses {
		if prefix.Addr().Is4() {
			return prefix.Addr(), nil
		}
	}
	return netip.Addr{}, errInterfaceIPv4AddrMissing
}
