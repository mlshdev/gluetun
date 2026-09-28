package daita

import (
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/wireguard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Settings_Check(t *testing.T) {
	t.Parallel()

	const validKey = "oMNSf/zJ0pt1ciy+qIRk8Rlyfs9accwuRLnKd85Yl1Q="

	makeSettings := func(addresses []netip.Prefix, exit *Exit) Settings {
		settings := Settings{
			Wireguard: wireguard.Settings{
				PrivateKey: validKey,
				PublicKey:  validKey,
				Endpoint:   netip.MustParseAddrPort("1.2.3.4:51820"),
				Addresses:  addresses,
				AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
			},
			Exit: exit,
		}
		settings.SetDefaults()
		return settings
	}
	ipv4Addresses := []netip.Prefix{netip.MustParsePrefix("10.64.1.2/32")}
	ipv6Addresses := []netip.Prefix{netip.MustParsePrefix("fc00:bbbb::2/128")}

	testCases := map[string]struct {
		settings   Settings
		errWrapped error
		errMessage string
	}{
		"invalid_wireguard_settings": {
			settings:   makeSettings(nil, nil),
			errMessage: "wireguard settings: interface address is missing",
		},
		"singlehop": {
			settings: makeSettings(ipv6Addresses, nil),
		},
		"multihop": {
			settings: makeSettings(ipv4Addresses, &Exit{
				PublicKey: validKey,
				Endpoint:  netip.MustParseAddrPort("5.6.7.8:51820"),
			}),
		},
		"invalid_exit_public_key": {
			settings: makeSettings(ipv4Addresses, &Exit{
				PublicKey: "invalid",
				Endpoint:  netip.MustParseAddrPort("5.6.7.8:51820"),
			}),
			errMessage: "parsing exit public key: ",
		},
		"exit_endpoint_ipv6": {
			settings: makeSettings(ipv4Addresses, &Exit{
				PublicKey: validKey,
				Endpoint:  netip.MustParseAddrPort("[::1]:51820"),
			}),
			errWrapped: errExitEndpointNotIPv4,
			errMessage: "exit endpoint is not IPv4: ::1",
		},
		"exit_endpoint_port_missing": {
			settings: makeSettings(ipv4Addresses, &Exit{
				PublicKey: validKey,
				Endpoint:  netip.MustParseAddrPort("5.6.7.8:0"),
			}),
			errWrapped: errExitEndpointPortMissing,
			errMessage: "exit endpoint port is missing",
		},
		"multihop_without_ipv4_address": {
			settings: makeSettings(ipv6Addresses, &Exit{
				PublicKey: validKey,
				Endpoint:  netip.MustParseAddrPort("5.6.7.8:51820"),
			}),
			errWrapped: errInterfaceIPv4AddrMissing,
			errMessage: "interface IPv4 address is missing",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := testCase.settings.Check()

			if testCase.errWrapped != nil {
				require.ErrorIs(t, err, testCase.errWrapped)
			}
			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
