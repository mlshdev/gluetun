package daita

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func Test_deviceConfig_uapiString(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		config   deviceConfig
		expected string
	}{
		"minimal": {
			config: deviceConfig{
				privateKey: wgtypes.Key{1},
				peer: peerConfig{
					publicKey: wgtypes.Key{2},
					endpoint:  netip.MustParseAddrPort("1.2.3.4:51820"),
				},
			},
			expected: "private_key=0100000000000000000000000000000000000000000000000000000000000000\n" +
				"replace_peers=true\n" +
				"public_key=0200000000000000000000000000000000000000000000000000000000000000\n" +
				"preshared_key=0000000000000000000000000000000000000000000000000000000000000000\n" +
				"endpoint=1.2.3.4:51820\n" +
				"persistent_keepalive_interval=0\n" +
				"replace_allowed_ips=true\n",
		},
		"full": {
			config: deviceConfig{
				privateKey:   wgtypes.Key{1},
				firewallMark: 51820,
				peer: peerConfig{
					publicKey:           wgtypes.Key{2},
					presharedKey:        wgtypes.Key{3},
					endpoint:            netip.MustParseAddrPort("[2001:db8::1]:443"),
					persistentKeepalive: 25 * time.Second,
					allowedIPs: []netip.Prefix{
						netip.MustParsePrefix("0.0.0.0/0"),
						netip.MustParsePrefix("::/0"),
					},
				},
			},
			expected: "private_key=0100000000000000000000000000000000000000000000000000000000000000\n" +
				"fwmark=51820\n" +
				"replace_peers=true\n" +
				"public_key=0200000000000000000000000000000000000000000000000000000000000000\n" +
				"preshared_key=0300000000000000000000000000000000000000000000000000000000000000\n" +
				"endpoint=[2001:db8::1]:443\n" +
				"persistent_keepalive_interval=25\n" +
				"replace_allowed_ips=true\n" +
				"allowed_ip=0.0.0.0/0\n" +
				"allowed_ip=::/0\n",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, testCase.expected, testCase.config.uapiString())
		})
	}
}
