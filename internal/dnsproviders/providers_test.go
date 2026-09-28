package dnsproviders

import (
	"net/netip"
	"testing"

	"github.com/qdm12/dns/v2/pkg/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Providers_Get(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		name         string
		providerName string
		errWrapped   error
		errMessage   string
	}{
		"mullvad_lowercase": {
			name:         "mullvad",
			providerName: "Mullvad",
		},
		"mullvad_uppercase": {
			name:         "MULLVAD",
			providerName: "Mullvad",
		},
		"library_provider": {
			name:         "cloudflare",
			providerName: "Cloudflare",
		},
		"unknown": {
			name:       "unknown",
			errWrapped: provider.ErrParseProviderNameUnknown,
			errMessage: "provider does not match any known providers: unknown",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			providers := New()
			dnsProvider, err := providers.Get(testCase.name)

			assert.ErrorIs(t, err, testCase.errWrapped)
			if testCase.errWrapped != nil {
				assert.EqualError(t, err, testCase.errMessage)
			}
			assert.Equal(t, testCase.providerName, dnsProvider.Name)
		})
	}
}

func Test_mullvad(t *testing.T) {
	t.Parallel()

	dnsProvider := mullvad()

	ipv4 := netip.MustParseAddr("194.242.2.2")
	ipv6 := netip.MustParseAddr("2a07:e340::2")
	expected := provider.Provider{
		Name: "Mullvad",
		DoT: provider.DoTServer{
			IPv4: []netip.AddrPort{netip.AddrPortFrom(ipv4, 853)},
			IPv6: []netip.AddrPort{netip.AddrPortFrom(ipv6, 853)},
			Name: "dns.mullvad.net",
		},
		DoH: provider.DoHServer{
			URL:  "https://dns.mullvad.net/dns-query",
			IPv4: []netip.Addr{ipv4},
			IPv6: []netip.Addr{ipv6},
		},
	}
	assert.Equal(t, expected, dnsProvider)
	require.Empty(t, dnsProvider.Plain.IPv4)
	require.Empty(t, dnsProvider.Plain.IPv6)
}
