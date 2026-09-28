package dnsproviders

import (
	"net/netip"

	"github.com/qdm12/dns/v2/pkg/provider"
)

// mullvad returns the Mullvad DNS provider, which only supports encrypted DNS.
// See https://mullvad.net/en/help/dns-over-https-and-dns-over-tls
func mullvad() provider.Provider {
	ipv4 := netip.MustParseAddr("194.242.2.2")
	ipv6 := netip.MustParseAddr("2a07:e340::2")
	const dotPort = 853
	return provider.Provider{
		Name: "Mullvad",
		DoT: provider.DoTServer{
			IPv4: []netip.AddrPort{netip.AddrPortFrom(ipv4, dotPort)},
			IPv6: []netip.AddrPort{netip.AddrPortFrom(ipv6, dotPort)},
			Name: "dns.mullvad.net",
		},
		DoH: provider.DoHServer{
			URL:  "https://dns.mullvad.net/dns-query",
			IPv4: []netip.Addr{ipv4},
			IPv6: []netip.Addr{ipv6},
		},
	}
}
