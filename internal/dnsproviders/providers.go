// Package dnsproviders extends the DNS providers of github.com/qdm12/dns/v2/pkg/provider
// with providers specific to gluetun.
package dnsproviders

import (
	"fmt"
	"strings"

	"github.com/qdm12/dns/v2/pkg/provider"
)

type Providers struct {
	providers []provider.Provider
}

func New() *Providers {
	return &Providers{
		providers: append(provider.NewProviders().List(), mullvad()),
	}
}

// Get returns the provider matching the name given, case insensitively.
// It returns an error wrapping [provider.ErrParseProviderNameUnknown]
// if no provider matches the name.
func (p *Providers) Get(name string) (provider.Provider, error) {
	for _, dnsProvider := range p.providers {
		if strings.EqualFold(name, dnsProvider.Name) {
			return dnsProvider, nil
		}
	}
	return provider.Provider{}, fmt.Errorf("%w: %s", provider.ErrParseProviderNameUnknown, name)
}
