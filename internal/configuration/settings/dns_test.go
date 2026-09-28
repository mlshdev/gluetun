package settings

import (
	"testing"

	"github.com/qdm12/dns/v2/pkg/provider"
	"github.com/qdm12/gluetun/internal/dnsproviders"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_defaultDNSProviders(t *testing.T) {
	t.Parallel()

	names := defaultDNSProviders()

	found := false
	providers := dnsproviders.New()
	for _, name := range names {
		provider, err := providers.Get(name)
		require.NoError(t, err)
		if len(provider.Plain.IPv4) > 0 {
			found = true
			break
		}
	}
	require.True(t, found, "no default DNS provider has a plaintext IPv4 address")
}

func Test_DNS_validate_providers(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		providers  []string
		errWrapped error
		errMessage string
	}{
		"mullvad": {
			providers: []string{"mullvad"},
		},
		"mullvad_and_library_provider": {
			providers: []string{"Mullvad", "quad9"},
		},
		"unknown_provider": {
			providers:  []string{"mullvad", "unknown"},
			errWrapped: provider.ErrParseProviderNameUnknown,
			errMessage: "DNS upstream resolver: provider does not match any known providers: unknown",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			settings := DNS{Providers: testCase.providers}
			settings.setDefaults()

			err := settings.validate()

			assert.ErrorIs(t, err, testCase.errWrapped)
			if testCase.errWrapped != nil {
				assert.EqualError(t, err, testCase.errMessage)
			}
		})
	}
}
