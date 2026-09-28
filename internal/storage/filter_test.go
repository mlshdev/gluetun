package storage

import (
	"testing"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
)

func Test_filterServer_mullvadDaita(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		server   models.Server
		daita    bool
		filtered bool
	}{
		"daita_off_non_daita_server": {
			server: models.Server{VPN: vpn.Wireguard},
		},
		"daita_on_daita_server": {
			server: models.Server{VPN: vpn.Wireguard, Daita: true},
			daita:  true,
		},
		"daita_on_non_daita_server": {
			server:   models.Server{VPN: vpn.Wireguard},
			daita:    true,
			filtered: true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			selection := settings.ServerSelection{
				VPN:          vpn.Wireguard,
				MullvadDaita: new(testCase.daita),
			}.WithDefaults(providers.Mullvad)

			filtered := filterServer(testCase.server, selection)

			assert.Equal(t, testCase.filtered, filtered)
		})
	}
}

func Test_noServerFoundError_mullvadDaita(t *testing.T) {
	t.Parallel()

	selection := settings.ServerSelection{
		VPN:          vpn.Wireguard,
		MullvadDaita: new(true),
	}.WithDefaults(providers.Mullvad)

	err := noServerFoundError(selection)

	assert.ErrorContains(t, err, "DAITA servers only")
}
