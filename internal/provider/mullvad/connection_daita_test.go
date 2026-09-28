package mullvad

import (
	"errors"
	"net/http"
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/common"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func Test_Provider_GetConnection_daita(t *testing.T) {
	t.Parallel()

	const provider = providers.Mullvad

	daitaSelection := func(direct bool) settings.ServerSelection {
		return settings.ServerSelection{
			VPN:                vpn.Wireguard,
			Cities:             []string{"Zurich"},
			MullvadDaita:       new(true),
			MullvadDaitaDirect: new(direct),
		}.WithDefaults(provider)
	}
	exitSelection := settings.ServerSelection{
		VPN:                vpn.Wireguard,
		Cities:             []string{"Zurich"},
		MullvadDaita:       new(false),
		MullvadDaitaDirect: new(false),
	}.WithDefaults(provider)
	hostnameSelection := settings.ServerSelection{
		VPN:       vpn.Wireguard,
		Hostnames: []string{"ch-zrh-wg-001"},
	}.WithDefaults(provider)
	entrySelection := func(countries []string) settings.ServerSelection {
		return settings.ServerSelection{
			VPN:          vpn.Wireguard,
			Countries:    countries,
			MullvadDaita: new(true),
		}.WithDefaults(provider)
	}

	exitServer := models.Server{
		Country:  "Switzerland",
		Hostname: "ch-zrh-wg-001",
		WgPubKey: "exit",
		IPs:      []netip.Addr{netip.MustParseAddr("2.2.2.2"), netip.MustParseAddr("::2")},
	}
	entryServer := models.Server{
		Country:  "Switzerland",
		Hostname: "ch-zrh-wg-002",
		WgPubKey: "entry",
		Daita:    true,
		IPs:      []netip.Addr{netip.MustParseAddr("1.1.1.1")},
	}
	exitConnection := models.Connection{
		Type:     vpn.Wireguard,
		IP:       netip.MustParseAddr("2.2.2.2"),
		Port:     51820,
		Protocol: constants.UDP,
		Hostname: "ch-zrh-wg-001",
		PubKey:   "exit",
	}
	errNoServer := errors.New("no server found")

	testCases := map[string]struct {
		selection  settings.ServerSelection
		setupMocks func(storage *common.MockStorage)
		connection models.Connection
		errMessage string
	}{
		"direct_daita_server": {
			selection: daitaSelection(true),
			setupMocks: func(storage *common.MockStorage) {
				storage.EXPECT().FilterServers(provider, daitaSelection(true)).
					Return([]models.Server{entryServer}, nil)
			},
			connection: models.Connection{
				Type:     vpn.Wireguard,
				IP:       netip.MustParseAddr("1.1.1.1"),
				Port:     51820,
				Protocol: constants.UDP,
				Hostname: "ch-zrh-wg-002",
				PubKey:   "entry",
				Daita:    true,
			},
		},
		"direct_only_no_daita_server": {
			selection: daitaSelection(true),
			setupMocks: func(storage *common.MockStorage) {
				storage.EXPECT().FilterServers(provider, daitaSelection(true)).
					Return(nil, errNoServer)
			},
			errMessage: "filtering servers: no server found",
		},
		"multihop_entry_in_exit_country": {
			selection: daitaSelection(false),
			setupMocks: func(storage *common.MockStorage) {
				gomock.InOrder(
					storage.EXPECT().FilterServers(provider, daitaSelection(false)).
						Return(nil, errNoServer),
					storage.EXPECT().FilterServers(provider, exitSelection).
						Return([]models.Server{exitServer}, nil),
					storage.EXPECT().FilterServers(provider, hostnameSelection).
						Return([]models.Server{exitServer}, nil),
					storage.EXPECT().FilterServers(provider, entrySelection([]string{"Switzerland"})).
						Return([]models.Server{entryServer}, nil),
				)
			},
			connection: models.Connection{
				Type:     vpn.Wireguard,
				IP:       netip.MustParseAddr("1.1.1.1"),
				Port:     51820,
				Protocol: constants.UDP,
				Hostname: "ch-zrh-wg-002",
				PubKey:   "entry",
				Daita:    true,
				Exit:     &exitConnection,
			},
		},
		"multihop_entry_in_any_country": {
			selection: daitaSelection(false),
			setupMocks: func(storage *common.MockStorage) {
				gomock.InOrder(
					storage.EXPECT().FilterServers(provider, daitaSelection(false)).
						Return(nil, errNoServer),
					storage.EXPECT().FilterServers(provider, exitSelection).
						Return([]models.Server{exitServer}, nil),
					storage.EXPECT().FilterServers(provider, hostnameSelection).
						Return([]models.Server{exitServer}, nil),
					storage.EXPECT().FilterServers(provider, entrySelection([]string{"Switzerland"})).
						Return(nil, errNoServer),
					storage.EXPECT().FilterServers(provider, entrySelection(nil)).
						Return([]models.Server{entryServer}, nil),
				)
			},
			connection: models.Connection{
				Type:     vpn.Wireguard,
				IP:       netip.MustParseAddr("1.1.1.1"),
				Port:     51820,
				Protocol: constants.UDP,
				Hostname: "ch-zrh-wg-002",
				PubKey:   "entry",
				Daita:    true,
				Exit:     &exitConnection,
			},
		},
		"multihop_no_exit_server": {
			selection: daitaSelection(false),
			setupMocks: func(storage *common.MockStorage) {
				gomock.InOrder(
					storage.EXPECT().FilterServers(provider, daitaSelection(false)).
						Return(nil, errNoServer),
					storage.EXPECT().FilterServers(provider, exitSelection).
						Return(nil, errNoServer),
				)
			},
			errMessage: "finding DAITA server: filtering servers: no server found; " +
				"finding multihop exit server: filtering servers: no server found",
		},
		"multihop_no_entry_server": {
			selection: daitaSelection(false),
			setupMocks: func(storage *common.MockStorage) {
				gomock.InOrder(
					storage.EXPECT().FilterServers(provider, daitaSelection(false)).
						Return(nil, errNoServer),
					storage.EXPECT().FilterServers(provider, exitSelection).
						Return([]models.Server{exitServer}, nil),
					storage.EXPECT().FilterServers(provider, hostnameSelection).
						Return([]models.Server{exitServer}, nil),
					storage.EXPECT().FilterServers(provider, entrySelection([]string{"Switzerland"})).
						Return(nil, errNoServer),
					storage.EXPECT().FilterServers(provider, entrySelection(nil)).
						Return(nil, errNoServer),
				)
			},
			errMessage: "finding multihop DAITA entry server: filtering servers: no server found",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			storage := common.NewMockStorage(ctrl)
			testCase.setupMocks(storage)

			client := (*http.Client)(nil)
			provider := New(storage, client)

			const ipv6Supported = false
			connection, err := provider.GetConnection(testCase.selection, ipv6Supported)

			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, testCase.connection, connection)
		})
	}
}
