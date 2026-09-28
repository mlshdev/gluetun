package mullvad

import (
	"fmt"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/utils"
)

const defaultWireguardPort uint16 = 51820

func (p *Provider) GetConnection(selection settings.ServerSelection, ipv6Supported bool) (
	connection models.Connection, err error,
) {
	defaults := utils.NewConnectionDefaults(0, 0, defaultWireguardPort)
	if selection.MullvadDaita == nil || !*selection.MullvadDaita {
		return utils.GetConnection(p.Name(),
			p.storage, selection, defaults, ipv6Supported, p.connPicker)
	}

	connection, err = utils.GetConnection(p.Name(),
		p.storage, selection, defaults, ipv6Supported, p.connPicker)
	if err == nil {
		connection.Daita = true
		return connection, nil
	} else if *selection.MullvadDaitaDirect {
		return models.Connection{}, err
	}

	return p.getMultihopDaitaConnection(selection, defaults, ipv6Supported, err)
}

// getMultihopDaitaConnection returns a connection to a DAITA entry server
// with an exit server matching the selection given, which does not support DAITA.
// The exit server is always reached over IPv4, and the entry server is picked
// in the same country as the exit server if possible.
func (p *Provider) getMultihopDaitaConnection(selection settings.ServerSelection,
	defaults utils.ConnectionDefaults, ipv6Supported bool, directErr error,
) (connection models.Connection, err error) {
	exitSelection := selection
	exitSelection.MullvadDaita = new(false)
	const exitIPv6Supported = false
	exit, err := utils.GetConnection(p.Name(), p.storage, exitSelection,
		defaults, exitIPv6Supported, p.connPicker)
	if err != nil {
		return models.Connection{}, fmt.Errorf("finding DAITA server: %w; "+
			"finding multihop exit server: %w", directErr, err)
	}
	// Exit servers are reached from the entry server on the default port.
	exit.Port = defaultWireguardPort

	exitCountry, err := p.getServerCountry(exit.Hostname)
	if err != nil {
		return models.Connection{}, fmt.Errorf("getting exit server country: %w", err)
	}

	entrySelection := settings.ServerSelection{
		VPN:          vpn.Wireguard,
		Mode:         selection.Mode,
		Countries:    []string{exitCountry},
		OwnedOnly:    selection.OwnedOnly,
		MullvadDaita: new(true),
		Wireguard: settings.WireguardSelection{
			EndpointPort: selection.Wireguard.EndpointPort,
		},
	}.WithDefaults(providers.Mullvad)
	connection, err = utils.GetConnection(p.Name(), p.storage, entrySelection,
		defaults, ipv6Supported, p.entryConnPicker)
	if err != nil {
		entrySelection.Countries = nil
		connection, err = utils.GetConnection(p.Name(), p.storage, entrySelection,
			defaults, ipv6Supported, p.entryConnPicker)
		if err != nil {
			return models.Connection{}, fmt.Errorf("finding multihop DAITA entry server: %w", err)
		}
	}

	connection.Daita = true
	connection.Exit = &exit
	return connection, nil
}

func (p *Provider) getServerCountry(hostname string) (country string, err error) {
	selection := settings.ServerSelection{
		VPN:       vpn.Wireguard,
		Hostnames: []string{hostname},
	}.WithDefaults(providers.Mullvad)
	servers, err := p.storage.FilterServers(p.Name(), selection)
	if err != nil {
		return "", fmt.Errorf("filtering servers: %w", err)
	}
	return servers[0].Country, nil
}
