package storage

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/qdm12/gluetun/internal/models"
)

// mullvadDaitaHostnames is the sorted list of Mullvad Wireguard hostnames
// supporting DAITA, since the embedded servers data from the gluetun-servers
// module does not contain this information.
//
//go:embed mullvad_daita.json
var mullvadDaitaHostnames []byte

// addMullvadDaita sets the Daita field of the Mullvad servers given, and
// increments the servers version so persisted servers without DAITA
// information are discarded.
func addMullvadDaita(servers *models.Servers) {
	var daitaHostnames []string
	err := json.Unmarshal(mullvadDaitaHostnames, &daitaHostnames)
	if err != nil {
		panic(fmt.Sprintf("JSON decoding embedded Mullvad DAITA hostnames: %s", err))
	}

	for i, server := range servers.Servers {
		_, found := slices.BinarySearch(daitaHostnames, server.Hostname)
		if found {
			servers.Servers[i].Daita = true
		}
	}
	servers.Version++
}
