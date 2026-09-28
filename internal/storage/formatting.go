package storage

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/vpn"
)

func commaJoin(slice []string) string {
	return strings.Join(slice, ", ")
}

func appendValues(messageParts []string, singular, plural string, values []string) []string {
	switch len(values) {
	case 0:
		return messageParts
	case 1:
		return append(messageParts, singular+" "+values[0])
	default:
		return append(messageParts, plural+" "+commaJoin(values))
	}
}

func noServerFoundError(selection settings.ServerSelection) (err error) {
	var messageParts []string

	messageParts = append(messageParts, "VPN "+selection.VPN)

	protocol := constants.UDP
	if selection.OpenVPN.Protocol == constants.TCP {
		protocol = constants.TCP
	}
	messageParts = append(messageParts, "protocol "+protocol)

	messageParts = appendValues(messageParts, "country", "countries", selection.Countries)
	messageParts = appendValues(messageParts, "category", "categories", selection.Categories)
	messageParts = appendValues(messageParts, "region", "regions", selection.Regions)
	messageParts = appendValues(messageParts, "city", "cities", selection.Cities)

	if *selection.OwnedOnly {
		messageParts = append(messageParts, "owned servers only")
	}

	if *selection.MullvadDaita {
		messageParts = append(messageParts, "DAITA servers only")
	}

	messageParts = appendValues(messageParts, "ISP", "ISPs", selection.ISPs)
	messageParts = appendValues(messageParts, "hostname", "hostnames", selection.Hostnames)
	messageParts = appendValues(messageParts, "name", "names", selection.Names)

	switch len(selection.Numbers) {
	case 0:
	case 1:
		part := "server number " + strconv.Itoa(int(selection.Numbers[0]))
		messageParts = append(messageParts, part)
	default:
		serverNumbers := make([]string, len(selection.Numbers))
		for i := range selection.Numbers {
			serverNumbers[i] = strconv.Itoa(int(selection.Numbers[i]))
		}
		part := "server numbers " + commaJoin(serverNumbers)
		messageParts = append(messageParts, part)
	}

	if *selection.OpenVPN.PIAEncPreset != "" {
		part := "encryption preset " + *selection.OpenVPN.PIAEncPreset
		messageParts = append(messageParts, part)
	}

	if *selection.FreeOnly {
		messageParts = append(messageParts, "free tier only")
	}

	if *selection.PremiumOnly {
		messageParts = append(messageParts, "premium tier only")
	}

	if *selection.StreamOnly {
		messageParts = append(messageParts, "stream only")
	}

	if *selection.MultiHopOnly {
		messageParts = append(messageParts, "multihop only")
	}

	if *selection.PortForwardOnly {
		messageParts = append(messageParts, "port forwarding only")
	}

	if *selection.SecureCoreOnly {
		messageParts = append(messageParts, "secure core only")
	}

	if *selection.TorOnly {
		messageParts = append(messageParts, "tor only")
	}

	targetIP := selection.OpenVPN.EndpointIP
	if selection.VPN == vpn.Wireguard {
		targetIP = selection.Wireguard.EndpointIP
	}
	if targetIP.IsValid() {
		messageParts = append(messageParts,
			"target ip address "+targetIP.String())
	}

	message := "for " + strings.Join(messageParts, "; ")

	return fmt.Errorf("no server found: %s", message)
}
