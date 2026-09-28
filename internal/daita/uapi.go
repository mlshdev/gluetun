package daita

import (
	"encoding/hex"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type deviceConfig struct {
	privateKey wgtypes.Key
	// firewallMark is not set if zero.
	firewallMark uint32
	peer         peerConfig
}

type peerConfig struct {
	publicKey wgtypes.Key
	// presharedKey is not used if all zeros.
	presharedKey        wgtypes.Key
	endpoint            netip.AddrPort
	persistentKeepalive time.Duration
	allowedIPs          []netip.Prefix
}

// uapiString returns the wireguard UAPI set operation text for the device
// configuration, replacing any existing peer, as documented at
// https://www.wireguard.com/xplatform/#configuration-protocol
func (c deviceConfig) uapiString() string {
	lines := make([]string, 0, 9+len(c.peer.allowedIPs)) //nolint:mnd
	lines = append(lines, "private_key="+hex.EncodeToString(c.privateKey[:]))
	if c.firewallMark != 0 {
		lines = append(lines, "fwmark="+strconv.FormatUint(uint64(c.firewallMark), 10))
	}
	lines = append(lines,
		"replace_peers=true",
		"public_key="+hex.EncodeToString(c.peer.publicKey[:]),
		"preshared_key="+hex.EncodeToString(c.peer.presharedKey[:]),
		"endpoint="+c.peer.endpoint.String(),
		"persistent_keepalive_interval="+strconv.Itoa(int(c.peer.persistentKeepalive.Seconds())),
		"replace_allowed_ips=true",
	)
	for _, allowedIP := range c.peer.allowedIPs {
		lines = append(lines, "allowed_ip="+allowedIP.String())
	}
	return strings.Join(lines, "\n") + "\n"
}
