# Mullvad DAITA

🍴 This feature is only available in this fork's images (`ghcr.io/mlshdev/gluetun`), not in `qmcgaw/gluetun`.

[DAITA](https://mullvad.net/en/blog/daita-defense-against-ai-guided-traffic-analysis) (Defense Against AI-guided Traffic Analysis) is a Mullvad feature which pads packets to a constant size and injects cover traffic, to hide the traffic patterns of your tunnel from anyone watching it.
Gluetun implements it the same way the official Mullvad app does on Linux, using the [Mullvad wireguard-go fork](https://github.com/mullvad/wireguard-go) and its [maybenot](https://github.com/maybenot-io/maybenot) framework.

## Requirements

- `VPN_SERVICE_PROVIDER=mullvad`
- `VPN_TYPE=wireguard`
- A `linux/amd64` or `linux/arm64` image. No other platform is built.

## Environment variables

| Variable | Default | Choices | Description |
| --- | --- | --- | --- |
| `MULLVAD_DAITA_ENABLE` | `off` | `on`, `off` | Enable DAITA. Only Mullvad relays supporting DAITA are used for the relay you connect to. |
| `MULLVAD_DAITA_DIRECT` | `off` | `on`, `off` | Only used with `MULLVAD_DAITA_ENABLE=on`. See [Direct and multihop](#direct-and-multihop). |

All the usual [Mullvad](../providers/mullvad.md) server filters (`SERVER_COUNTRIES`, `SERVER_CITIES`, `SERVER_HOSTNAMES`, `ISP`, `OWNED_ONLY`) still apply.

## Example

```yml
services:
  gluetun:
    image: ghcr.io/mlshdev/gluetun:latest
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    environment:
      - VPN_SERVICE_PROVIDER=mullvad
      - VPN_TYPE=wireguard
      - WIREGUARD_PRIVATE_KEY=wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=
      - WIREGUARD_ADDRESSES=10.64.222.21/32
      - SERVER_CITIES=Amsterdam
      - MULLVAD_DAITA_ENABLE=on
```

## Direct and multihop

Not every Mullvad relay supports DAITA, so your server filters may match no DAITA relay.

- `MULLVAD_DAITA_DIRECT=on` only connects directly to a DAITA relay matching your filters, and fails with an error if there is none.
- `MULLVAD_DAITA_DIRECT=off` (default) connects directly to a DAITA relay matching your filters if there is one.
  Otherwise it falls back to **multihop**, like the official app does:
  - the entry relay is a DAITA relay, picked in the same country as the exit relay if possible, otherwise in any country. Only `OWNED_ONLY` and `WIREGUARD_ENDPOINT_PORT` apply to it, your other filters are ignored;
  - the exit relay is a relay matching your filters, which does not need to support DAITA;
  - the tunnel to the exit relay goes through the tunnel to the entry relay. DAITA runs between you and the entry relay, and your public IP address is the exit relay's one.

## How it works

1. Gluetun connects to the relay with your account Wireguard key.
1. Through that tunnel, it registers a new ephemeral Wireguard key with the Mullvad relay config service at `10.64.0.1:1337`, asking for DAITA.
   The service answers with the DAITA state machines to run.
1. Gluetun switches the Wireguard device to the ephemeral key and enables DAITA with these machines.

In multihop mode, the negotiation happens with the entry relay, and gluetun then runs two Wireguard devices in-process: one to the entry relay with DAITA, and one to the exit relay tunneled inside it.

When the connection is established, the logs show `DAITA enabled`, or `DAITA enabled on entry relay ...` in multihop mode.

## Notes

- DAITA requires the Mullvad userspace Wireguard implementation. `WIREGUARD_IMPLEMENTATION` is ignored, and a warning is logged if it is set to `kernelspace`.
- Connecting takes a few more seconds, since the ephemeral peer is negotiated through the tunnel. The negotiation is tried 4 times, with timeouts of 8, 16, 32 and 48 seconds.
- DAITA adds bandwidth overhead, since it sends padding and cover traffic.
- `wg show` does not work, since the userspace devices are configured in-process and do not expose a UAPI socket.
- DAITA can be combined with [post-quantum tunnels](mullvad-post-quantum.md).

## DAITA relays list

The Mullvad servers data embedded in gluetun does not say which relays support DAITA.
This fork ships a separate list of DAITA Wireguard hostnames in `internal/storage/mullvad_daita.json`, overlaid on the embedded servers data.
A GitHub workflow refreshes it from the [Mullvad relays API](https://api.mullvad.net/www/relays/all/) on Mondays and Thursdays and opens a pull request when it changes.

The [servers updater](../servers.md#update-the-vpn-servers-list) also reads the `daita` field of the Mullvad API, so servers updated at runtime carry it.
