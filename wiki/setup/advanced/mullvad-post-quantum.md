# Mullvad post-quantum

🍴 This feature is only available in this fork's images (`ghcr.io/mlshdev/gluetun`), not in `qmcgaw/gluetun`.

Like the official Mullvad app, gluetun can upgrade the Wireguard tunnel to a [quantum-resistant tunnel](https://mullvad.net/en/blog/stable-quantum-resistant-tunnels-in-the-app).
This protects the traffic recorded today from being decrypted in the future by a quantum computer.
It does the same as Mullvad's [mullvad-upgrade-tunnel](https://github.com/mullvad/wgephemeralpeer) program, built into gluetun.

## Requirements

- `VPN_SERVICE_PROVIDER=mullvad`
- `VPN_TYPE=wireguard`

It works with both the kernelspace and userspace Wireguard implementations, and with [DAITA](mullvad-daita.md), including DAITA multihop.

## Environment variables

| Variable | Default | Choices | Description |
| --- | --- | --- | --- |
| `MULLVAD_POST_QUANTUM_ENABLE` | `off` | `on`, `off` | Upgrade the Wireguard tunnel to a quantum-resistant tunnel |

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
      - MULLVAD_POST_QUANTUM_ENABLE=on
```

## How it works

1. Gluetun connects to the relay with your account Wireguard key.
1. It generates a Classic McEliece 460896 key pair and an ML-KEM-1024 key pair, and a new ephemeral Wireguard key.
1. Through the tunnel, it sends the public keys to the Mullvad relay config service at `10.64.0.1:1337`.
   The relay encapsulates a secret for each key pair and returns the two ciphertexts.
1. Gluetun decapsulates both ciphertexts. The Wireguard pre-shared key is the XOR of the two 32-byte shared secrets, so the tunnel stays secure as long as one of the two algorithms is not broken.
1. Gluetun switches the Wireguard interface to the ephemeral key and the pre-shared key.

The logs show `Upgrading to a quantum-resistant tunnel` then `Quantum-resistant tunnel enabled`.
With DAITA, they show `DAITA enabled with quantum-resistant tunnel`.

In DAITA multihop mode, both hops are upgraded: the entry relay pre-shared key comes with the DAITA negotiation,
and a second ephemeral key is registered with the exit relay through the exit tunnel.

## Notes

- If the upgrade fails, the tunnel is torn down and the error is logged, so no traffic flows through a tunnel which is not quantum-resistant. Gluetun then retries connecting as usual.
- `WIREGUARD_PRESHARED_KEY` is ignored, since it is replaced by the negotiated pre-shared key.
- Connecting takes a few more seconds, mostly to generate the Classic McEliece key pair and to negotiate through the tunnel. The negotiation is tried 4 times, with timeouts of 8, 16, 32 and 48 seconds.
