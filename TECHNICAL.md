# Technical notes

This fork of [gluetun](https://github.com/passteque/gluetun) adds Mullvad DAITA, DAITA multihop, Mullvad post-quantum tunnels and the Mullvad DNS provider.
Upstream conventions in [AGENTS.md](AGENTS.md) apply to all code.

## Mullvad DAITA

### Components

| Path | Role |
| --- | --- |
| `third_party/mullvad-wireguard-go` | Trimmed Linux-only copy of the [Mullvad wireguard-go fork](https://github.com/mullvad/wireguard-go) (branch `mullvad`, commit `86ccb9b`, release 0.1.6), nested Go module wired with a `replace` in `go.mod`. `tun/multihoptun` builds IPv4/IPv6/UDP headers by hand instead of depending on gvisor. |
| `third_party/mullvad-wireguard-go/maybenot-ffi` | Rust wrapper crate with a committed `Cargo.lock`, built into the `libmaybenot.a` static library linked with cgo. `maybenot.h` must match the `maybenot-ffi` version in `Cargo.toml`. |
| `internal/ephemeralpeer` | Mullvad ephemeral peer registration shared by DAITA and post-quantum: gRPC over h2c (`negotiate.go`), hand-written protobuf (`proto.go`), KEM key pairs and pre-shared key derivation (`kem.go`), `Client.Register` (`client.go`), and the `PostQuantum` runner wrapper (`postquantum.go`). |
| `internal/daita` | DAITA runner: UAPI configuration (`uapi.go`), settings (`settings.go`), and the device lifecycle in `run_daita.go` (`daita` build tag) or a stub returning an error in `run_nodaita.go`. |
| `internal/storage/mullvad_daita.json` | Sorted Mullvad Wireguard hostnames supporting DAITA, overlaid on the embedded servers data which lacks this field. Refreshed on Mondays and Thursdays by `.github/workflows/mullvad-daita.yml`. |
| `internal/provider/mullvad/connection.go` | Relay selection: direct DAITA relay, or a DAITA entry relay (same country first) plus a non-DAITA exit relay when `MULLVAD_DAITA_DIRECT=off`. |
| `internal/vpn/wireguard.go` | Uses the DAITA runner instead of `internal/wireguard` when the connection requires DAITA, and wraps `internal/wireguard` with the post-quantum runner when only `MULLVAD_POST_QUANTUM_ENABLE=on`. |

### Runtime flow

1. Create the TUN device and the link, add addresses, and bring up a userspace device with the account (parent) key.
   In multihop mode the device reaches the entry relay through a TUN wrapper which does not close the real TUN device.
2. Set up routes and rules, then negotiate an ephemeral peer over the tunnel with the gRPC
   `ephemeralpeer.EphemeralPeer/RegisterPeerV1` method at `http://10.64.0.1:1337`,
   using HTTP/2 without TLS and a hand-written protobuf encoding. There are 4 attempts with timeouts of 8, 16, 32 and 48 seconds.
3. Singlehop: switch the device to the ephemeral private key and enable DAITA on the peer with the negotiated maybenot machines.
4. Multihop: close the negotiation device, then run an entry device (ephemeral key, DAITA enabled, UDP bind with firewall mark)
   on a `multihoptun` pair, and an exit device (parent key) on the real TUN device using the `multihoptun` binder.
   With post-quantum enabled, a second ephemeral peer is registered with the exit relay through the exit tunnel,
   and the exit device switches to its key and pre-shared key.
5. The runner reports an error when a device closes, and cleans up in reverse order of setup.

The DAITA userspace devices do not serve a UAPI socket, since gluetun configures them in-process.

## Mullvad post-quantum

`MULLVAD_POST_QUANTUM_ENABLE=on` does what the official app and
[mullvad-upgrade-tunnel](https://github.com/mullvad/wgephemeralpeer) do:

1. Once the tunnel is up with the account key, generate a Classic McEliece 460896 key pair and an ML-KEM-1024 key pair,
   and send their public keys, in that order, with a new ephemeral public key in the same `RegisterPeerV1` request as DAITA.
   The algorithm names sent are `Classic-McEliece-460896f-round3` and `ML-KEM-1024`.
2. Decapsulate the two ciphertexts returned; the Wireguard pre-shared key is the XOR of both 32-byte shared secrets.
3. Switch the device to the ephemeral private key and the pre-shared key. Any `WIREGUARD_PRESHARED_KEY` is replaced.

Without DAITA, `ephemeralpeer.PostQuantum` wraps the `internal/wireguard` runner: it waits for the tunnel to be ready,
registers the peer, then reconfigures the interface with `wgctrl`, so it works with both kernelspace and userspace.
If the upgrade fails, the tunnel is torn down and the error is reported, so traffic never flows over a non-upgraded tunnel.
With DAITA, the DAITA runner requests both in a single registration, and reconfigures its in-process devices.

ML-KEM-1024 comes from the Go standard library `crypto/mlkem`. Classic McEliece round 3 comes from the
[Mullvad circl fork](https://github.com/mullvad/circl), wired with a `replace` of `github.com/cloudflare/circl` in `go.mod`
and allowed in `.golangci.yml` `gomoddirectives`. The fork is ahead of circl v1.6.1 and not behind it, so
`github.com/ProtonMail/go-crypto`, which also depends on circl, keeps working. The "f" McEliece variant only differs in
key generation, so keys generated by the non "f" circl implementation are compatible.

## Build

Default Go builds (`go build ./...`, unit tests, cross compilation) do not use the `daita` tag and need no cgo.
The Docker image builds the final binary with `CGO_ENABLED=1 go build -tags daita`, statically linked against musl:

- The `maybenot` stage builds `libmaybenot.a` with cargo for the target platform.
- The `build` stage runs on the target platform, so images must be built on native runners (no QEMU), for `linux/amd64` and `linux/arm64` only.
- The `lint-daita` stage lints the `daita` tagged code.

Build and inspect locally with OrbStack:

```sh
docker build --platform linux/arm64 --target lint-daita .
docker build --platform linux/arm64 -t gluetun-daita .
```

### CI

- `.github/workflows/ci.yml`: upstream verification, plus the `lint-daita` stage.
- `.github/workflows/docker-rebuild.yml`: native `ubuntu-26.04` and `ubuntu-26.04-arm` builds, pushed by digest and merged into
  `ghcr.io/<owner>/gluetun` tagged `latest` and `sha-<commit>`. Pull requests build without pushing. It also does a clean
  rebuild on Mondays and Thursdays.
- `.github/workflows/mullvad-daita.yml`: opens a pull request when the DAITA hostnames list changes.

### Validation

```sh
go build ./...
go test ./...
docker build --platform linux/arm64 --target lint .
docker build --platform linux/arm64 --target lint-daita .
docker build --platform linux/arm64 --target test -t gluetun-test .
docker run --rm --cap-add=NET_ADMIN --device /dev/net/tun gluetun-test
```

Under OrbStack, `internal/pmtud/tcp` tests fail with `setting mark option on raw socket: protocol not available`
since its kernel rejects `SO_MARK` on raw sockets; this is unrelated to DAITA.

## Wiki

`wiki/` is a copy of [qdm12/gluetun-wiki](https://github.com/qdm12/gluetun-wiki) at commit `888ab89` (2026-08-07), MIT licensed,
without its `.github`, `.vscode` and link checker files. It keeps its own `.markdownlint.json` (`MD013` off).
Fork pages and sections are marked with 🍴:

- `wiki/setup/advanced/mullvad-daita.md` and `wiki/setup/advanced/mullvad-post-quantum.md`: user guides.
- `wiki/setup/providers/mullvad.md`, `wiki/setup/options/dns.md`, `wiki/setup/options/wireguard.md`: fork variables and notes.
- `wiki/contributing/fork.md`: fork internals and how to resync the wiki from upstream.

Upstream pages got table spacing (MD060) and link text (MD059) fixes in `faq/bandwidth.md`, `setup/options/openvpn.md`,
`setup/options/shadowsocks.md` and `errors/routing.md`, to pass `markdownlint-cli2`. `wiki` is in `.dockerignore`.
Update the wiki pages in the same change as any fork feature change.

## Mullvad DNS

`internal/dnsproviders` extends the providers of `github.com/qdm12/dns/v2` with Mullvad (`dns.mullvad.net`, `194.242.2.2`,
`2a07:e340::2`, DoT port 853, DoH port 443). Provider names are matched case insensitively and validated in the DNS settings.
