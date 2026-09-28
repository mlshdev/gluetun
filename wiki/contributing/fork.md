# Fork internals

🍴 This page documents how this fork implements its features. See [TECHNICAL.md](../../TECHNICAL.md) at the repository root for the detailed notes.

## Features and code

| Feature | Environment variables | Code |
| --- | --- | --- |
| [Mullvad DAITA](../setup/advanced/mullvad-daita.md) | `MULLVAD_DAITA_ENABLE`, `MULLVAD_DAITA_DIRECT` | `internal/daita`, `internal/provider/mullvad/connection.go`, `internal/storage/mullvaddaita.go`, `third_party/mullvad-wireguard-go` |
| [Mullvad post-quantum](../setup/advanced/mullvad-post-quantum.md) | `MULLVAD_POST_QUANTUM_ENABLE` | `internal/ephemeralpeer` |
| [Mullvad DNS](../setup/options/dns.md#mullvad-dns) | `DNS_UPSTREAM_RESOLVERS=mullvad` | `internal/dnsproviders` |

The settings are read and validated in `internal/configuration/settings/serverselection.go` and `internal/configuration/settings/dns.go`.
`internal/vpn/wireguard.go` picks the Wireguard runner: the DAITA runner if the connection requires DAITA, otherwise the usual `internal/wireguard` runner, wrapped by the post-quantum runner if `MULLVAD_POST_QUANTUM_ENABLE=on`.

## Ephemeral peer negotiation

DAITA and post-quantum both register an ephemeral Wireguard key with the Mullvad relay config service, through the tunnel, like the official app does.
`internal/ephemeralpeer` implements it without generated code:

- the gRPC method `ephemeralpeer.EphemeralPeer/RegisterPeerV1` at `http://10.64.0.1:1337`, over HTTP/2 without TLS (`negotiate.go`);
- the protobuf messages of [ephemeralpeer.proto](https://github.com/mullvad/mullvadvpn-app/blob/main/talpid-tunnel-config-client/proto/ephemeralpeer.proto), encoded by hand with `protowire` (`proto.go`);
- the Classic McEliece 460896 and ML-KEM-1024 key pairs, and the pre-shared key derivation (`kem.go`).
  ML-KEM comes from the Go standard library `crypto/mlkem`, and Classic McEliece from the [Mullvad circl fork](https://github.com/mullvad/circl), wired with a `replace` of `github.com/cloudflare/circl` in `go.mod`.

## DAITA build

DAITA needs the [Mullvad wireguard-go fork](https://github.com/mullvad/wireguard-go) and the Rust [maybenot](https://github.com/maybenot-io/maybenot) library:

- `third_party/mullvad-wireguard-go` is a trimmed Linux-only copy of the fork, as a nested Go module wired with a `replace` in `go.mod`. Its `README.md` lists the changes from the original.
- `third_party/mullvad-wireguard-go/maybenot-ffi` is built with cargo into the static `libmaybenot.a`, linked with cgo.
- The DAITA runner is in `internal/daita/run_daita.go`, behind the `daita` build tag. Without the tag, `run_nodaita.go` returns an error, so `go build ./...` and `go test ./...` need neither cgo nor Rust.

The Docker image builds the binary with `CGO_ENABLED=1 go build -tags daita`, statically linked against musl.
Since the `build` stage runs on the target platform, images are built on native runners only, for `linux/amd64` and `linux/arm64`.

```sh
go build ./...
go test ./...
docker build --platform linux/arm64 --target lint .
docker build --platform linux/arm64 --target lint-daita .
docker build --platform linux/arm64 -t gluetun-daita .
```

## CI workflows

- `.github/workflows/ci.yml`: upstream verification, plus the `lint-daita` stage.
- `.github/workflows/docker-rebuild.yml`: native `linux/amd64` and `linux/arm64` builds, merged into `ghcr.io/mlshdev/gluetun` tagged `latest` and `sha-<commit>`. Pull requests build without pushing, and a clean rebuild runs on Mondays and Thursdays.
- `.github/workflows/mullvad-daita.yml`: refreshes `internal/storage/mullvad_daita.json` from the Mullvad relays API on Mondays and Thursdays, and opens a pull request when it changes.

## Wiki

The `wiki` directory is a copy of [qdm12/gluetun-wiki](https://github.com/qdm12/gluetun-wiki), without its `.github`, `.vscode` and link checker files.
Table spacing and link text fixes were applied to four upstream pages so it passes the repository `markdownlint-cli2` configuration.
To update it from upstream, download the upstream `main` tarball with `gh api repos/qdm12/gluetun-wiki/tarball/main`, extract it, merge it into `wiki` keeping the 🍴 fork sections, update the commit referenced in [the wiki README](../README.md#this-fork), and run `markdownlint-cli2 "**/*.md"`.
