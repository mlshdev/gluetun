# mullvad-wireguard-go

Trimmed copy of [Mullvad's wireguard-go fork](https://github.com/mullvad/wireguard-go),
branch `mullvad`, commit `86ccb9b49b8f095775109b62554efedbc1d0e3c6` (release 0.1.6),
used by gluetun for Mullvad DAITA.

Changes from the original:

- module path renamed to `github.com/qdm12/gluetun/third_party/mullvad-wireguard-go`
  so it can live next to the upstream `golang.zx2c4.com/wireguard` module;
- only the Linux files needed by gluetun are kept (no tests, Windows, BSD, netstack, examples or main package);
- `tun/multihoptun` does not depend on gvisor anymore, IP and UDP headers are written by `headers.go`;
- `MultihopTun.Close` is safe to call more than once.

`device/daita.go` is built with the `daita` build tag and links against `libmaybenot.a`,
which must be built from `maybenot-ffi` and placed at the root of this module:

```sh
cargo rustc --manifest-path maybenot-ffi/Cargo.toml --release --locked --crate-type=staticlib
cp maybenot-ffi/target/release/libmaybenot_ffi.a libmaybenot.a
```
