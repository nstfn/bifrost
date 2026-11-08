# Bifrost (nstfn)

A Hue bridge emulator backed by Zigbee2MQTT, for one home. Its main job: let
[lg-hue-sync (nstfn)](https://github.com/nstfn/lg-hue-sync) on an LG TV drive a Philips Hue Play
gradient lightstrip (LCX002, 7 segments) in Hue Entertainment mode, without a Hue Bridge. It also
exposes the home's Zigbee lights to Hue apps.

This is a fork of [duvholt/bifrost](https://github.com/duvholt/bifrost). It is tuned for this
setup, and it no longer follows upstream. Thanks to Bifrost's authors and contributors for the
emulator this work starts from.

## The setup it targets

- Home Assistant OS on a Raspberry Pi 5, with the app "Bifrost (nstfn)" from this repository
  ([bifrost-nstfn/](bifrost-nstfn/), no host network).
- Zigbee2MQTT 2.14.3; Zigbee coordinator on the network (CC2652P over TCP).
- One entertainment area, one paired app (lg-hue-sync), `auth.mode: strict`,
  `streaming_fps: 15`.

## How this fork diverges

Upstream base: `d29b1d1` (2026-11-04). This fork adds 22 commits. Six of them are PR #39 by
twenty5schmeckels (LCX002 segment layout), which upstream has merged since.

- **Entertainment frames cannot pile up in Zigbee2MQTT.** zigbee-herdsman sends to one device
  one request at a time (~52 ms per frame to this strip). Fire-and-forget frames used to queue
  there, and the strip showed the picture seconds late. Now Bifrost keeps only the latest frame
  and sends it after Zigbee2MQTT reports the previous one done (`70c22d2`, `189d9be`):
  - the frame's `zclcommand` sets `"logging": true`, so Zigbee2MQTT logs
    `Invoked ZCL command ...` when the frame completes, or `Publish 'set' 'zclcommand' ... failed`;
  - Bifrost reads these lines on `bridge/logging` over the websocket it already holds, with the
    namespace in its own field (newer Zigbee2MQTT) or at the start of the message (2.14);
  - without an ack, a second frame may go after 300 ms, never more than 2 within 2 s;
  - Bifrost logs `first completion ack` at stream start, and warns after 5 s without one.

  Cost: one Zigbee2MQTT info log line per frame, about 20 MB of Zigbee2MQTT log per hour of
  streaming (measured).
- **No retry of a failed frame.** Entertainment frames use `disableRecovery`: a failed frame is
  dropped, not retried for seconds behind the next ones (`1af135e`).
- **Strict auth (opt-in).** Per-app keys and a virtual link button; the streamer's key no longer
  leaks and is cleared on delete; `GET /api/<unknown user>/config` returns the short public
  config, as a real bridge does; expected rejections no longer log at error level (`3ff499f`,
  `e216c6b`, `18fda94`, `f82c4e8`, `2a13187`, `de8eb4a`).
- **Entertainment API.** Accepts the `type` field when an entertainment configuration is created,
  as the Hue app sends it (`a62da0f`); ends the stream session as soon as its area stops
  (`eae6682`); schedules the throttle by deadline, so frames pass at the configured rate
  (`a194626`).
- **Images.** CI publishes `ghcr.io/nstfn/bifrost:nstfn-main-YYYY-MM-DD` and
  `nstfn-main-latest` from `nstfn/main`, and runs the Rust checks there (`beaad53`, `d227b3c`,
  `395e84f`). Docs for `bridge.bind_ipaddress` (`97e85a4`).

## Install

This repository is also the Home Assistant app repository (`repository.yaml`, app in
`bifrost-nstfn/`). Add `https://github.com/nstfn/bifrost#nstfn/main` to the app store
and install "Bifrost (nstfn)". To ship a new build:

1. Push to `nstfn/main`. CI publishes the image with today's date tag.
2. Set that tag in `bifrost-nstfn/build.yaml` and the same version in
   `bifrost-nstfn/config.yaml`.
3. Reload the app store and update the app with a backup.

The Supervisor accepts `build_from` only as `image:tag`. With `image@sha256:...` it falls back to
its default base image and starts a container without Bifrost. It builds with `--pull`, so a
moved tag is fetched again.

Configuration reference: [doc/config-reference.md](doc/config-reference.md).

## Known gaps

- `cargo clippy --all-targets -- -D warnings` fails with Rust 1.99 in `crates/svc` and
  `crates/hue` (code from upstream). CI runs clippy without `-D warnings`.
- `tests/zone.rs` `empty_zone_can_acquire_first_child` fails on macOS; it passes in CI on Linux.
- The frame flow state machine (`src/backend/z2m/flow.rs`) has one test, for the log formats.

## License

[GPL-3.0](LICENSE), as upstream.
