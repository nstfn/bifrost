# Bifrost (nstfn)

Personal build of [Bifrost](https://github.com/nstfn/bifrost), a Philips Hue
bridge emulator backed by Zigbee2MQTT. Based on `duvholt/bifrost`.

Differences with the upstream "Bifrost" add-on of this repository:

- aarch64 only, image `ghcr.io/nstfn/bifrost`.
- No host network. Ports 80/tcp, 443/tcp and 2100/udp are published on the
  host. Bifrost reaches Zigbee2MQTT on the hassio network by its hostname.
- No `NET_ADMIN`.
- mDNS and SSDP discovery do not reach the LAN. Give clients the IP address.

## Configuration

Copy `bifrost.example.yaml` (this folder) to `/config/bifrost/config.yaml` (the `bifrost`
folder next to `configuration.yaml`) and adapt it. `bridge.bind_ipaddress:
0.0.0.0` is required in this add-on.
