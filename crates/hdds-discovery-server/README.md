# hdds-discovery-server

Standalone Discovery Server for HDDS: a rendezvous service that lets DDS participants find each other without multicast.

## Usage

```bash
cargo install hdds-discovery-server
hdds-discovery-server --domain 0 --port 7400
```

`--domain 0` (the default) serves every domain; pass a domain id to serve only that one.
Run `hdds-discovery-server --help` for the full option list.

## Features

- Centralized discovery for DDS participants on networks where multicast is not available
- By default the server is a rendezvous service: after the initial locator exchange, peers must be able to reach each other's advertised UDP locators directly. Do not rely on it for NAT traversal
- Optional relay mode (`--relay`) that forwards datagrams through the server; its tested perimeter is not documented yet
- Configured with command-line options and an optional JSON configuration file (`--config`)

## License

Apache-2.0 OR MIT - See [LICENSE-APACHE](../../LICENSE-APACHE) and [LICENSE-MIT](../../LICENSE-MIT) for details.
