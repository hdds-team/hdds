# 12_typescript - DDS from TypeScript

There are two supported ways to reach DDS from TypeScript, and both are built.

## 1. Native binding (Node) - `@hdds/client`

```
Node.js process
  (TypeScript)  --koffi FFI-->  libhdds_c.so  --UDP/RTPS-->  DDS peers
```

`sdk/typescript` is a native FFI binding over `libhdds_c.so` through koffi. No
bridge process, no WebSocket, no serialization detour: `writer.write()` and
`reader.take()` are one FFI call each. This is the path `hello_world.ts`,
`publisher.ts`, `subscriber.ts` and `qos_example.ts` take.

## 2. WebSocket bridge (browser, or Node without the shared library) - `hdds-ws`

```
Browser / Node.js        hdds-ws bridge            DDS Domain
  (TypeScript)   --WS-->  (Rust native)   --UDP/RTPS-->  DDS peers
  ws_bridge.ts           127.0.0.1:9090
```

`tools/hdds-ws` is a Rust WebSocket server that speaks a JSON protocol
(`{"type":"subscribe"|"publish"|"data"...}`, see `tools/hdds-ws/src/protocol.rs`)
and owns the DDS participant. A browser cannot dlopen `libhdds_c.so`, so this is
the browser path. `ws_bridge.ts` implements a client for it with **zero
dependencies**: it uses the global `WebSocket` that Node >= 22 and every current
browser provide.

## Prerequisites

Node >= 18 for the native samples, Node >= 22 for `ws_bridge.ts` (global
`WebSocket`).

```bash
# 1. The shared library (native samples only)
cargo build --release -p hdds-c

# 2. The SDK and the samples, compiled (no ts-node, no tsx)
cd sdk/typescript
npm ci
npm run build          # -> dist/
npm run build:samples  # -> dist-samples/

# 3. The bridge (ws_bridge.ts only)
cargo run --release -p hdds-ws -- --port 9090 --domain 39 --transport udp
```

## Samples

| File | Path | Description |
|------|------|-------------|
| `hello_world.ts` | native | Intra-process pub/sub, 5 samples, no network |
| `publisher.ts`   | native | JSON sensor publisher, configurable topic/interval/count/domain |
| `subscriber.ts`  | native | Topic listener with a bounded timeout and an exit code |
| `qos_example.ts` | native | best_effort/volatile vs reliable/transient_local, measured on a late joiner |
| `ws_bridge.ts`   | bridge | hdds-ws JSON-over-WebSocket client, dependency-free |

These are symlinks to `sdk/typescript/samples/` - the canonical source.
On a Windows checkout without symlink support (`core.symlinks=false`, the
default outside Developer Mode) git writes each of these as a one-line text
file holding the relative path instead of the sample. Build and run the
samples from `sdk/typescript/samples/` there; that directory is the source
of truth on every platform, and it is the one the gate compiles.

## Running

```bash
cd sdk/typescript
export HDDS_LIB_PATH=$PWD/../../target/release

node dist-samples/hello_world.js
node dist-samples/publisher.js temperature 1000 5 39
node dist-samples/subscriber.js temperature 5 30 39
node dist-samples/qos_example.js

# needs the bridge from step 3 above
node dist-samples/ws_bridge.js ws://127.0.0.1:9090/ws temperature 3
```

Every one of these is executed by `sdk/typescript/tests/samples.test.ts`, which
asserts each sample's success line; `scripts/test-sdk.sh` Layer 1c runs that
suite as part of the SDK gate.

## Domain IDs

The networked samples default to domain **39**, the HDDS project domain. Pass a
different id as the last argument if you need one.

## Compatibility

- Interoperates with any DDS implementation over RTPS (FastDDS, CycloneDDS);
  the cross-language pub/sub matrix in `scripts/test-sdk.sh`
  covers Rust, C, C++, Python and TypeScript against each other.
- ROS 2 compatible through the DDS middleware layer.

## License

Apache-2.0 OR MIT
