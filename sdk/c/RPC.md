# C RPC API (candidate 1.5.0)

Enable the optional API in the library and in its C/C++ consumer:

```sh
cargo build --locked -p hdds-c --features rpc
cmake -S sdk/c -B build/c-rpc \
  -DHDDS_C_LIB_DIR="$PWD/target/debug" -DHDDS_WITH_RPC=ON
cmake --build build/c-rpc
ctest --test-dir build/c-rpc --output-on-failure
```

Outside CMake, define `HDDS_WITH_RPC` before including `hdds.h` and link the
library built with `rpc`. The generated header contains feature-guarded
prototypes even when a default library is built. Defining the C macro does not
add missing symbols to a library. C++ callers can use the same C declarations
with C linkage:

```cpp
#define HDDS_WITH_RPC
extern "C" {
#include <hdds.h>
}
```

## Behavior and ownership

- Create a participant, then create a server with a callback and start it using
  `hdds_rpc_server_spin_background` or the blocking `hdds_rpc_server_spin`.
  A server starts once. A successful background start acknowledges runtime
  initialization. Timeout configuration must precede spin.
- Create a client for the same service name. `hdds_rpc_client_call` uses its
  explicit millisecond timeout; zero expires immediately. The separate
  `hdds_rpc_client_call_default` uses the timeout configured at creation.
  Queueing on the local client worker counts against the call's deadline.
  Each client admits at most 64 calls, including queued/cancelling work; further
  calls return `HDDS_WOULD_BLOCK` so callers can retry with backoff.
- An empty request is NULL/0. A nonempty request is borrowed for the call;
  the caller must keep its bytes stable. NULL with a positive length is rejected.
- On success, a nonempty client reply is allocated by Rust. Free the exact
  pointer/length pair once with `hdds_rpc_reply_free`, never with C `free`.
  Empty replies and valid outputs on failure are reset to NULL/0.
- A callback returns 0 for success, or a remote exception constant on error.
  For success it transfers a `malloc` allocation compatible with the C runtime
  used by HDDS. HDDS copies and frees it, including non-NULL empty allocations.
  NULL/0 is also a valid empty reply. On error, output values are ignored;
  the callback retains responsibility for allocations it made.
- A local/client timeout returns `HDDS_TIMEOUT`; shutdown returns
  `HDDS_INVALID_STATE`. Every remote exception returns `HDDS_OPERATION_FAILED`,
  including a server-side handler timeout: DDS-RPC defines no timeout code, so
  the server sends `HDDS_RPC_UNKNOWN_EXCEPTION`. Detailed remote exception
  retrieval is not exposed.

## Threads, timeouts and shutdown

Each C client has a runtime driven continuously by its own thread. Calls from
multiple C threads are supported. Each server has a runtime owner thread and
executes callbacks sequentially on blocking workers; their thread identity may
change between calls. No Tokio runtime is
entered on a foreign caller's thread. A callback can call a different service;
a synchronous cycle back to the same sequential server waits until timeout.

The server request timeout measures handler execution from local dispatch. It
neither measures age in the DDS queue nor propagates a client's deadline. When
it expires, HDDS sends an `HDDS_RPC_UNKNOWN_EXCEPTION` reply and waits for that
callback to finish before dispatching another. A client timeout cancels local waiting; it cannot
undo a remote side effect or forcibly stop a callback.

`shutdown` is safe alongside live calls and may be requested by a callback.
A handle remains valid until destroyed. Destruction requires exclusive ownership:
join all external operations, including blocking spin, first. Server destruction
waits for active callbacks before returning, so user_data may then be freed.
A callback must not destroy its own server. A callback that never returns also
prevents destruction from returning. Callbacks must not unwind across the C ABI.

## Local registry and wire scope

`hdds_rpc_service_count` and `hdds_rpc_service_name` inspect local Rust server
registrations, grouped by service name across domains. An unstarted server is
registered. A spinning server's registration ends when its spin future exits;
a C handle can remain valid after that. Duplicate owners retain a registration
until the last underlying server ends. Each query takes a separate snapshot;
concurrent server changes can move indices. This is not remote discovery or a
service readiness check.

The wire body starts with the OMG DDS-RPC 1.0 Basic Service Mapping header
(formal/17-04-01, clause 7.5.1.1.1) in little-endian plain CDR. A request
carries `RequestHeader`: a 24-byte `SampleIdentity` (16-byte writer GUID, then
the RTPS `SequenceNumber_t` as `high` then `low` 32-bit words) and the
`string<255>` `instanceName` (empty unless set), padded to a 4-byte boundary,
so the payload of a request with an empty instance name starts at byte 32. A
reply carries the 28-byte `ReplyHeader`: the related `SampleIdentity` and the
4-byte `RemoteExceptionCode_t`, whose values are the `HDDS_RPC_*` constants.
Application bytes follow immediately; payload serialization belongs to the
application, and this API does not generate the typed `_Call`/`_Return` IDL
unions. The receiving endpoint decodes its own header type; correlation uses
the actual request writer's DDS identity. The header layout is pinned in the
Rust unit tests against byte vectors produced by fastddsgen 4.0.4 and Fast-CDR
2.3.3 from the specification's IDL.

The RTPS-level sample encapsulation (the representation id in the 4-byte
header the RTPS DATA submessage wraps the CDR body in, separate from the
header layout above) is `PLAIN_CDR_LE` (`0x0001`), not the DDS-XTypes-only
`PLAIN_CDR2_LE` (`0x0007`) HDDS uses for ordinary topics: clause 7.5.1.1 says
the Basic Service Mapping "maps interfaces to data-types that can be used by
DDS version 1.3 compliant implementations, which may lack support for the
[DDS-XTypes] specification", so the writer must not offer a peer an
XTypes-only representation. This is proven by chaining the crate's own
representation-negotiation functions (`rpc::tests::
rpc_qos_negotiates_to_plain_cdr_le_via_the_shared_cdr_negotiation_path`); an
end-to-end wire capture against a real peer or a real foreign DDS-RPC
implementation has not been run.

Topic names are still an HDDS convention (`rq/{service}` / `rr/{service}`)
at the C ABI: `hdds_rpc_client_create` / `hdds_rpc_server_create` take only a
service name, not the request/reply topics, so a C caller cannot point them
at a peer using the specification's own default names (7.4.1) or any other
convention. The Rust API added `ServiceClient::with_topic_names` /
`ServiceServer::with_topic_names` for that; the C ABI does not expose it yet.

Typed `_Call`/`_Return` operation unions (7.5.1.1.4/7.5.1.1.6, discriminated
by the `HASH(operation_name)` of clause 7.5.1.1.2) are not implemented and
out of scope here: this is an `hdds_gen` (IDL code generation) feature, not a
runtime change, and none of the code generation for it exists yet. A service
with more than one operation must invent and check its own discriminator
inside the opaque payload; this API neither computes nor verifies one. See
`crates/hdds/src/rpc/mod.rs` ("Scope: typed operation unions") for the full
statement of what a consumer can and cannot rely on.

**End-to-end interoperability with a foreign DDS-RPC implementation has not
been validated** (topic naming agreement with a real peer, and the typed
unions above). Interoperability testing against a foreign DDS-RPC implementation remains
required before this API is declared stable.

The POSIX C regression consumer is `sdk/c/tests/test_rpc.c`; it covers actual
binary/empty exchanges, nested and concurrent calls, errors, shutdown, deadlines,
blocking spin, and callback lifetime during destruction.
