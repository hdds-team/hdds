# Live Consul agent (opt-in evidence run)

The Consul backend's gate is hermetic: `test_support::fake_consul` is an
in-process agent on `127.0.0.1:0` and needs no container. This directory
is for the extra evidence run against a REAL agent, which nothing in CI
depends on.

```sh
docker compose -f tools/docker-consul/compose.yml up -d
HDDS_CONSUL_URL=http://127.0.0.1:8500 \
  cargo test -p hdds --all-features --test cloud_consul -- --ignored --nocapture
docker compose -f tools/docker-consul/compose.yml down
```

`consul_live_agent_round_trip` builds two participants pointed at the
agent, waits for both to report `registered`, waits for each to discover
the other through `/v1/health/service/...?passing=true`, then drops one
and waits for the survivor's `registry_peers` to fall back to zero. It
uses a service name of the form `hdds-live-<pid>` so several runs (or a
shared agent) cannot mix.

Without `HDDS_CONSUL_URL` the test prints
`SKIPPED consul_live_agent_round_trip: HDDS_CONSUL_URL is not set` and
returns: a run that proves nothing says so by name.

ACLs: the compose file runs `consul agent -dev`, which has ACLs disabled.
To exercise the `X-Consul-Token` path against a real agent, start Consul
with ACLs bootstrapped and export `HDDS_CONSUL_TOKEN` as well. The token
path is covered hermetically by
`token_is_sent_as_x_consul_token_header_on_every_request` and
`consul_options_from_the_builder_reach_every_request`.

## Run of record

| run | image | agent version | result |
|---|---|---|---|
| first run | `hashicorp/consul:1.20.2` (digest `sha256:02739a744b71931209f275bea234c6bc0b747e41266462744a6774b99c08b98d`) | 1.20.2, datacenter `dc1`, `agent -dev` | `consul_live_agent_round_trip ... ok`, `1 passed; 0 failed`, 3.03 s |
| after the review fixes | `hashicorp/consul:1.20.2` (local image `sha256:7ef86f6073b136731c66f7258cd07bd6c96fb84589aca2a147f183648a38be13`) | 1.20.2, datacenter `dc1`, `agent -dev` | `consul_live_agent_round_trip ... ok`, `1 passed; 0 failed`, 3.13 s |

### What the in-process fake models, checked against that agent

The hermetic gate is only as good as the double. These four answers were
read back from the live agent in the same session, and
`test_support::fake_consul` reproduces each of them:

| request | hashicorp/consul 1.20.2 answered |
|---|---|
| register with a 545-character `Meta` value | `400 Invalid Service Meta: Couldn't load metadata pair ('locators', 'xxx...` |
| register with a 512-character `Meta` value | `200` (the limit is a ceiling, not an off-by-one) |
| register with the `Meta` key `user_my.key` | `400 Invalid Service Meta: Couldn't load metadata pair ('user_my.key', 'v'): Key contains invalid characters` |
| `PUT /v1/agent/check/pass/service%3Aghost` | `404 Unknown check ID "service:ghost". Ensure that the check ID is passed, not the check name.` |

The last one is what `HeartbeatError::RecordGone` is keyed on: 404 is the
one status that means "register again".

Negative control, so the assertions are known to bite: with `HDDS_CONSUL_URL=http://127.0.0.1:9` (nothing listening) the
test FAILS at `participant a never registered`, after 5 registration
attempts and 30 consecutive failed polls. Re-run after the review fixes:
`test result: FAILED. 0 passed; 1 failed`, 32.06 s.

Not covered by that run: ACLs (the `-dev` agent has none), TLS to the
agent, a multi-node datacenter, and the real TTL expiry path (the run is
seconds long; the hermetic `consul_peer_that_stops_heartbeating_leaves_the_peer_set`
covers the expiry by marking the check critical). Say so before claiming
anything wider.
