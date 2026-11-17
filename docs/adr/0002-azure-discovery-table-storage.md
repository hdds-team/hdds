# ADR 0002: Azure participant discovery runs on Table Storage, authenticated by Entra ID identities

Status: accepted (2026-09-06). Scope: `hdds` `cloud-discovery` feature, Azure backend.

## Context

`discovery/cloud/azure.rs` shipped as a stub since the initial public
release: `register_participant` logged "would insert entity" and returned
`Ok(())`, `discover_participants` returned an empty vector after logging a
URL it never fetched, `deregister_participant` logged "would delete", and
`health_check` reported healthy whenever the instance metadata service was
unreachable. The only real network call was an IMDS lookup of the VM's
private address. The sync poller refused the Azure provider outright and
the participant builder never spawned it, so even a working backend would
have been unreachable from `Participant`.

Three Azure services could plausibly carry participant locators, and the
module's own rustdoc promised all of them ("DNS Private Zones", "Service
Bus Topics", "Table Storage"). One had to be chosen and the others
recorded as rejected, because a participant registry has a hard shape: a
late joiner must be able to READ the full current membership of its
domain, and each record must carry a GUID plus a list of locators.

## Decision

### 1. The registry is Azure Table Storage, over the data-plane REST API

One row per participant:

| column | meaning |
|---|---|
| `PartitionKey` | `domain-<id>`, or `<namespace>-domain-<id>` when a namespace is configured |
| `RowKey` | participant GUID, 32 hex characters |
| `Guid`, `Name`, `DomainId` | identity |
| `Locators` | JSON array of the participant's metatraffic unicast locators |
| `Metadata` | JSON object (vendor, version) |
| `LastUpdated`, `LeaseSeconds` | lease |

- register = `POST /Tables` (409 tolerated) then
  `PUT /{table}(PartitionKey='..',RowKey='..')`, an insert-or-replace, so
  the same call refreshes the lease;
- discover = `GET /{table}()?$filter=PartitionKey eq '..'`, following the
  `x-ms-continuation-*` headers, capped at 32 pages;
- deregister = `DELETE` with `If-Match: *`; a 404 is success.

Rationale: it is the only candidate that stores a full record (GUID +
locators + domain + metadata), returns the whole membership of a domain in
one filtered query, works identically on a VM, a VMSS instance, an AKS
node and an AKS pod, and has a local stand-in (Azurite) so the wire can be
exercised without an Azure account.

**DNS Private Zones: rejected.** A zone record carries a name and an
address, not a participant GUID, and writing one goes through the ARM
control plane (a different API, different rights, minutes of propagation).
Reading SRV records also needs a resolver: the standard library resolves
A/AAAA only, so it would mean a new dependency stack for the one thing
the query already gives us.

**Service Bus Topics: rejected as the registry.** A bus delivers
announcements to whoever is listening at that moment; a participant that
joins later hears nothing, so a store would still be needed underneath.
It remains a plausible LOW-LATENCY ANNOUNCER on top of the table, which
is not built (see 4).

**Azure Resource Manager tags: rejected.** VM-scoped, control-plane
rate-limited, and they require Contributor rights on the resource, which
is far more than a participant should hold.

### 2. Identity, not secrets: Managed Identity, AKS Workload Identity, or a scoped SAS

- **Managed Identity** (default): a bearer token from IMDS
  (`GET http://169.254.169.254/metadata/identity/oauth2/token`,
  `Metadata: true`), optionally selecting a user-assigned identity by
  `client_id`. Covers VM, VMSS and AKS-node-assigned identities.
- **AKS Workload Identity**: IMDS does not serve a POD-scoped identity, so
  a pod-level identity needs the federated flow -- read the projected
  token (`AZURE_FEDERATED_TOKEN_FILE`) and exchange it at the Entra ID
  authority (`client_credentials` + `client_assertion`). Every field
  defaults to the `AZURE_*` variable the AKS webhook projects. Without
  this flow, "AKS support" would mean node-assigned identity only, which
  gives every pod on the node the same rights.
- **SAS**: a scoped, expiring signature in the query string. `token_env`
  names the environment variable holding it, so the participant
  configuration itself carries no secret.

The identity must hold the `Storage Table Data Contributor` role on the
storage account.

**Shared Key (account key, connection string): refused, by name.** It is a
non-expiring shared secret that grants full data-plane rights over the
whole account, it cannot be scoped to one table, and rotating it breaks
every other consumer at once. A config that asks for it fails
`Participant::build()` with an error that says so. This also removes the
reason to carry a hand-rolled HMAC/base64 pair in the tree.

### 3. Fail closed, everywhere

- No credential -> no request at all. Nothing is advertised, the poller
  reports the error, the participant keeps running.
- The table endpoint follows the crate-wide registry transport rule:
  `https://` anywhere, plaintext `http://` only to a loopback literal
  (Azurite and the hermetic fake). No flag re-opens it.
- The instance-metadata endpoint may only be the well-known link-local
  address, an `https://` host, or a loopback literal.
- Unknown configuration fields are refused rather than defaulted.
- The whole config is parsed and validated at `Participant::build()`,
  because configuring a cloud registry lowers the multicast default: a
  config that only fails on the first poll would leave a participant with
  no peer source in either direction.
- A non-2xx query is an ERROR, never an empty registry: `Ok(vec![])` on a
  503 would make every peer look lost at once.
- A record whose lease has expired is ignored, and never deleted: it
  belongs to another participant.
- Every row is untrusted input. A row is ignored unless its `Guid` column
  equals the `RowKey` it is stored under and both decode as ASCII hex (a
  row carrying one multi-byte character used to PANIC the poller thread,
  which froze the status at `running: true` for the life of the process);
  the honoured lease is capped at four of the reader's own lease periods,
  so a row cannot declare itself immortal; a row replayed across
  continuation pages counts once.
- A credential never reaches an error, a log line or a `Debug` rendering.
  That includes the request URL, which carries the SAS signature: every
  transport error strips it.
- `health_check` answers `false` when the service is unreachable or
  refuses; it used to answer `true`.
- Table creation is BEST EFFORT: `409` (it exists) and `403` (this
  credential may not create tables, which is what a table-scoped SAS
  answers) both let the registration continue, because the entity upsert
  is the authority and reports `TableNotFound` itself. A `404` on any
  entity call clears the "table created" latch, so a table deleted under
  a running participant is created again on the next registration instead
  of erroring for the life of the process.
- A partition with more continuation pages than the cap (32) DEGRADES to
  the participants read so far, with a warning. Returning an error there
  discarded the peers already collected, so a churning deployment that
  outgrew the cap would have killed discovery outright and permanently.
- A participant that cannot refresh its row for a whole lease stops
  reporting itself as registered and arms the registration again: the
  status must not claim a record the registry has already dropped.
- The registered row carries the participant's OWN filtered metatraffic
  locators, never an address read from instance metadata: on AKS the
  instance address is the node's, not the pod's, and it bypasses the
  interface allowlist SPDP itself honours.

### 4. What is not built

- No Service Bus announcer, no DNS SRV path. The module rustdoc that
  listed them was a code comment describing an intention, not a published
  promise: the surfaces of record (README, website, datasheet) say "Azure
  VNet integration, managed identity", which this backend satisfies. The
  rustdoc now describes what exists and points here for the rejections.
- No rotation of a SAS while a participant is running; the signature is
  read once at build time.
- No reclamation of dead rows. `deregister_participant` deletes only the
  caller's own row, and an expired row is skipped but kept, so a partition
  grows with the deployment's churn until an operator (or a table
  lifecycle policy) removes the rows. Above 32 pages the poll reports what
  it read. If reclamation is ever wanted, the choice is between a filter
  on `LastUpdated` and a cross-owner delete for rows expired by several
  lease periods; neither is built.
- The liveness deadline compares the row's `LastUpdated` (the writer's
  wall clock) with the reader's, so a fleet with badly skewed clocks can
  hide live peers or keep dead ones for one lease. Azure stamps a
  service-side `Timestamp` on every row that would remove the skew;
  parsing its ISO-8601 form is not built, and Azurite/fake parity would
  have to be checked first.

### 5. Validation status

Everything is proven against an in-process fake (`test_support::fake_azure`)
that mints the tokens it accepts and answers `401` to any table request
without one. **No live Azure account has been used.** An opt-in test runs
the same participant against a local Azurite over SAS when
`HDDS_AZURITE_URL` and `HDDS_AZURITE_SAS` are set; it is not part of any
gate and is `#[ignore]`d so it can never contribute a green line to a
suite it did not run. **It has never been executed.** Documentation must
say "hermetic in-process tests only; not validated against Azurite or a
live Azure account" until an owner-run validation is filed.

## Consequences

- `AzureDiscovery::new(namespace)` keeps its shape but the argument is now
  a PartitionKey prefix, not a DNS zone; `from_config` is the real
  constructor. `Participant::create_azure_discovery()` parses the config
  the same way the poller does (it used to hand the JSON to `new()` as a
  zone name).
- `with_service_bus` is deprecated: it records a string nothing reads.
- `CloudPollerConfig` gains `heartbeat_interval`: a leased registry needs
  its row written again, and the idempotent registration call is that
  refresh. Consul, whose services persist until deregistered, keeps
  `None`.
- The Azure path pulls no new crate: `reqwest`, `serde` and `tokio` are
  already the feature's dependencies.

## Proofs

`cargo test -p hdds --all-features --test cloud_azure` and
`cargo test -p hdds --lib --all-features azure`:

| claim | test |
|---|---|
| a table-listed peer receives unicast SPDP, and the participant registers its own locators | `azure_discovered_peer_receives_unicast_spdp_from_table_storage` |
| an expired lease never becomes a peer and is never deleted by a non-owner | `azure_stale_lease_entity_is_never_turned_into_a_peer`, `discover_follows_continuation_pages_and_skips_expired_leases` |
| no token -> no row, no unauthenticated request | `azure_registration_fails_closed_without_a_managed_identity_token`, `register_fails_closed_when_no_token_can_be_minted` |
| Shared Key is refused at build time | `azure_build_refuses_shared_key_authentication`, `from_json_refuses_shared_key_by_name` |
| plaintext to a remote table endpoint is refused at build time | `azure_build_refuses_a_plaintext_remote_table_endpoint`, `table_endpoint_is_https_unless_the_host_is_loopback` |
| AKS Workload Identity exchanges the projected token, IMDS untouched | `workload_identity_exchanges_the_projected_federated_token` |
| a 503 is an error, not an empty registry; health_check fails closed | `a_non_2xx_query_is_an_error_not_an_empty_registry` |
| the lease is refreshed while the participant lives | `the_registration_is_refreshed_once_per_heartbeat_interval` |
| the token is cached, the table created once | `the_token_is_minted_once_and_the_table_created_once` |
| a SAS is used verbatim and mints no token | `a_sas_credential_is_appended_to_the_query_and_mints_no_token` |
| no credential ever reaches an error message (the URL carries the SAS) | `a_transport_failure_never_quotes_the_request_url_or_the_signature`, `debug_never_renders_the_service_bus_connection_string` |
| a poisoned row is skipped instead of panicking the poller | `a_row_that_is_not_ascii_hex_is_skipped_instead_of_panicking` |
| a row is trusted no further than its RowKey and a bounded lease | `a_row_is_not_trusted_further_than_its_row_key_and_a_bounded_lease`, `a_row_replayed_by_the_service_is_counted_once` |
| a registry past the page cap still answers | `a_registry_larger_than_the_page_cap_degrades_to_the_pages_that_were_read` |
| a credential that cannot create tables still registers; a deleted table comes back | `a_credential_that_may_not_create_tables_still_registers`, `a_table_deleted_under_a_running_participant_is_created_again` |
| an absurd `expires_in` is clamped instead of panicking | `an_absurd_token_lifetime_is_clamped_instead_of_overflowing_the_clock`, `an_absurd_lifetime_never_overflows_the_cache_deadline` |
| the federated token file and the SAS shape are checked at build time | `workload_identity_reads_its_token_file_at_build_time`, `a_sas_signature_must_already_be_url_encoded` |
| a lease that cannot be refreshed stops reading as registered; a panicking poller says so | `a_registration_that_cannot_be_refreshed_stops_being_reported_as_registered`, `a_panicking_backend_stops_the_poller_instead_of_freezing_its_status` |
