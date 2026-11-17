// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Backend-level tests for the Azure Table Storage discovery backend.
//!
//! Every network test runs against `test_support::fake_azure`: one
//! loopback HTTP server that mints the tokens it accepts and refuses any
//! table request carrying no credential it issued. No Azure account, no
//! Azurite, no network.

use super::*;

// ---------------------------------------------------------------------------
// Pure shape tests (no feature needed)
// ---------------------------------------------------------------------------

#[test]
fn to_hex_renders_lowercase_bytes() {
    assert_eq!(to_hex(&[0xca, 0xfe, 0xba, 0xbe]), "cafebabe");
}

#[test]
fn entity_id_is_the_short_guid_form() {
    let discovery = AzureDiscovery::new("").expect("construct");
    let guid = [
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert_eq!(discovery.entity_id(&guid), "hdds-aabbccddeeff0011");
}

// ---------------------------------------------------------------------------
// Backend tests against the hermetic fake
// ---------------------------------------------------------------------------

#[cfg(feature = "cloud-discovery")]
mod backend {
    use super::*;
    use crate::test_support::fake_azure::{FakeAzure, TokenScript};
    use std::collections::HashMap;

    const TABLE: &str = "hddsparticipants";

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime")
    }

    fn config_json(url: &str, auth: &str) -> String {
        format!(
            r#"{{"account":"hddsacct","table":"{}","auth":{},"endpoint":"{}","imds_endpoint":"{}","authority_endpoint":"{}"}}"#,
            TABLE, auth, url, url, url
        )
    }

    fn backend(url: &str, auth: &str, domain_id: u32) -> AzureDiscovery {
        let config =
            AzureDiscoveryConfig::from_json(&config_json(url, auth)).expect("valid config");
        AzureDiscovery::from_config(config)
            .expect("backend")
            .with_domain_id(domain_id)
    }

    fn info(guid: u8, domain_id: u32, port: u32) -> ParticipantInfo {
        let mut metadata = HashMap::new();
        metadata.insert("vendor".to_string(), "hdds".to_string());
        ParticipantInfo {
            guid: [guid; 16],
            name: format!("node-{}", guid),
            domain_id,
            locators: vec![Locator {
                kind: 1,
                port,
                address: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, guid],
            }],
            metadata,
        }
    }

    fn peer_row(guid: u8, domain_id: u32, port: u32, last_updated: u64, lease: u32) -> String {
        let mut address = [0u8; 16];
        address[12..].copy_from_slice(&[198, 51, 100, guid]);
        let locators = serialize_locators(&[Locator {
            kind: 1,
            port,
            address,
        }])
        .replace('"', "\\\"");
        format!(
            concat!(
                r#"{{"PartitionKey":"domain-{domain}","RowKey":"{guid}","Guid":"{guid}","#,
                r#""Name":"peer","DomainId":{domain},"Locators":"{locators}","#,
                r#""Metadata":"{{}}","LastUpdated":"{updated}","LeaseSeconds":{lease}}}"#
            ),
            domain = domain_id,
            guid = to_hex(&[guid; 16]),
            locators = locators,
            updated = last_updated,
            lease = lease
        )
    }

    /// One row with every key spelled out, for the rows a well-behaved
    /// participant would never write.
    fn row(
        row_key: &str,
        guid: &str,
        domain_id: u32,
        port: u32,
        last_updated: u64,
        lease: u32,
    ) -> String {
        let mut address = [0u8; 16];
        address[12..].copy_from_slice(&[198, 51, 100, 1]);
        let locators = serialize_locators(&[Locator {
            kind: 1,
            port,
            address,
        }])
        .replace('"', "\\\"");
        format!(
            concat!(
                r#"{{"PartitionKey":"domain-{domain}","RowKey":"{row_key}","Guid":"{guid}","#,
                r#""Name":"peer","DomainId":{domain},"Locators":"{locators}","#,
                r#""Metadata":"{{}}","LastUpdated":"{updated}","LeaseSeconds":{lease}}}"#
            ),
            domain = domain_id,
            row_key = row_key,
            guid = guid,
            locators = locators,
            updated = last_updated,
            lease = lease
        )
    }

    /// One row whose single locator carries `address` verbatim.
    fn row_with_address(
        row_key: &str,
        address: &str,
        domain_id: u32,
        last_updated: u64,
        lease: u32,
    ) -> String {
        format!(
            concat!(
                r#"{{"PartitionKey":"domain-{domain}","RowKey":"{row_key}","Guid":"{row_key}","#,
                r#""Name":"peer","DomainId":{domain},"#,
                r#""Locators":"[{{\"kind\":1,\"port\":7415,\"address\":\"{address}\"}}]","#,
                r#""Metadata":"{{}}","LastUpdated":"{updated}","LeaseSeconds":{lease}}}"#
            ),
            domain = domain_id,
            row_key = row_key,
            address = address,
            updated = last_updated,
            lease = lease
        )
    }

    fn now() -> u64 {
        now_secs()
    }

    /// Register creates the table, writes the row under a bearer token
    /// the fake minted, and advertises the CALLER's locators.
    #[test]
    fn register_creates_the_table_and_upserts_a_row_with_a_bearer_token() {
        let azure = FakeAzure::start().expect("fake");
        let discovery = backend(&azure.url(), r#"{"kind":"managed_identity"}"#, 39);
        let record = info(7, 39, 7410);

        runtime()
            .block_on(discovery.register_participant(&record))
            .expect("registration succeeds");

        assert_eq!(azure.tables(), vec![TABLE.to_string()]);
        assert_eq!(azure.unauthenticated_attempts(), 0);
        let entities = azure.entities();
        assert_eq!(entities.len(), 1, "{:?}", entities);
        let (partition_key, row_key, body) = &entities[0];
        assert_eq!(partition_key, "domain-39");
        assert_eq!(row_key, &to_hex(&record.guid));
        assert!(body.contains(r#""Name":"node-7""#), "{}", body);
        assert!(body.contains(r#""LeaseSeconds":60"#), "{}", body);
        // The advertised locator is the caller's, port included.
        assert!(body.contains("7410"), "locator port missing: {}", body);
        // Instance metadata was used for the TOKEN only, never for an
        // address: no instance route was ever requested.
        assert!(
            azure
                .requests_matching("GET", "/metadata/instance")
                .is_empty(),
            "the backend read an instance address"
        );

        let bearer = azure
            .requests_matching("PUT", "/hddsparticipants(")
            .first()
            .and_then(|request| request.header("authorization").map(str::to_string))
            .expect("the upsert carried an Authorization header");
        assert!(bearer.starts_with("Bearer fake-azure-token-"), "{}", bearer);
    }

    /// A second register reuses the cached token and does not re-create
    /// the table.
    #[test]
    fn the_token_is_minted_once_and_the_table_created_once() {
        let azure = FakeAzure::start().expect("fake");
        let discovery = backend(&azure.url(), r#"{"kind":"managed_identity"}"#, 39);
        let record = info(7, 39, 7410);
        let runtime = runtime();
        runtime
            .block_on(discovery.register_participant(&record))
            .expect("first registration");
        runtime
            .block_on(discovery.register_participant(&record))
            .expect("heartbeat registration");

        assert_eq!(azure.token_requests(), 1, "the token was not cached");
        assert_eq!(
            azure.requests_matching("POST", "/Tables").len(),
            1,
            "the table was created twice"
        );
        assert_eq!(azure.entities().len(), 1, "the row was duplicated");
    }

    /// A table that already exists answers 409, which is success.
    #[test]
    fn an_existing_table_is_not_an_error() {
        let azure = FakeAzure::start().expect("fake");
        azure.create_table(TABLE);
        let discovery = backend(&azure.url(), r#"{"kind":"managed_identity"}"#, 39);
        runtime()
            .block_on(discovery.register_participant(&info(7, 39, 7410)))
            .expect("409 on table creation is tolerated");
        assert_eq!(azure.entities().len(), 1);
    }

    /// Fail closed: no identity, no token, no request, no row.
    #[test]
    fn register_fails_closed_when_no_token_can_be_minted() {
        let azure = FakeAzure::start().expect("fake");
        azure.set_token_script(TokenScript::Status(500));
        let discovery = backend(&azure.url(), r#"{"kind":"managed_identity"}"#, 39);

        let error = runtime()
            .block_on(discovery.register_participant(&info(7, 39, 7410)))
            .expect_err("no token must fail the registration");
        let Error::Config(message) = &error else {
            panic!("unexpected error kind: {:?}", error);
        };
        assert!(
            message.contains("token endpoint answered HTTP 500"),
            "{}",
            message
        );
        assert!(
            azure.entities().is_empty(),
            "a row was written with no token"
        );
        assert_eq!(
            azure.unauthenticated_attempts(),
            0,
            "a table request went out without a credential"
        );
    }

    /// Discovery reads the domain partition, follows the continuation
    /// pages, and drops rows whose lease has expired.
    #[test]
    fn discover_follows_continuation_pages_and_skips_expired_leases() {
        let azure = FakeAzure::start().expect("fake");
        azure.create_table(TABLE);
        let now = now();
        for guid in [1u8, 2, 3] {
            azure.put_entity(
                "domain-39",
                &to_hex(&[guid; 16]),
                &peer_row(guid, 39, 7410 + u32::from(guid), now, 60),
            );
        }
        // Expired: last seen two hours ago with a 60 s lease.
        azure.put_entity(
            "domain-39",
            &to_hex(&[9u8; 16]),
            &peer_row(9, 39, 7419, now - 7200, 60),
        );
        // Another domain's partition is never queried.
        azure.put_entity(
            "domain-40",
            &to_hex(&[8u8; 16]),
            &peer_row(8, 40, 7420, now, 60),
        );
        azure.set_page_size(2);

        let discovery = backend(&azure.url(), r#"{"kind":"managed_identity"}"#, 39);
        let peers = runtime()
            .block_on(discovery.discover_participants())
            .expect("query succeeds");

        let mut guids: Vec<u8> = peers.iter().map(|peer| peer.guid[0]).collect();
        guids.sort_unstable();
        assert_eq!(guids, vec![1, 2, 3], "peers: {:?}", guids);
        assert!(peers.iter().all(|peer| peer.domain_id == 39));
        assert_eq!(peers[0].locators.len(), 1);
        assert!(
            azure.requests_matching("GET", "/hddsparticipants()").len() >= 2,
            "the continuation page was not followed"
        );
        assert!(
            azure
                .entities()
                .iter()
                .any(|(_, row_key, _)| *row_key == to_hex(&[9u8; 16])),
            "an expired row was deleted by a participant that does not own it"
        );
    }

    /// A registry hiccup is an ERROR, never an empty registry: the poller
    /// keeps its peer view only because this returns `Err`.
    #[test]
    fn a_non_2xx_query_is_an_error_not_an_empty_registry() {
        let azure = FakeAzure::start().expect("fake");
        azure.create_table(TABLE);
        azure.put_entity(
            "domain-39",
            &to_hex(&[1u8; 16]),
            &peer_row(1, 39, 7411, now(), 60),
        );
        let discovery = backend(&azure.url(), r#"{"kind":"managed_identity"}"#, 39);
        let runtime = runtime();
        assert_eq!(
            runtime
                .block_on(discovery.discover_participants())
                .expect("healthy query")
                .len(),
            1
        );

        azure.set_table_status(503);
        let error = runtime
            .block_on(discovery.discover_participants())
            .expect_err("a 503 must not read as an empty registry");
        let Error::Config(message) = &error else {
            panic!("unexpected error kind: {:?}", error);
        };
        assert!(message.contains("503"), "{}", message);

        // Fail closed on the same failure: health_check answers false
        // instead of the old "unreachable, so probably fine".
        assert!(
            !runtime
                .block_on(discovery.health_check())
                .expect("health check"),
            "an unreachable or refusing table service must not report healthy"
        );
    }

    /// Deregistration deletes the row, and a row that is already gone is
    /// success.
    #[test]
    fn deregister_deletes_the_row_and_tolerates_404() {
        let azure = FakeAzure::start().expect("fake");
        let discovery = backend(&azure.url(), r#"{"kind":"managed_identity"}"#, 39);
        let record = info(7, 39, 7410);
        let runtime = runtime();
        runtime
            .block_on(discovery.register_participant(&record))
            .expect("registration");
        assert_eq!(azure.entities().len(), 1);

        runtime
            .block_on(discovery.deregister_participant(record.guid))
            .expect("deregistration");
        assert!(azure.entities().is_empty());

        runtime
            .block_on(discovery.deregister_participant(record.guid))
            .expect("a row that is already gone is not an error");
        let deletes = azure.requests_matching("DELETE", "/hddsparticipants(");
        assert_eq!(deletes.len(), 2);
        assert_eq!(deletes[0].header("if-match"), Some("*"));
    }

    /// A SAS credential travels in the query string; no token endpoint is
    /// ever contacted.
    #[test]
    fn a_sas_credential_is_appended_to_the_query_and_mints_no_token() {
        let azure = FakeAzure::start().expect("fake");
        azure.set_sas_signature("ABC/def");
        let discovery = backend(
            &azure.url(),
            r#"{"kind":"sas","token":"?sv=2024-11-04&sig=ABC%2Fdef"}"#,
            39,
        );
        runtime()
            .block_on(discovery.register_participant(&info(7, 39, 7410)))
            .expect("registration over SAS");

        assert_eq!(azure.token_requests(), 0, "a SAS needs no token endpoint");
        assert_eq!(azure.unauthenticated_attempts(), 0);
        assert_eq!(azure.entities().len(), 1);
        let upsert = azure.requests_matching("PUT", "/hddsparticipants(");
        assert!(upsert[0].header("authorization").is_none());
        assert!(
            upsert[0]
                .query()
                .unwrap_or_default()
                .contains("sig=ABC%2Fdef"),
            "the signature was re-encoded: {:?}",
            upsert[0].query()
        );
    }

    /// AKS Workload Identity (AZ-2): the projected federated token is
    /// exchanged at the authority for a storage bearer token.
    #[test]
    fn workload_identity_exchanges_the_projected_federated_token() {
        let directory = tempfile::tempdir().expect("temp dir");
        let token_file = directory.path().join("federated-token");
        std::fs::write(&token_file, "PROJECTED.JWT.VALUE\n").expect("write token file");

        let azure = FakeAzure::start().expect("fake");
        azure.set_federated_assertion("PROJECTED.JWT.VALUE");
        let auth = format!(
            r#"{{"kind":"workload_identity","tenant_id":"tenant-1","client_id":"client-1","token_file":"{}"}}"#,
            token_file.display()
        );
        let discovery = backend(&azure.url(), &auth, 39);

        runtime()
            .block_on(discovery.register_participant(&info(7, 39, 7410)))
            .expect("registration over workload identity");

        let exchanges = azure.requests_matching("POST", "/tenant-1/oauth2/v2.0/token");
        assert_eq!(exchanges.len(), 1, "the federated token was not exchanged");
        let body = exchanges[0].body_text();
        assert!(body.contains("grant_type=client_credentials"), "{}", body);
        assert!(
            body.contains("client_assertion=PROJECTED.JWT.VALUE"),
            "{}",
            body
        );
        assert!(
            azure
                .requests_matching("GET", "/metadata/identity")
                .is_empty(),
            "IMDS was contacted for a pod-scoped identity"
        );
        assert_eq!(azure.entities().len(), 1);

        // A backend built while the file existed, kept for the check
        // below (no token minted yet, so nothing is cached).
        let standby = backend(&azure.url(), &auth, 39);

        // A token file that disappears fails closed BOTH ways: a new
        // configuration is refused at build time, and a backend that
        // already exists refuses on the next mint.
        std::fs::remove_file(&token_file).expect("remove token file");
        let Err(Error::Config(message)) =
            AzureDiscoveryConfig::from_json(&config_json(&azure.url(), &auth))
        else {
            panic!("a missing federated token file was accepted at build time");
        };
        assert!(message.contains("unreadable"), "{}", message);
        assert!(runtime()
            .block_on(standby.register_participant(&info(7, 39, 7410)))
            .is_err());
    }

    /// A backend with no account or table configured refuses every call
    /// rather than building a URL out of defaults.
    #[test]
    fn an_unconfigured_backend_refuses_every_call() {
        let discovery = AzureDiscovery::new("fleet").expect("construct");
        let runtime = runtime();
        assert!(runtime
            .block_on(discovery.register_participant(&info(7, 39, 7410)))
            .is_err());
        assert!(runtime.block_on(discovery.discover_participants()).is_err());
        assert!(runtime
            .block_on(discovery.deregister_participant([7; 16]))
            .is_err());
    }

    /// The namespace becomes a PartitionKey prefix, and the URL shapes
    /// are the ones the Table service defines.
    #[test]
    fn partition_key_and_urls_follow_the_table_service_shapes() {
        let discovery = AzureDiscovery::new("fleet-a")
            .expect("construct")
            .with_table_storage("hddsacct", "mytable")
            .with_domain_id(39);
        assert_eq!(discovery.partition_key(), "fleet-a-domain-39");
        assert_eq!(
            discovery.table_storage_url("mytable"),
            Some("https://hddsacct.table.core.windows.net/mytable".to_string())
        );
        assert_eq!(
            discovery.entity_url(
                "https://hddsacct.table.core.windows.net/mytable",
                "domain-39",
                "abcd"
            ),
            "https://hddsacct.table.core.windows.net/mytable(PartitionKey='domain-39',RowKey='abcd')"
        );
        assert_eq!(
            encode_query_value("PartitionKey eq 'domain-39'"),
            "PartitionKey%20eq%20%27domain-39%27"
        );

        let plain = AzureDiscovery::new("")
            .expect("construct")
            .with_domain_id(7);
        assert_eq!(plain.partition_key(), "domain-7");
    }

    /// A transport failure reaches `cloud_discovery_status().last_error`
    /// and the log. The request URL carries the SAS signature, so the
    /// message must never quote a URL.
    #[test]
    fn a_transport_failure_never_quotes_the_request_url_or_the_signature() {
        const SIGNATURE: &str = "sv=2024-11-04&sig=SUPERSECRETSIGNATURE";
        // Port 1 on loopback: nothing listens there, so every call fails
        // in transport rather than at the service.
        let discovery = backend(
            "http://127.0.0.1:1",
            &format!(r#"{{"kind":"sas","token":"{}"}}"#, SIGNATURE),
            39,
        );
        let runtime = runtime();
        let messages = [
            format!(
                "{:?}",
                runtime
                    .block_on(discovery.register_participant(&info(7, 39, 7410)))
                    .expect_err("a dead endpoint fails the registration")
            ),
            format!(
                "{:?}",
                runtime
                    .block_on(discovery.discover_participants())
                    .expect_err("a dead endpoint fails the query")
            ),
            format!(
                "{:?}",
                runtime
                    .block_on(discovery.deregister_participant([7; 16]))
                    .expect_err("a dead endpoint fails the delete")
            ),
        ];
        for message in &messages {
            assert!(
                !message.contains("SUPERSECRETSIGNATURE"),
                "the SAS signature leaked into an error: {}",
                message
            );
            assert!(
                !message.contains("sig="),
                "a credential-bearing URL leaked into an error: {}",
                message
            );
        }
    }

    /// Registry rows are foreign bytes: one poisoned row must be skipped,
    /// never panic the poller thread (which would freeze the status at
    /// `running: true` for the life of the process).
    #[test]
    fn a_row_that_is_not_ascii_hex_is_skipped_instead_of_panicking() {
        let azure = FakeAzure::start().expect("fake");
        azure.create_table(TABLE);
        let now = now();
        // A GUID whose byte 2 falls INSIDE a multi-byte character.
        azure.put_entity(
            "domain-39",
            "poisoned-guid",
            &row("poisoned-guid", "a\u{e9}b", 39, 7411, now, 60),
        );
        // A well-formed row whose locator address is not ASCII either
        // (byte 2 falls inside the multi-byte character).
        azure.put_entity(
            "domain-39",
            &to_hex(&[5u8; 16]),
            &row_with_address(&to_hex(&[5u8; 16]), &format!("c{}d", '\u{e9}'), 39, now, 60),
        );
        azure.put_entity(
            "domain-39",
            &to_hex(&[1u8; 16]),
            &peer_row(1, 39, 7411, now, 60),
        );

        let discovery = backend(&azure.url(), r#"{"kind":"managed_identity"}"#, 39);
        let peers = runtime()
            .block_on(discovery.discover_participants())
            .expect("a poisoned row is skipped, not an error");
        let mut guids: Vec<u8> = peers.iter().map(|peer| peer.guid[0]).collect();
        guids.sort_unstable();
        assert_eq!(guids, vec![1, 5], "peers: {:?}", guids);
        assert!(
            peers
                .iter()
                .find(|peer| peer.guid[0] == 5)
                .expect("the row with the bad locator is still a peer")
                .locators
                .is_empty(),
            "a locator that is not ASCII hex was decoded"
        );
    }

    /// An issuer that reports an absurd lifetime must not overflow the
    /// cache deadline (`Instant + Duration` panics on overflow).
    #[test]
    fn an_absurd_token_lifetime_is_clamped_instead_of_overflowing_the_clock() {
        let azure = FakeAzure::start().expect("fake");
        azure.set_token_script(TokenScript::Ok {
            expires_in: u64::MAX,
        });
        let discovery = backend(&azure.url(), r#"{"kind":"managed_identity"}"#, 39);
        runtime()
            .block_on(discovery.register_participant(&info(7, 39, 7410)))
            .expect("an absurd expires_in must not kill the poller");
        assert_eq!(azure.entities().len(), 1);
    }

    /// A registry with more pages than the cap DEGRADES to the pages that
    /// were read. Returning `Err` there would discard the peers already
    /// collected and freeze discovery for good once a churning partition
    /// crosses the cap.
    #[test]
    fn a_registry_larger_than_the_page_cap_degrades_to_the_pages_that_were_read() {
        let azure = FakeAzure::start().expect("fake");
        azure.create_table(TABLE);
        let now = now();
        let rows = MAX_QUERY_PAGES + 8;
        for guid in 1..=rows {
            let guid = guid as u8;
            azure.put_entity(
                "domain-39",
                &to_hex(&[guid; 16]),
                &peer_row(guid, 39, 7400 + u32::from(guid), now, 60),
            );
        }
        azure.set_page_size(1);

        let discovery = backend(&azure.url(), r#"{"kind":"managed_identity"}"#, 39);
        let peers = runtime()
            .block_on(discovery.discover_participants())
            .expect("a registry past the page cap must still answer");
        assert_eq!(
            peers.len(),
            MAX_QUERY_PAGES,
            "the pages that were read were discarded"
        );
    }

    /// A credential scoped to one table cannot create tables. Table
    /// creation is best effort: the entity upsert is the authority.
    #[test]
    fn a_credential_that_may_not_create_tables_still_registers() {
        let azure = FakeAzure::start().expect("fake");
        azure.create_table(TABLE);
        azure.set_table_create_status(403);
        let discovery = backend(&azure.url(), r#"{"kind":"managed_identity"}"#, 39);

        runtime()
            .block_on(discovery.register_participant(&info(7, 39, 7410)))
            .expect("a 403 on table creation must not block the registration");
        assert_eq!(azure.entities().len(), 1);
    }

    /// A table deleted under a running participant is created again
    /// instead of erroring for the life of the process.
    #[test]
    fn a_table_deleted_under_a_running_participant_is_created_again() {
        let azure = FakeAzure::start().expect("fake");
        let discovery = backend(&azure.url(), r#"{"kind":"managed_identity"}"#, 39);
        let record = info(7, 39, 7410);
        let runtime = runtime();
        runtime
            .block_on(discovery.register_participant(&record))
            .expect("first registration");

        azure.drop_table(TABLE);
        // The first attempt after the loss reports it (the client cannot
        // know before it is refused)...
        assert!(runtime
            .block_on(discovery.register_participant(&record))
            .is_err());
        // ... and the next one re-creates the table.
        runtime
            .block_on(discovery.register_participant(&record))
            .expect("the table must be created again");
        assert_eq!(azure.entities().len(), 1);
        assert_eq!(
            azure.requests_matching("POST", "/Tables").len(),
            2,
            "the table was never created again"
        );
    }

    /// A row is not trusted further than its own key: the GUID must be
    /// the RowKey, and a row cannot declare itself immortal.
    #[test]
    fn a_row_is_not_trusted_further_than_its_row_key_and_a_bounded_lease() {
        let azure = FakeAzure::start().expect("fake");
        azure.create_table(TABLE);
        let now = now();
        azure.put_entity(
            "domain-39",
            &to_hex(&[1u8; 16]),
            &peer_row(1, 39, 7411, now, 60),
        );
        // RowKey and Guid disagree: somebody else's identity.
        azure.put_entity(
            "domain-39",
            &to_hex(&[2u8; 16]),
            &row(&to_hex(&[2u8; 16]), &to_hex(&[3u8; 16]), 39, 7412, now, 60),
        );
        // Immortal by its own claim: last seen an hour ago, lease u32::MAX.
        azure.put_entity(
            "domain-39",
            &to_hex(&[4u8; 16]),
            &row(
                &to_hex(&[4u8; 16]),
                &to_hex(&[4u8; 16]),
                39,
                7414,
                now - 3600,
                u32::MAX,
            ),
        );

        let discovery = backend(&azure.url(), r#"{"kind":"managed_identity"}"#, 39);
        let peers = runtime()
            .block_on(discovery.discover_participants())
            .expect("query succeeds");
        let guids: Vec<u8> = peers.iter().map(|peer| peer.guid[0]).collect();
        assert_eq!(guids, vec![1], "peers: {:?}", guids);
    }

    /// A row replayed across pages is one peer, not two: the count is
    /// what `cloud_discovery_status().registry_peers` reports.
    #[test]
    fn a_row_replayed_by_the_service_is_counted_once() {
        let azure = FakeAzure::start().expect("fake");
        azure.create_table(TABLE);
        let now = now();
        for guid in [1u8, 2] {
            azure.put_entity(
                "domain-39",
                &to_hex(&[guid; 16]),
                &peer_row(guid, 39, 7400 + u32::from(guid), now, 60),
            );
        }
        azure.set_duplicate_rows(true);

        let discovery = backend(&azure.url(), r#"{"kind":"managed_identity"}"#, 39);
        let peers = runtime()
            .block_on(discovery.discover_participants())
            .expect("query succeeds");
        assert_eq!(peers.len(), 2, "a replayed row was counted twice");
    }

    /// `new()` and `from_config()` must enforce the SAME namespace rule:
    /// the namespace becomes a PartitionKey, which is an OData string
    /// literal and a URL path segment.
    #[test]
    fn a_directly_constructed_backend_validates_its_namespace() {
        assert!(AzureDiscovery::new("fleet-a").is_ok());
        assert!(AzureDiscovery::new("").is_ok(), "no prefix is legal");
        let Err(Error::Config(message)) = AzureDiscovery::new("fleet' or '1'='1") else {
            panic!("an unquotable namespace was accepted");
        };
        assert!(message.contains("namespace"), "{}", message);
    }

    /// `{:?}` of a backend must not print a secret: the Service Bus
    /// connection string carries a `SharedAccessKey`.
    #[test]
    fn debug_never_renders_the_service_bus_connection_string() {
        #[allow(deprecated)]
        let discovery = AzureDiscovery::new("fleet")
            .expect("construct")
            .with_table_storage("hddsacct", "mytable")
            .with_service_bus(
                "Endpoint=sb://x.servicebus.windows.net/;SharedAccessKey=SUPERSECRET",
            );
        let rendered = format!("{:?}", discovery);
        assert!(
            !rendered.contains("SUPERSECRET"),
            "the connection string leaked: {}",
            rendered
        );
        assert!(rendered.contains("hddsacct"), "{}", rendered);
    }

    #[test]
    fn locators_round_trip_through_the_row_encoding() {
        let locators = vec![Locator {
            kind: 1,
            port: 7400,
            address: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 172, 16, 0, 1],
        }];
        let parsed = parse_locators(&serialize_locators(&locators));
        assert_eq!(parsed, locators);
        assert!(parse_locators("not json").is_empty());
    }
}
