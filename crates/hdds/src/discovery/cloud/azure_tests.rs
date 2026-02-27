// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

    use super::*;

    // ========================================================================
    // Basic construction tests
    // ========================================================================

    #[test]
    fn test_azure_discovery_creation() {
        let discovery = AzureDiscovery::new("hdds.private.azure.local").unwrap();
        assert_eq!(discovery.dns_zone, "hdds.private.azure.local");
    }

    #[test]
    fn test_azure_with_options() {
        let discovery = AzureDiscovery::new("hdds.azure.local")
            .unwrap()
            .with_domain_id(5)
            .with_table_storage("myaccount", "participants")
            .with_service_bus("Endpoint=sb://...");

        assert_eq!(discovery.domain_id, 5);
        assert_eq!(discovery.storage_account.unwrap(), "myaccount");
        assert_eq!(discovery.table_name.unwrap(), "participants");
        assert!(discovery.service_bus_conn.is_some());
    }

    #[test]
    fn test_azure_with_shared_key() {
        let discovery = AzureDiscovery::new("test.local")
            .unwrap()
            .with_table_storage("myaccount", "mytable")
            .with_storage_key("dGVzdGtleQ==");

        match &discovery.auth_mode {
            AzureAuthMode::SharedKey(k) => assert_eq!(k, "dGVzdGtleQ=="),
            _ => panic!("Expected SharedKey auth mode"),
        }
    }

    #[test]
    fn test_azure_with_sas_token() {
        let sas = "sv=2021-06-08&ss=t&srt=sco&sp=rwdlacu&se=2026-01-01";
        let discovery = AzureDiscovery::new("test.local")
            .unwrap()
            .with_table_storage("myaccount", "mytable")
            .with_sas_token(sas);

        match &discovery.auth_mode {
            AzureAuthMode::SasToken(s) => assert_eq!(s, sas),
            _ => panic!("Expected SasToken auth mode"),
        }
    }

    #[test]
    fn test_azure_with_managed_identity() {
        let discovery = AzureDiscovery::new("test.local")
            .unwrap()
            .with_managed_identity();

        matches!(&discovery.auth_mode, AzureAuthMode::ManagedIdentity);
    }

    // ========================================================================
    // Entity ID generation
    // ========================================================================

    #[test]
    fn test_entity_id_generation() {
        let discovery = AzureDiscovery::new("test.local").unwrap();
        let guid = [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(discovery.entity_id(&guid), "hdds-aabbccddeeff0011");
    }

    #[test]
    fn test_entity_id_all_zeros() {
        let discovery = AzureDiscovery::new("test.local").unwrap();
        let guid = [0u8; 16];
        assert_eq!(discovery.entity_id(&guid), "hdds-0000000000000000");
    }

    #[test]
    fn test_entity_id_all_ff() {
        let discovery = AzureDiscovery::new("test.local").unwrap();
        let guid = [0xff; 16];
        assert_eq!(discovery.entity_id(&guid), "hdds-ffffffffffffffff");
    }

    // ========================================================================
    // Hex encode/decode
    // ========================================================================

    #[test]
    fn test_to_hex() {
        assert_eq!(to_hex(&[0xca, 0xfe, 0xba, 0xbe]), "cafebabe");
    }

    #[test]
    fn test_to_hex_empty() {
        assert_eq!(to_hex(&[]), "");
    }

    #[test]
    fn test_to_hex_single_byte() {
        assert_eq!(to_hex(&[0x00]), "00");
        assert_eq!(to_hex(&[0xff]), "ff");
        assert_eq!(to_hex(&[0x0a]), "0a");
    }

    #[test]
    fn test_from_hex() {
        assert_eq!(from_hex("cafebabe"), Some(vec![0xca, 0xfe, 0xba, 0xbe]));
    }

    #[test]
    fn test_from_hex_empty() {
        assert_eq!(from_hex(""), Some(vec![]));
    }

    #[test]
    fn test_from_hex_odd_length() {
        assert_eq!(from_hex("abc"), None);
    }

    #[test]
    fn test_from_hex_invalid_chars() {
        assert_eq!(from_hex("zzzz"), None);
    }

    #[test]
    fn test_hex_roundtrip() {
        let original = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let hex = to_hex(&original);
        let decoded = from_hex(&hex).unwrap();
        assert_eq!(original, decoded);
    }

    // ========================================================================
    // Base64 encode/decode
    // ========================================================================

    #[test]
    fn test_base64_encode_empty() {
        assert_eq!(base64_impl::encode(&[]), "");
    }

    #[test]
    fn test_base64_encode_basic() {
        assert_eq!(base64_impl::encode(b"Hello"), "SGVsbG8=");
        assert_eq!(base64_impl::encode(b"He"), "SGU=");
        assert_eq!(base64_impl::encode(b"Hel"), "SGVs");
    }

    #[test]
    fn test_base64_decode_basic() {
        assert_eq!(base64_impl::decode("SGVsbG8="), Some(b"Hello".to_vec()));
        assert_eq!(base64_impl::decode("SGU="), Some(b"He".to_vec()));
        assert_eq!(base64_impl::decode("SGVs"), Some(b"Hel".to_vec()));
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let encoded = base64_impl::encode(data);
        let decoded = base64_impl::decode(&encoded).unwrap();
        assert_eq!(data.to_vec(), decoded);
    }

    #[test]
    fn test_base64_decode_invalid_length() {
        assert_eq!(base64_impl::decode("abc"), None);
    }

    // ========================================================================
    // SHA-256
    // ========================================================================

    #[test]
    fn test_sha256_empty() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = sha256::digest(b"");
        assert_eq!(
            to_hex(&hash),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_hello() {
        // SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        let hash = sha256::digest(b"hello");
        assert_eq!(
            to_hex(&hash),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_sha256_abc() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let hash = sha256::digest(b"abc");
        assert_eq!(
            to_hex(&hash),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    // ========================================================================
    // HMAC-SHA256
    // ========================================================================

    #[test]
    fn test_hmac_sha256_rfc4231_test1() {
        // RFC 4231 Test Case 1
        let key = [0x0b; 20];
        let data = b"Hi There";
        let mac = sha256::hmac_sha256(&key, data);
        assert_eq!(
            to_hex(&mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn test_hmac_sha256_rfc4231_test2() {
        // RFC 4231 Test Case 2
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let mac = sha256::hmac_sha256(key, data);
        assert_eq!(
            to_hex(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn test_hmac_sha256_rfc4231_test3() {
        // RFC 4231 Test Case 3
        let key = [0xaa; 20];
        let data = [0xdd; 50];
        let mac = sha256::hmac_sha256(&key, &data);
        assert_eq!(
            to_hex(&mac),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
    }

    // ========================================================================
    // Table Storage URL construction
    // ========================================================================

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_table_storage_url() {
        let discovery = AzureDiscovery::new("test.local")
            .unwrap()
            .with_table_storage("myaccount", "mytable");

        assert_eq!(
            discovery.table_storage_url("mytable"),
            Some("https://myaccount.table.core.windows.net/mytable".to_string())
        );
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_entity_url() {
        let discovery = AzureDiscovery::new("test.local")
            .unwrap()
            .with_table_storage("myaccount", "mytable");

        let url = discovery
            .entity_url("mytable", "domain-0", "aabbccdd00112233")
            .unwrap();
        assert_eq!(
            url,
            "https://myaccount.table.core.windows.net/mytable(PartitionKey='domain-0',RowKey='aabbccdd00112233')"
        );
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_canonicalized_resource() {
        let url = "https://myaccount.table.core.windows.net/mytable(PartitionKey='domain-0',RowKey='abc')";
        let resource = AzureDiscovery::canonicalized_resource(url);
        assert_eq!(resource, "/mytable(PartitionKey='domain-0',RowKey='abc')");
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_canonicalized_resource_with_query() {
        let url = "https://myaccount.table.core.windows.net/mytable()?$filter=PartitionKey%20eq%20'domain-0'";
        let resource = AzureDiscovery::canonicalized_resource(url);
        assert_eq!(resource, "/mytable()");
    }

    // ========================================================================
    // Shared Key auth header generation
    // ========================================================================

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_shared_key_auth_header_format() {
        // Use a known key (base64 of "testkey1234567890")
        let key_b64 = base64_impl::encode(b"testkey1234567890");
        let date = "Mon, 13 Jan 2026 12:00:00 GMT";
        let resource = "/mytable(PartitionKey='domain-0',RowKey='abc')";

        let header =
            AzureDiscovery::shared_key_auth_header("myaccount", &key_b64, date, resource)
                .unwrap();

        // Verify format: "SharedKeyLite myaccount:{base64_signature}"
        assert!(header.starts_with("SharedKeyLite myaccount:"));
        let sig_b64 = header.strip_prefix("SharedKeyLite myaccount:").unwrap();
        // Verify signature is valid base64
        assert!(base64_impl::decode(sig_b64).is_some());
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_shared_key_auth_deterministic() {
        let key_b64 = base64_impl::encode(b"deterministic-key");
        let date = "Thu, 01 Jan 2026 00:00:00 GMT";
        let resource = "/mytable";

        let h1 =
            AzureDiscovery::shared_key_auth_header("acct", &key_b64, date, resource).unwrap();
        let h2 =
            AzureDiscovery::shared_key_auth_header("acct", &key_b64, date, resource).unwrap();

        assert_eq!(h1, h2);
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_shared_key_auth_invalid_base64() {
        let result =
            AzureDiscovery::shared_key_auth_header("acct", "not-valid-base64!", "date", "/res");
        assert!(result.is_err());
    }

    // ========================================================================
    // Partition key generation
    // ========================================================================

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_partition_key() {
        assert_eq!(AzureDiscovery::partition_key(0), "domain-0");
        assert_eq!(AzureDiscovery::partition_key(42), "domain-42");
        assert_eq!(AzureDiscovery::partition_key(232), "domain-232");
    }

    // ========================================================================
    // Locator serialization roundtrip
    // ========================================================================

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_locator_roundtrip() {
        let locators = vec![Locator {
            kind: 1,
            port: 7400,
            address: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 172, 16, 0, 1],
        }];

        let json = serialize_locators(&locators);
        let parsed = parse_locators(&json);

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].port, 7400);
        assert_eq!(parsed[0].address[12..16], [172, 16, 0, 1]);
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_locator_roundtrip_multiple() {
        let locators = vec![
            Locator {
                kind: 1,
                port: 7400,
                address: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 1, 50],
            },
            Locator {
                kind: 2,
                port: 7401,
                address: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1],
            },
        ];

        let json = serialize_locators(&locators);
        let parsed = parse_locators(&json);

        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].kind, 1);
        assert_eq!(parsed[0].port, 7400);
        assert_eq!(parsed[1].kind, 2);
        assert_eq!(parsed[1].port, 7401);
        assert_eq!(parsed[1].address[12..16], [192, 168, 1, 1]);
    }

    // ========================================================================
    // IMDS response parsing
    // ========================================================================

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_imds_response_parsing() {
        let json = r#"{
            "network": {
                "interface": [{
                    "ipv4": {
                        "ipAddress": [{
                            "privateIpAddress": "10.0.0.4",
                            "publicIpAddress": "52.174.7.154"
                        }]
                    }
                }]
            }
        }"#;

        let resp: AzureImdsResponse = serde_json::from_str(json).unwrap();
        let ip = resp
            .network
            .unwrap()
            .interface
            .unwrap()
            .first()
            .unwrap()
            .ipv4
            .as_ref()
            .unwrap()
            .ip_address
            .as_ref()
            .unwrap()
            .first()
            .unwrap()
            .private_ip_address
            .clone()
            .unwrap();

        assert_eq!(ip, "10.0.0.4");
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_imds_response_empty_network() {
        let json = r#"{"network": null}"#;
        let resp: AzureImdsResponse = serde_json::from_str(json).unwrap();
        assert!(resp.network.is_none());
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_imds_response_no_interfaces() {
        let json = r#"{"network": {"interface": []}}"#;
        let resp: AzureImdsResponse = serde_json::from_str(json).unwrap();
        assert!(resp.network.unwrap().interface.unwrap().is_empty());
    }

    // ========================================================================
    // OData response parsing (discover)
    // ========================================================================

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_odata_response_parsing() {
        let json = r#"{
            "value": [
                {
                    "PartitionKey": "domain-0",
                    "RowKey": "0102030405060708090a0b0c0d0e0f10",
                    "Guid": "0102030405060708090a0b0c0d0e0f10",
                    "Name": "participant-1",
                    "DomainId": 0,
                    "Locators": "[{\"kind\":1,\"port\":7400,\"address\":\"000000000000000000000000ac100001\"}]",
                    "Metadata": "{\"region\":\"eastus\"}",
                    "LastUpdated": "1700000000Z"
                }
            ]
        }"#;

        let odata: ODataQueryResponse = serde_json::from_str(json).unwrap();
        assert_eq!(odata.value.len(), 1);

        let entity = &odata.value[0];
        assert_eq!(entity.partition_key, "domain-0");
        assert_eq!(entity.name, "participant-1");
        assert_eq!(entity.domain_id, 0);

        // Parse GUID
        let guid_bytes = from_hex(&entity.guid).unwrap();
        assert_eq!(guid_bytes.len(), 16);
        assert_eq!(guid_bytes[0], 0x01);
        assert_eq!(guid_bytes[15], 0x10);

        // Parse locators
        let locators = parse_locators(&entity.locators);
        assert_eq!(locators.len(), 1);
        assert_eq!(locators[0].kind, 1);
        assert_eq!(locators[0].port, 7400);
        assert_eq!(locators[0].address[12..16], [172, 16, 0, 1]);

        // Parse metadata
        let metadata: std::collections::HashMap<String, String> =
            serde_json::from_str(&entity.metadata).unwrap();
        assert_eq!(metadata.get("region").unwrap(), "eastus");
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_odata_response_empty() {
        let json = r#"{"value": []}"#;
        let odata: ODataQueryResponse = serde_json::from_str(json).unwrap();
        assert!(odata.value.is_empty());
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_odata_response_multiple_entities() {
        let json = r#"{
            "value": [
                {
                    "PartitionKey": "domain-5",
                    "RowKey": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",
                    "Guid": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",
                    "Name": "node-alpha",
                    "DomainId": 5,
                    "Locators": "[]",
                    "Metadata": "{}",
                    "LastUpdated": "1700000000Z"
                },
                {
                    "PartitionKey": "domain-5",
                    "RowKey": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "Guid": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "Name": "node-beta",
                    "DomainId": 5,
                    "Locators": "[{\"kind\":1,\"port\":8000,\"address\":\"00000000000000000000000000000001\"}]",
                    "Metadata": "{\"zone\":\"1\"}",
                    "LastUpdated": "1700000001Z"
                }
            ]
        }"#;

        let odata: ODataQueryResponse = serde_json::from_str(json).unwrap();
        assert_eq!(odata.value.len(), 2);
        assert_eq!(odata.value[0].name, "node-alpha");
        assert_eq!(odata.value[1].name, "node-beta");
        assert_eq!(odata.value[1].domain_id, 5);
    }

    // ========================================================================
    // TableStorageEntity serialization
    // ========================================================================

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_table_storage_entity_serialization() {
        let entity = TableStorageEntity {
            partition_key: "domain-0".to_string(),
            row_key: "0102030405060708090a0b0c0d0e0f10".to_string(),
            guid: "0102030405060708090a0b0c0d0e0f10".to_string(),
            name: "test-participant".to_string(),
            domain_id: 0,
            locators: "[{\"kind\":1,\"port\":7400,\"address\":\"000000000000000000000000ac100001\"}]"
                .to_string(),
            metadata: "{}".to_string(),
            last_updated: "1700000000Z".to_string(),
        };

        let json = serde_json::to_string(&entity).unwrap();

        // Verify the JSON contains expected field names (OData format)
        assert!(json.contains("\"PartitionKey\""));
        assert!(json.contains("\"RowKey\""));
        assert!(json.contains("\"Guid\""));
        assert!(json.contains("\"Name\""));
        assert!(json.contains("\"DomainId\""));
        assert!(json.contains("\"Locators\""));
        assert!(json.contains("\"Metadata\""));
        assert!(json.contains("\"LastUpdated\""));
        assert!(json.contains("domain-0"));
        assert!(json.contains("test-participant"));

        // Verify round-trip
        let parsed: TableStorageEntity = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.partition_key, "domain-0");
        assert_eq!(parsed.name, "test-participant");
        assert_eq!(parsed.domain_id, 0);
    }

    // ========================================================================
    // Register request body format
    // ========================================================================

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_register_request_body_format() {
        // Simulate what register_participant builds
        let guid = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        ];
        let locators = vec![Locator {
            kind: 1,
            port: 7400,
            address: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 1, 50],
        }];

        let partition_key = AzureDiscovery::partition_key(42);
        let row_key = to_hex(&guid);

        let mut metadata = HashMap::new();
        metadata.insert("region".to_string(), "eastus".to_string());

        let entity = TableStorageEntity {
            partition_key: partition_key.clone(),
            row_key: row_key.clone(),
            guid: to_hex(&guid),
            name: "my-participant".to_string(),
            domain_id: 42,
            locators: serialize_locators(&locators),
            metadata: serde_json::to_string(&metadata).unwrap(),
            last_updated: "1700000000Z".to_string(),
        };

        let body = serde_json::to_string(&entity).unwrap();

        // Verify key fields
        assert!(body.contains("\"PartitionKey\":\"domain-42\""));
        assert!(body.contains(&format!("\"RowKey\":\"{}\"", row_key)));
        assert!(body.contains("\"DomainId\":42"));
        assert!(body.contains("\"Name\":\"my-participant\""));
        // Verify locators are embedded as JSON string
        assert!(body.contains("Locators"));
    }

    // ========================================================================
    // Register/Deregister URL format
    // ========================================================================

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_register_url_format() {
        let discovery = AzureDiscovery::new("test.local")
            .unwrap()
            .with_domain_id(0)
            .with_table_storage("hddsaccount", "participants");

        let guid = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        ];

        let pk = AzureDiscovery::partition_key(0);
        let rk = to_hex(&guid);
        let url = discovery.entity_url("participants", &pk, &rk).unwrap();

        assert_eq!(
            url,
            format!(
                "https://hddsaccount.table.core.windows.net/participants(PartitionKey='domain-0',RowKey='{}')",
                rk
            )
        );
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_deregister_url_format() {
        let discovery = AzureDiscovery::new("test.local")
            .unwrap()
            .with_domain_id(7)
            .with_table_storage("myacct", "tbl");

        let guid = [0xaa; 16];
        let pk = AzureDiscovery::partition_key(7);
        let rk = to_hex(&guid);
        let url = discovery.entity_url("tbl", &pk, &rk).unwrap();

        assert!(url.starts_with("https://myacct.table.core.windows.net/tbl("));
        assert!(url.contains("PartitionKey='domain-7'"));
        assert!(url.contains(&format!("RowKey='{}'", to_hex(&guid))));
    }

    // ========================================================================
    // Discover query URL format
    // ========================================================================

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_discover_query_url_format() {
        let discovery = AzureDiscovery::new("test.local")
            .unwrap()
            .with_domain_id(3)
            .with_table_storage("acct", "mytable");

        let base_url = discovery.table_storage_url("mytable").unwrap();
        let pk = AzureDiscovery::partition_key(3);
        let filter = format!("PartitionKey eq '{}'", pk);
        let query_url = format!(
            "{}()?$filter={}",
            base_url,
            filter.replace(' ', "%20").replace('\'', "%27")
        );

        assert!(query_url.starts_with("https://acct.table.core.windows.net/mytable()"));
        assert!(query_url.contains("$filter="));
        assert!(query_url.contains("domain-3"));
    }

    // ========================================================================
    // IMDS token response parsing
    // ========================================================================

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_imds_token_response_parsing() {
        let json = r#"{
            "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.test",
            "expires_on": "1700000000",
            "token_type": "Bearer",
            "resource": "https://storage.azure.com/"
        }"#;

        let resp: ImdsTokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.access_token, "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.test");
        assert_eq!(resp.expires_on, "1700000000");
    }

    // ========================================================================
    // http_date_now format check
    // ========================================================================

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_http_date_format() {
        let date = http_date_now();
        // Should match "Day, DD Mon YYYY HH:MM:SS GMT"
        assert!(date.ends_with(" GMT"), "Date should end with GMT: {}", date);
        // Should have comma after day name
        assert!(date.contains(','), "Date should contain comma: {}", date);
        // Should be roughly the right length
        assert!(
            date.len() >= 28 && date.len() <= 31,
            "Date length unexpected: {} (len={})",
            date,
            date.len()
        );
    }

    // ========================================================================
    // parse_locators edge cases
    // ========================================================================

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_parse_locators_empty_json() {
        let locators = parse_locators("[]");
        assert!(locators.is_empty());
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_parse_locators_invalid_json() {
        let locators = parse_locators("not json");
        assert!(locators.is_empty());
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_parse_locators_wrong_address_length() {
        // Address hex is too short (only 4 bytes, not 16)
        let json = r#"[{"kind":1,"port":7400,"address":"aabbccdd"}]"#;
        let locators = parse_locators(json);
        assert!(locators.is_empty());
    }
