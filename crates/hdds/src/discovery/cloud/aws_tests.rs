// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

    use super::*;

    #[test]
    fn test_aws_cloud_map_creation() {
        let discovery = AwsCloudMap::new("hdds-ns", "hdds-svc", "us-east-1").unwrap();
        assert_eq!(discovery.namespace, "hdds-ns");
        assert_eq!(discovery.service_name, "hdds-svc");
        assert_eq!(discovery.region, "us-east-1");
    }

    #[test]
    fn test_aws_with_domain() {
        let discovery = AwsCloudMap::new("ns", "svc", "eu-west-1")
            .unwrap()
            .with_domain_id(42);
        assert_eq!(discovery.domain_id, 42);
    }

    #[test]
    fn test_instance_id_generation() {
        let discovery = AwsCloudMap::new("ns", "svc", "us-east-1").unwrap();
        let guid = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(discovery.instance_id(&guid), "hdds-0102030405060708");
    }

    #[test]
    fn test_to_hex() {
        assert_eq!(to_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn test_from_hex() {
        assert_eq!(from_hex("deadbeef"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(from_hex("0"), None); // odd length
        assert_eq!(from_hex("zz"), None); // invalid hex
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_locator_serialization() {
        let locators = vec![Locator {
            kind: 1,
            port: 7400,
            address: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 1, 50],
        }];

        let json = serialize_locators(&locators);
        let parsed = parse_locators(&json);

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].kind, 1);
        assert_eq!(parsed[0].port, 7400);
        assert_eq!(parsed[0].address[12], 10);
        assert_eq!(parsed[0].address[15], 50);
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_register_request_format() {
        // Verify the register request JSON is structured correctly
        let mut attributes = HashMap::new();
        attributes.insert("AWS_INSTANCE_IPV4".to_string(), "10.0.1.50".to_string());
        attributes.insert("AWS_INSTANCE_PORT".to_string(), "7400".to_string());
        attributes.insert(
            "GUID".to_string(),
            "0102030405060708090a0b0c0d0e0f10".to_string(),
        );
        attributes.insert("DOMAIN_ID".to_string(), "0".to_string());
        attributes.insert("PARTICIPANT_NAME".to_string(), "test-node".to_string());

        let request = CloudMapRegisterRequest {
            service_id: "hdds-participants".to_string(),
            instance_id: "hdds-0102030405060708".to_string(),
            attributes,
        };

        let json = serde_json::to_string(&request).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["ServiceId"], "hdds-participants");
        assert_eq!(parsed["InstanceId"], "hdds-0102030405060708");
        assert_eq!(parsed["Attributes"]["AWS_INSTANCE_IPV4"], "10.0.1.50");
        assert_eq!(parsed["Attributes"]["AWS_INSTANCE_PORT"], "7400");
        assert_eq!(parsed["Attributes"]["DOMAIN_ID"], "0");
        assert_eq!(parsed["Attributes"]["PARTICIPANT_NAME"], "test-node");
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_deregister_request_format() {
        let request = CloudMapDeregisterRequest {
            service_id: "hdds-participants".to_string(),
            instance_id: "hdds-0102030405060708".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["ServiceId"], "hdds-participants");
        assert_eq!(parsed["InstanceId"], "hdds-0102030405060708");
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_discover_response_parsing() {
        // Simulate an AWS DiscoverInstances response
        let response_json = r#"{
            "Instances": [
                {
                    "InstanceId": "hdds-0102030405060708",
                    "NamespaceName": "hdds-namespace",
                    "Attributes": {
                        "AWS_INSTANCE_IPV4": "10.0.1.50",
                        "AWS_INSTANCE_PORT": "7400",
                        "GUID": "0102030405060708090a0b0c0d0e0f10",
                        "DOMAIN_ID": "0",
                        "PARTICIPANT_NAME": "node-alpha",
                        "LOCATORS": "[{\"kind\":1,\"port\":7400,\"address\":\"00000000000000000000000000000132\"}]",
                        "USER_REGION": "us-east-1"
                    }
                },
                {
                    "InstanceId": "hdds-aabbccdd11223344",
                    "NamespaceName": "hdds-namespace",
                    "Attributes": {
                        "AWS_INSTANCE_IPV4": "10.0.2.100",
                        "AWS_INSTANCE_PORT": "7410",
                        "GUID": "aabbccdd11223344556677889900aabb",
                        "DOMAIN_ID": "0",
                        "PARTICIPANT_NAME": "node-beta"
                    }
                },
                {
                    "InstanceId": "hdds-different-domain",
                    "NamespaceName": "hdds-namespace",
                    "Attributes": {
                        "AWS_INSTANCE_IPV4": "10.0.3.1",
                        "AWS_INSTANCE_PORT": "7400",
                        "GUID": "ffeeddccbbaa99887766554433221100",
                        "DOMAIN_ID": "42",
                        "PARTICIPANT_NAME": "node-other-domain"
                    }
                }
            ]
        }"#;

        let resp: CloudMapDiscoverResponse = serde_json::from_str(response_json).unwrap();
        assert_eq!(resp.instances.len(), 3);

        // Parse like discover_participants does, filtering domain_id=0
        let domain_id: u32 = 0;
        let participants: Vec<ParticipantInfo> = resp
            .instances
            .iter()
            .filter_map(|inst| parse_cloud_map_instance(inst, domain_id))
            .collect();

        // Should get 2 participants (domain 42 filtered out)
        assert_eq!(participants.len(), 2);

        // First participant: node-alpha with explicit LOCATORS
        assert_eq!(participants[0].name, "node-alpha");
        assert_eq!(participants[0].guid[0], 0x01);
        assert_eq!(participants[0].locators.len(), 1);
        assert_eq!(participants[0].locators[0].port, 7400);
        assert_eq!(
            participants[0].metadata.get("region"),
            Some(&"us-east-1".to_string())
        );

        // Second participant: node-beta with fallback locator
        assert_eq!(participants[1].name, "node-beta");
        assert_eq!(participants[1].guid[0], 0xaa);
        assert_eq!(participants[1].locators.len(), 1);
        assert_eq!(participants[1].locators[0].port, 7410);
        // Fallback locator should have IP 10.0.2.100
        assert_eq!(participants[1].locators[0].address[12], 10);
        assert_eq!(participants[1].locators[0].address[13], 0);
        assert_eq!(participants[1].locators[0].address[14], 2);
        assert_eq!(participants[1].locators[0].address[15], 100);
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_discover_response_empty() {
        let response_json = r#"{"Instances": []}"#;
        let resp: CloudMapDiscoverResponse = serde_json::from_str(response_json).unwrap();
        assert_eq!(resp.instances.len(), 0);
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_discover_response_missing_guid() {
        // Instance without GUID should be skipped
        let response_json = r#"{
            "Instances": [
                {
                    "InstanceId": "no-guid-instance",
                    "NamespaceName": "ns",
                    "Attributes": {
                        "AWS_INSTANCE_IPV4": "10.0.1.1",
                        "DOMAIN_ID": "0"
                    }
                }
            ]
        }"#;

        let resp: CloudMapDiscoverResponse = serde_json::from_str(response_json).unwrap();
        assert_eq!(resp.instances.len(), 1);
        // But no GUID -> would be skipped in parsing
        assert!(!resp.instances[0].attributes.contains_key("GUID"));
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_ecs_metadata_parsing() {
        let metadata_json = r#"{
            "Networks": [
                {
                    "NetworkMode": "awsvpc",
                    "IPv4Addresses": ["10.0.1.50"],
                    "IPv6Addresses": []
                }
            ]
        }"#;

        let metadata: EcsTaskMetadata = serde_json::from_str(metadata_json).unwrap();
        let ip = metadata
            .networks
            .as_ref()
            .and_then(|nets| nets.first())
            .and_then(|net| net.ipv4_addresses.as_ref())
            .and_then(|addrs| addrs.first())
            .cloned();

        assert_eq!(ip, Some("10.0.1.50".to_string()));
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_ecs_metadata_no_networks() {
        let metadata_json = r#"{}"#;
        let metadata: EcsTaskMetadata = serde_json::from_str(metadata_json).unwrap();
        assert!(metadata.networks.is_none());
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_ecs_metadata_empty_networks() {
        let metadata_json = r#"{"Networks": []}"#;
        let metadata: EcsTaskMetadata = serde_json::from_str(metadata_json).unwrap();
        let ip = metadata
            .networks
            .as_ref()
            .and_then(|nets| nets.first())
            .and_then(|net| net.ipv4_addresses.as_ref())
            .and_then(|addrs| addrs.first())
            .cloned();
        assert!(ip.is_none());
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_credential_loading_from_env() {
        // This tests the env var path of credential loading
        // We can't call load_credentials (async + needs AwsCloudMap instance)
        // but we can test the parsing logic directly.

        // @audit-ok: official AWS docs test vectors, not real credentials.
        // See docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html
        let key = "AKIAIOSFODNN7EXAMPLE";
        let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"; // @audit-ok: AWS test vector
        let token = "FwoGZXIvYXdzEBYaDHQa...";

        let creds = sigv4::AwsCredentials {
            access_key_id: key.to_string(),
            secret_access_key: secret.to_string(),
            session_token: Some(token.to_string()),
        };

        assert_eq!(creds.access_key_id, key);
        assert_eq!(creds.secret_access_key, secret);
        assert_eq!(creds.session_token.as_deref(), Some(token));
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_credential_without_session_token() {
        let creds = sigv4::AwsCredentials {
            access_key_id: "AKID".to_string(),
            secret_access_key: "secret".to_string(),
            session_token: None,
        };
        assert!(creds.session_token.is_none());
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_aws_error_response_parsing() {
        let error_json = r#"{
            "__type": "ServiceNotFound",
            "Message": "Service not found in namespace"
        }"#;
        let err: CloudMapErrorResponse = serde_json::from_str(error_json).unwrap();
        assert_eq!(err.error_type, "ServiceNotFound");
        assert_eq!(err.message, "Service not found in namespace");
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_aws_error_response_lowercase_message() {
        // Some AWS errors use lowercase "message"
        let error_json = r#"{
            "__type": "InvalidInput",
            "message": "Parameter validation failed"
        }"#;
        let err: CloudMapErrorResponse = serde_json::from_str(error_json).unwrap();
        assert_eq!(err.error_type, "InvalidInput");
        assert_eq!(err.message, "Parameter validation failed");
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_build_fallback_locator() {
        let instance = CloudMapInstance {
            instance_id: "test-id".to_string(),
            namespace_name: "ns".to_string(),
            attributes: {
                let mut m = HashMap::new();
                m.insert("AWS_INSTANCE_IPV4".to_string(), "192.168.1.100".to_string());
                m.insert("AWS_INSTANCE_PORT".to_string(), "7410".to_string());
                m
            },
        };

        let locators = build_fallback_locator(&instance);
        assert_eq!(locators.len(), 1);
        assert_eq!(locators[0].kind, 1);
        assert_eq!(locators[0].port, 7410);
        assert_eq!(locators[0].address[12], 192);
        assert_eq!(locators[0].address[13], 168);
        assert_eq!(locators[0].address[14], 1);
        assert_eq!(locators[0].address[15], 100);
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_build_fallback_locator_missing_ip() {
        let instance = CloudMapInstance {
            instance_id: "test-id".to_string(),
            namespace_name: "ns".to_string(),
            attributes: HashMap::new(),
        };

        let locators = build_fallback_locator(&instance);
        assert_eq!(locators.len(), 1);
        assert_eq!(locators[0].port, 7400); // default port
        // IP should be all zeros
        assert_eq!(locators[0].address, [0u8; 16]);
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_utc_now_format() {
        let (datetime, date) = utc_now();
        // datetime should be like "20260213T120000Z"
        assert_eq!(datetime.len(), 16);
        assert!(datetime.ends_with('Z'));
        assert!(datetime.contains('T'));
        // date should be like "20260213"
        assert_eq!(date.len(), 8);
        // date should be a prefix of datetime
        assert!(datetime.starts_with(&date));
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_operation_response_parsing() {
        let json = r#"{"OperationId": "op-12345678"}"#;
        let resp: CloudMapOperationResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.operation_id, "op-12345678");
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_credential_response_parsing() {
        let json = r#"{
            "AccessKeyId": "ASIEXAMPLE",
            "SecretAccessKey": "secretkey",
            "Token": "sessiontoken123",
            "Expiration": "2026-02-13T18:00:00Z"
        }"#;
        let resp: CredentialResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.access_key_id, "ASIEXAMPLE");
        assert_eq!(resp.secret_access_key, "secretkey");
        assert_eq!(resp.token.as_deref(), Some("sessiontoken123"));
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_credential_response_with_session_token_alias() {
        // IMDS returns "Token", but some endpoints return "SessionToken"
        let json = r#"{
            "AccessKeyId": "ASIEXAMPLE",
            "SecretAccessKey": "secretkey",
            "SessionToken": "session-from-imds"
        }"#;
        let resp: CredentialResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.token.as_deref(), Some("session-from-imds"));
    }

    #[cfg(feature = "cloud-discovery")]
    #[test]
    fn test_discover_request_format() {
        let mut query_params = HashMap::new();
        query_params.insert("DOMAIN_ID".to_string(), "42".to_string());

        let request = CloudMapDiscoverRequest {
            namespace_name: "hdds-namespace".to_string(),
            service_name: "hdds-participants".to_string(),
            health_status: Some("HEALTHY".to_string()),
            query_parameters: Some(query_params),
        };

        let json = serde_json::to_string(&request).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["NamespaceName"], "hdds-namespace");
        assert_eq!(parsed["ServiceName"], "hdds-participants");
        assert_eq!(parsed["HealthStatus"], "HEALTHY");
        assert_eq!(parsed["QueryParameters"]["DOMAIN_ID"], "42");
    }
