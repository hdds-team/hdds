// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The REST surface, driven through tower's oneshot: no socket, no port, no
//! runtime scheduling to wait on.

#![cfg(feature = "server")]

use std::sync::{Arc, RwLock};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use hdds_schema_registry::persistence::FilePersistence;
use hdds_schema_registry::registry::SchemaRegistry;
use hdds_schema_registry::server::SchemaRegistryApi;
use hdds_schema_registry::{router, ServerState};

fn api() -> SchemaRegistryApi {
    SchemaRegistryApi::new(Arc::new(RwLock::new(SchemaRegistry::new())))
}

async fn send(state: Arc<ServerState>, request: Request<Body>) -> (StatusCode, serde_json::Value) {
    let response = router(state).oneshot(request).await.expect("route");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, json)
}

fn post(path: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request")
}

fn get(path: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .body(Body::empty())
        .expect("request")
}

#[tokio::test]
async fn register_then_read_back_every_documented_route() {
    let state = Arc::new(ServerState::in_memory(api()));

    let (status, body) = send(
        state.clone(),
        post(
            "/schemas",
            serde_json::json!({
                "name": "Sensor",
                "content": "struct Sensor { long id; };",
                "format": "Idl4"
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["version"], 1);

    let (status, body) = send(
        state.clone(),
        post(
            "/schemas",
            serde_json::json!({
                "name": "Sensor",
                "content": "struct Sensor { long id; string name; };",
                "format": "Idl4"
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["version"], 2);

    let (status, body) = send(state.clone(), get("/schemas")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, serde_json::json!(["Sensor"]));

    let (status, body) = send(state.clone(), get("/schemas/Sensor")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["version"], 2);
    assert!(body["content"].as_str().expect("content").contains("name"));

    let (status, body) = send(state.clone(), get("/schemas/Sensor/versions")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, serde_json::json!([1, 2]));

    let (status, body) = send(state.clone(), get("/schemas/Sensor/versions/1")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["version"], 1);
    assert!(!body["content"].as_str().expect("content").contains("name"));

    let (status, body) = send(state.clone(), get("/health")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn unknown_schema_is_a_404_not_an_empty_200() {
    let state = Arc::new(ServerState::in_memory(api()));
    for path in [
        "/schemas/Ghost",
        "/schemas/Ghost/versions",
        "/schemas/Ghost/versions/3",
    ] {
        let (status, body) = send(state.clone(), get(path)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{}", path);
        assert!(body["error"].is_string(), "{}", path);
    }
}

#[tokio::test]
async fn empty_content_is_400_and_a_duplicate_is_409() {
    let state = Arc::new(ServerState::in_memory(api()));
    let (status, _) = send(
        state.clone(),
        post(
            "/schemas",
            serde_json::json!({"name": "S", "content": "", "format": "Idl4"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let payload =
        serde_json::json!({"name": "S", "content": "struct S { long x; };", "format": "Idl4"});
    let (status, _) = send(state.clone(), post("/schemas", payload.clone())).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, body) = send(state.clone(), post("/schemas", payload)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body["error"].as_str().expect("error").contains("already"));
}

#[tokio::test]
async fn compatibility_check_reports_the_verdict() {
    let state = Arc::new(ServerState::in_memory(api()));
    send(
        state.clone(),
        post(
            "/schemas",
            serde_json::json!({"name": "S", "content": "struct S { long x; };", "format": "Idl4"}),
        ),
    )
    .await;

    let (status, body) = send(
        state.clone(),
        post(
            "/schemas/S/compatibility",
            serde_json::json!({"content": "struct S { long x; string y; };"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["compatibility"], "BACKWARD");
    assert_eq!(body["compatible"], true);

    // Removing a field is forward compatible under this model, not breaking.
    let (status, body) = send(
        state.clone(),
        post(
            "/schemas/S/compatibility",
            serde_json::json!({"content": "struct S { };"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["compatibility"], "FORWARD");

    // Changing a field's type is.
    let (status, body) = send(
        state.clone(),
        post(
            "/schemas/S/compatibility",
            serde_json::json!({"content": "struct S { string x; };"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["compatibility"], "BREAKING");
    assert_eq!(body["compatible"], false);
}

#[tokio::test]
async fn a_registration_is_on_disk_before_it_is_acknowledged() {
    let dir = tempfile::tempdir().expect("tempdir");
    let persistence = FilePersistence::new(dir.path().to_path_buf()).expect("persistence");
    let state = Arc::new(ServerState::with_persistence(api(), persistence));

    let (status, _) = send(
        state.clone(),
        post(
            "/schemas",
            serde_json::json!({"name": "Sensor", "content": "struct Sensor { long id; };", "format": "Idl4"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // The 201 is only true if the bytes are already there.
    let file = dir.path().join("Sensor").join("v1.json");
    assert!(file.exists(), "{} was not written", file.display());

    // And a fresh registry started on that directory sees the schema.
    let reloaded = FilePersistence::new(dir.path().to_path_buf())
        .expect("persistence")
        .load()
        .expect("load");
    assert_eq!(reloaded.schema_count(), 1);
    assert_eq!(reloaded.get_latest("Sensor").expect("entry").version, 1);
}

/// "A persistence failure is a 500 with the version NOT reported as
/// registered" - the module documentation said it, and the code did the
/// opposite: it registered in memory first, so a 500 still left the schema on
/// every read route, and a retry of the identical body got 409.
#[tokio::test]
async fn a_persistence_failure_leaves_nothing_behind() {
    let dir = tempfile::tempdir().expect("tempdir");
    let persistence = FilePersistence::new(dir.path().to_path_buf()).expect("persistence");
    let state = Arc::new(ServerState::with_persistence(api(), persistence));

    // Make the directory unwritable, so save() cannot create the schema dir.
    let mut permissions = std::fs::metadata(dir.path())
        .expect("metadata")
        .permissions();
    let original = permissions.clone();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o500);
    std::fs::set_permissions(dir.path(), permissions).expect("chmod");

    let body = serde_json::json!({
        "name": "Doomed",
        "content": "struct Doomed { long id; };",
        "format": "Idl4",
    });
    let (status, json) = send(Arc::clone(&state), post("/schemas", body.clone())).await;
    std::fs::set_permissions(dir.path(), original).expect("restore chmod");
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{:?}", json);

    // Nothing is served, and the identical body is not a duplicate.
    let (status, _) = send(Arc::clone(&state), get("/schemas/Doomed")).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a schema the registry said it failed to record is being served"
    );
    let (status, _) = send(Arc::clone(&state), get("/schemas")).await;
    assert_eq!(status, StatusCode::OK);
    let (status, json) = send(Arc::clone(&state), post("/schemas", body)).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "the failed registration still consumed the content: {:?}",
        json
    );
    assert_eq!(json["version"], 1, "the version counter moved on a failure");
}
