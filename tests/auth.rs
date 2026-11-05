//! Authentication modes ("open" and "strict"), tested on the axum router
//! with `oneshot` requests.

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use serde_json::{Value, json};
use std::path::PathBuf;
use tokio::sync::mpsc;
use tower::ServiceExt;
use uuid::Uuid;

use bifrost::config::AppConfig;
use bifrost::routes;
use bifrost::server::appstate::AppState;
use svc::manager::ServiceManager;

const STANDARD_APPLICATION_ID: &str = "01010101-0202-0303-0404-050505050505";

struct TestApp {
    state: AppState,
    router: Router,
    workdir: PathBuf,
}

impl Drop for TestApp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.workdir);
    }
}

impl TestApp {
    async fn start(mode: &str) -> Self {
        let workdir = std::env::temp_dir().join(format!("bifrost-auth-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&workdir).unwrap();

        let config: AppConfig = serde_json::from_value(json!({
            "bridge": {
                "name": "Bifrost auth test",
                "mac": "11:22:33:44:55:66",
                "ipaddress": "127.0.0.1",
                "http_port": 0,
                "https_port": 0,
                "entm_port": 0,
                "entm_cookie_exchange": true,
                "netmask": "255.0.0.0",
                "gateway": "127.0.0.1",
                "timezone": "Etc/UTC"
            },
            "z2m": {},
            "bifrost": {
                "state_file": workdir.join("state.yaml"),
                "cert_file": workdir.join("cert.pem"),
                "auth_file": workdir.join("auth.yaml"),
            },
            "auth": { "mode": mode },
        }))
        .unwrap();

        let (svm, _future) = ServiceManager::spawn();
        let (behavior_tx, _behavior_rx) = mpsc::channel(16);
        let state = AppState::from_config(config, svm, behavior_tx)
            .await
            .unwrap();
        let router = routes::router(state.clone());

        Self {
            state,
            router,
            workdir,
        }
    }

    async fn request(
        &self,
        method: Method,
        uri: &str,
        key: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, axum::http::HeaderMap, Value) {
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(key) = key {
            req = req.header("hue-application-key", key);
        }
        let body = body.map_or_else(Body::empty, |body| Body::from(body.to_string()));
        let resp = self
            .router
            .clone()
            .oneshot(req.body(body).unwrap())
            .await
            .unwrap();

        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, headers, json)
    }

    /// POST /api, returns (username, clientkey) on success, or the v1 error type
    async fn pair(&self) -> Result<(String, String), u64> {
        self.pair_as("test#auth").await
    }

    async fn pair_as(&self, devicetype: &str) -> Result<(String, String), u64> {
        let (status, _, json) = self
            .request(
                Method::POST,
                "/api",
                None,
                Some(json!({"devicetype": devicetype, "generateclientkey": true})),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        if let Some(err) = json[0].get("error") {
            return Err(err["type"].as_u64().unwrap());
        }
        let success = &json[0]["success"];
        Ok((
            success["username"].as_str().unwrap().to_string(),
            success["clientkey"].as_str().unwrap().to_string(),
        ))
    }

    fn application_id(&self, username: &str) -> Uuid {
        self.state
            .auth()
            .find_by_username(username)
            .unwrap()
            .application_id
    }
}

#[tokio::test]
async fn open_mode_keeps_upstream_behavior() {
    let app = TestApp::start("open").await;

    let (username, clientkey) = app.pair().await.unwrap();
    assert_eq!(username, STANDARD_APPLICATION_ID);
    assert_eq!(clientkey, hex::encode_upper(b"BifrostHueTlsKey"));

    let (status, _, _) = app
        .request(Method::GET, "/clip/v2/resource/light", None, None)
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, headers, _) = app.request(Method::GET, "/auth/v1", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["hue-application-id"], STANDARD_APPLICATION_ID);

    let (status, _, json) = app
        .request(Method::GET, "/api/anyone/lights", None, None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json.get(0).and_then(|e| e.get("error")).is_none());

    assert!(!app.workdir.join("auth.yaml").exists());
}

#[tokio::test]
async fn strict_pairing_needs_the_link_button() {
    let app = TestApp::start("strict").await;

    assert_eq!(app.pair().await, Err(101));

    app.state.auth().press_link_button();
    let (username, clientkey) = app.pair().await.unwrap();
    assert_eq!(username.len(), 40);
    assert_ne!(username, STANDARD_APPLICATION_ID);
    assert_eq!(clientkey.len(), 32);
    assert_eq!(clientkey, clientkey.to_uppercase());

    // several apps may pair while the window is open
    let (other, _) = app.pair().await.unwrap();
    assert_ne!(username, other);
}

#[tokio::test]
async fn strict_pairing_window_expires() {
    let app = TestApp::start("strict").await;
    app.state
        .auth()
        .open_link_button_for(std::time::Duration::from_millis(50));
    assert!(app.pair().await.is_ok());
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(app.pair().await, Err(101));
}

#[tokio::test]
async fn strict_v1_requires_a_paired_user() {
    let app = TestApp::start("strict").await;
    app.state.auth().press_link_button();
    let (username, _) = app.pair().await.unwrap();

    let (status, _, json) = app
        .request(Method::GET, "/api/unknown-user/lights", None, None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json[0]["error"]["type"], 1);

    let (_, _, json) = app
        .request(
            Method::GET,
            &format!("/api/{STANDARD_APPLICATION_ID}"),
            None,
            None,
        )
        .await;
    assert_eq!(json[0]["error"]["type"], 1);

    let (status, _, json) = app
        .request(Method::GET, &format!("/api/{username}/lights"), None, None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json.get(0).and_then(|e| e.get("error")).is_none());

    // these stay open
    for uri in ["/api/config", "/api/nouser/config", "/description.xml"] {
        let (status, _, _) = app.request(Method::GET, uri, None, None).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
    }
}

#[tokio::test]
async fn strict_v2_requires_a_known_key() {
    let app = TestApp::start("strict").await;
    app.state.auth().press_link_button();
    let (username, _) = app.pair().await.unwrap();

    for uri in [
        "/clip/v2/resource/light",
        "/auth/v1",
        "/eventstream/clip/v2",
        "/bifrost/config",
    ] {
        for key in [None, Some("unknown"), Some(STANDARD_APPLICATION_ID)] {
            let (status, _, json) = app.request(Method::GET, uri, key, None).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{uri} {key:?}");
            assert_eq!(json["errors"][0]["description"], "unauthorized user");
            assert_eq!(json["data"], json!([]));
        }
    }

    let (status, _, _) = app.request(Method::POST, "/updater", None, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _, _) = app
        .request(
            Method::GET,
            "/clip/v2/resource/light",
            Some(&username),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _, _) = app
        .request(Method::GET, "/bifrost/config", Some(&username), None)
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn strict_auth_v1_returns_the_caller_id() {
    let app = TestApp::start("strict").await;
    app.state.auth().press_link_button();
    let (user1, _) = app.pair().await.unwrap();
    let (user2, _) = app.pair().await.unwrap();

    for user in [user1, user2] {
        let (status, headers, _) = app
            .request(Method::GET, "/auth/v1", Some(&user), None)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers["hue-application-id"].to_str().unwrap(),
            app.application_id(&user).to_string()
        );
    }
}

#[tokio::test]
async fn strict_entertainment_streamer_is_the_caller() {
    let app = TestApp::start("strict").await;
    app.state.auth().press_link_button();
    let (user1, _) = app.pair().await.unwrap();
    let (user2, _) = app.pair().await.unwrap();
    let id1 = app.application_id(&user1);
    let id2 = app.application_id(&user2);

    let (status, _, json) = app
        .request(
            Method::POST,
            "/clip/v2/resource/entertainment_configuration",
            Some(&user1),
            Some(json!({
                "type": "entertainment_configuration",
                "configuration_type": "screen",
                "metadata": { "name": "tv" },
                "locations": { "service_locations": [] },
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    let rid = json["data"][0]["rid"].as_str().unwrap().to_string();
    let uri = format!("/clip/v2/resource/entertainment_configuration/{rid}");

    let auth = app.state.auth();
    assert!(auth.psk_for_identity(id1.to_string().as_bytes()).is_none());

    let (status, _, _) = app
        .request(
            Method::PUT,
            &uri,
            Some(&user1),
            Some(json!({"action": "start"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (_, _, json) = app.request(Method::GET, &uri, Some(&user1), None).await;
    assert_eq!(json["data"][0]["active_streamer"]["rid"], id1.to_string());
    assert_eq!(json["data"][0]["active_streamer"]["rtype"], "auth_v1");

    // v1 stream owner: the streamer sees its own username, any other app
    // only sees the (not secret) application id
    let owner = |json: &Value| {
        json.as_object()
            .unwrap()
            .values()
            .find(|group| group["type"] == "Entertainment")
            .unwrap()["stream"]["owner"]
            .clone()
    };
    let (_, _, json) = app
        .request(Method::GET, &format!("/api/{user2}/groups"), None, None)
        .await;
    assert_ne!(owner(&json), user1.as_str());
    assert_eq!(owner(&json), id1.to_string().as_str());
    let (_, _, json) = app
        .request(Method::GET, &format!("/api/{user1}/groups"), None, None)
        .await;
    assert_eq!(owner(&json), user1.as_str());

    // only the streamer's identity gets a key
    assert!(auth.psk_for_identity(id1.to_string().as_bytes()).is_some());
    assert!(auth.psk_for_identity(id2.to_string().as_bytes()).is_none());
    assert!(
        auth.psk_for_identity(STANDARD_APPLICATION_ID.as_bytes())
            .is_none()
    );

    let (status, _, _) = app
        .request(
            Method::PUT,
            &uri,
            Some(&user1),
            Some(json!({"action": "stop"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, _, json) = app.request(Method::GET, &uri, Some(&user1), None).await;
    assert!(json["data"][0].get("active_streamer").is_none());
    assert!(auth.psk_for_identity(id1.to_string().as_bytes()).is_none());
}

#[tokio::test]
async fn strict_devicetype_is_capped() {
    let app = TestApp::start("strict").await;
    app.state.auth().press_link_button();

    assert_eq!(app.pair_as(&"x".repeat(65)).await, Err(7));
    assert!(app.pair_as(&"x".repeat(64)).await.is_ok());
}

#[tokio::test]
async fn strict_pairings_are_capped_per_press() {
    let app = TestApp::start("strict").await;
    app.state.auth().press_link_button();
    for _ in 0..10 {
        assert!(app.pair().await.is_ok());
    }
    assert_eq!(app.pair().await, Err(101));

    app.state.auth().press_link_button();
    assert!(app.pair().await.is_ok());
}

#[tokio::test]
async fn deleting_the_streaming_area_clears_the_streamer() {
    let app = TestApp::start("strict").await;
    app.state.auth().press_link_button();
    let (user, _) = app.pair().await.unwrap();
    let id = app.application_id(&user);

    let (_, _, json) = app
        .request(
            Method::POST,
            "/clip/v2/resource/entertainment_configuration",
            Some(&user),
            Some(json!({
                "configuration_type": "screen",
                "metadata": { "name": "tv" },
                "locations": { "service_locations": [] },
            })),
        )
        .await;
    let rid = json["data"][0]["rid"].as_str().unwrap().to_string();
    let uri = format!("/clip/v2/resource/entertainment_configuration/{rid}");

    let (status, _, _) = app
        .request(
            Method::PUT,
            &uri,
            Some(&user),
            Some(json!({"action": "start"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let auth = app.state.auth();
    assert!(auth.psk_for_identity(id.to_string().as_bytes()).is_some());

    let (status, _, _) = app.request(Method::DELETE, &uri, Some(&user), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(auth.psk_for_identity(id.to_string().as_bytes()).is_none());
}
