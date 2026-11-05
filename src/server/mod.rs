#[cfg(feature = "server-banner")]
pub mod banner;

pub mod appstate;
pub mod auth_store;
pub mod behavior_instance;
pub mod certificate;
pub mod entertainment;
pub mod http;
pub mod hueevents;
pub mod mdns;
pub mod ssdp;
pub mod updater;

use std::fs::File;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::connect_info::IntoMakeServiceWithConnectInfo;
use axum::extract::{ConnectInfo, Request};
use axum::http::Uri;
use axum::response::Response;
use axum::{Router, ServiceExt};

use camino::Utf8PathBuf;
use tokio::select;
use tokio::sync::Mutex;
use tokio::time::{MissedTickBehavior, sleep_until};
use tower::Layer;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::normalize_path::{NormalizePath, NormalizePathLayer};
use tower_http::trace::TraceLayer;
use tracing::{Span, info_span};

use crate::error::ApiResult;
use crate::resource::Resources;
use crate::routes;
use crate::server::appstate::AppState;
use crate::server::auth_store::redact;
use crate::server::updater::VersionUpdater;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Http,
    Https,
}

/// Shorten the v1 username in a `/api/{user}/...` uri, so the request log
/// does not show a full key (strict auth mode)
fn redact_v1_uri(uri: &Uri) -> String {
    let full = uri.to_string();
    let Some(rest) = uri.path().strip_prefix("/api/") else {
        return full;
    };
    let user = rest.split('/').next().unwrap_or_default();
    if user.len() <= 4 || matches!(user, "config" | "nouser" | "newUser") {
        return full;
    }
    full.replacen(
        &format!("/api/{user}"),
        &format!("/api/{}", redact(user)),
        1,
    )
}

fn trace_layer_make_span_with(request: &Request, protocol: Protocol, strict: bool) -> Span {
    let addr = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |ci| ci.0.ip());

    if strict {
        let uri = redact_v1_uri(request.uri());
        return match protocol {
            Protocol::Https => info_span!(
                "https",
                client = ?addr,
                method = ?request.method(),
                uri = %uri,
                status = tracing::field::Empty,
            ),
            Protocol::Http => info_span!(
                "http",
                client = ?addr,
                method = ?request.method(),
                uri = %uri,
                status = tracing::field::Empty,
            ),
        };
    }

    match protocol {
        Protocol::Https => info_span!(
            "https",
            client = ?addr,
            method = ?request.method(),
            uri = ?request.uri(),
            status = tracing::field::Empty,
        ),
        Protocol::Http => info_span!(
            "http",
            client = ?addr,
            method = ?request.method(),
            uri = ?request.uri(),
            status = tracing::field::Empty,
        ),
    }
}

fn trace_layer_on_response(response: &Response<Body>, latency: Duration, span: &Span) {
    span.record(
        "latency",
        tracing::field::display(format!("{}μs", latency.as_micros())),
    );
    span.record("status", tracing::field::display(response.status()));
}

fn router(protocol: Protocol, appstate: AppState) -> Router<()> {
    let strict = appstate.auth().is_strict();
    routes::router(appstate).layer(
        TraceLayer::new_for_http()
            .make_span_with(move |request: &Request| {
                trace_layer_make_span_with(request, protocol, strict)
            })
            .on_response(trace_layer_on_response),
    )
}

#[must_use]
pub fn build_service(
    protocol: Protocol,
    appstate: AppState,
) -> IntoMakeServiceWithConnectInfo<NormalizePath<Router>, SocketAddr> {
    let cors_layer = CorsLayer::new()
        .allow_methods(Any)
        .allow_origin(AllowOrigin::any())
        .allow_headers(Any);
    let normalized = NormalizePathLayer::trim_trailing_slash()
        .layer(router(protocol, appstate).layer(cors_layer));

    ServiceExt::<Request>::into_make_service_with_connect_info(normalized)
}

pub async fn config_writer(res: Arc<Mutex<Resources>>, filename: Utf8PathBuf) -> ApiResult<()> {
    const STABILIZE_TIME: Duration = Duration::from_secs(1);

    let rx = res.lock().await.state_channel();
    let tmp = filename.with_extension("tmp");

    let mut old_state = res.lock().await.serialize()?;

    loop {
        /* Wait for change notification */
        rx.notified().await;

        /* Updates often happen in burst, and we don't want to write the state
         * file over and over, so ignore repeated update notifications within
         * STABILIZE_TIME */
        let deadline = tokio::time::Instant::now() + STABILIZE_TIME;
        loop {
            select! {
                () = rx.notified() => {},
                () = sleep_until(deadline) => break,
            }
        }

        /* Now that the state is likely stabilized, serialize the new state */
        let new_state = res.lock().await.serialize()?;

        /* If state is not actually changed, try again */
        if old_state == new_state && filename.exists() {
            continue;
        }

        log::debug!("Config changed, saving..");

        let mut fd = File::create(&tmp)?;
        fd.write_all(new_state.as_bytes())?;
        std::fs::rename(&tmp, &filename)?;

        old_state = new_state;
    }
}

#[allow(clippy::significant_drop_tightening)]
pub async fn version_updater(
    res: Arc<Mutex<Resources>>,
    upd: Arc<Mutex<VersionUpdater>>,
) -> ApiResult<()> {
    const INTERVAL: Duration = Duration::from_secs(60);
    let mut interval = tokio::time::interval(INTERVAL);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut version = upd.lock().await.get().await.clone();

    loop {
        interval.tick().await;

        let mut lock = upd.lock().await;
        let new_version = lock.get().await;
        if new_version != &version {
            log::info!("New version detected! Patching state database with new version numbers..");
            version.clone_from(new_version);
            res.lock().await.update_bridge_version(version.clone());
        }
    }
}
