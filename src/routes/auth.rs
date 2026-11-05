use std::convert::Infallible;

use axum::Router;
use axum::extract::{FromRequestParts, Path, Request, State};
use axum::http::HeaderValue;
use axum::http::request::Parts;
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use hyper::HeaderMap;
use serde_json::{Value, json};
use uuid::{Uuid, uuid};

use hue::api::HueStreamKey;
use hue::error::HueApiV1Error;

use crate::routes::ApiV1Error;
use crate::routes::clip::{V2Error, V2Reply};
use crate::routes::extractor::Json;
use crate::server::appstate::AppState;
use crate::server::auth_store::{PairedApp, redact};

pub const STANDARD_APPLICATION_ID: &str = "01010101-0202-0303-0404-050505050505";

/// This 16-byte key is used for all DTLS entertainment streams in open mode
pub const STANDARD_CLIENT_KEY: HueStreamKey = HueStreamKey::new(*b"BifrostHueTlsKey");

/// Header that carries the username of a paired app (Hue API v2)
pub const APPLICATION_KEY_HEADER: &str = "hue-application-key";

/// The paired app that sent a request. Only present in strict mode, where
/// the auth middleware inserts it as a request extension.
#[derive(Clone)]
pub struct Caller {
    pub username: String,
    pub application_id: Uuid,
}

/// Never show a full username or application id
impl std::fmt::Debug for Caller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Caller")
            .field("username", &redact(&self.username))
            .field("application_id", &redact(&self.application_id.to_string()))
            .finish()
    }
}

impl From<PairedApp> for Caller {
    fn from(app: PairedApp) -> Self {
        Self {
            username: app.username,
            application_id: app.application_id,
        }
    }
}

/// Extractor for the [`Caller`] of a request, if any (never rejects)
#[derive(Clone, Debug, Default)]
pub struct MaybeCaller(pub Option<Caller>);

impl<S: Send + Sync> FromRequestParts<S> for MaybeCaller {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(Self(parts.extensions.get::<Caller>().cloned())))
    }
}

/// Application id to record as the entertainment streamer: the caller in
/// strict mode, the standard id in open mode.
#[must_use]
pub fn streamer_id(caller: Option<&Caller>) -> Uuid {
    caller.map_or(uuid!(STANDARD_APPLICATION_ID), |caller| {
        caller.application_id
    })
}

fn unauthorized_v2() -> Response {
    let res = Json(V2Reply::<Value> {
        data: vec![],
        errors: vec![V2Error {
            description: "unauthorized user".to_string(),
        }],
    });
    (StatusCode::FORBIDDEN, res).into_response()
}

/// Middleware for v2 and bifrost routes: in strict mode, require a
/// `hue-application-key` header with the username of a paired app.
pub async fn require_application_key(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let auth = state.auth();
    if !auth.is_strict() {
        return next.run(req).await;
    }

    let app = req
        .headers()
        .get(APPLICATION_KEY_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|key| auth.find_by_username(key));

    let Some(app) = app else {
        log::warn!(
            "Rejected {} {}: missing or unknown {APPLICATION_KEY_HEADER}",
            req.method(),
            req.uri().path()
        );
        return unauthorized_v2();
    };

    req.extensions_mut().insert(Caller::from(app));
    next.run(req).await
}

/// Middleware for v1 `/api/{user}/...` routes: in strict mode, require the
/// username of a paired app in the path.
pub async fn require_v1_user(
    State(state): State<AppState>,
    Path(params): Path<Vec<(String, String)>>,
    mut req: Request,
    next: Next,
) -> Response {
    let auth = state.auth();
    if !auth.is_strict() {
        return next.run(req).await;
    }

    let user = params
        .iter()
        .find(|(name, _)| name == "user")
        .map_or("", |(_, value)| value.as_str());
    let Some(app) = auth.find_by_username(user) else {
        // A real bridge answers GET /api/<any user>/config with the short
        // public config, and clients read its bridgeid before they pair
        // (lg-hue-sync calls GET /api/0/config). Keep that path open.
        let rtype = params
            .iter()
            .find(|(name, _)| name == "rtype")
            .map(|(_, value)| value.as_str());
        let has_id = params.iter().any(|(name, _)| name == "id");
        if req.method() == Method::GET && rtype == Some("config") && !has_id {
            return Json(state.api_short_config().await).into_response();
        }

        log::warn!("Rejected v1 request: unknown user {}", redact(user));
        return ApiV1Error::from(HueApiV1Error::UnauthorizedUser).into_response();
    };

    req.extensions_mut().insert(Caller::from(app));
    next.run(req).await
}

pub async fn auth_v1(MaybeCaller(caller): MaybeCaller) -> impl IntoResponse {
    let value = match caller {
        Some(caller) => HeaderValue::from_str(&caller.application_id.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static(STANDARD_APPLICATION_ID)),
        None => HeaderValue::from_static(STANDARD_APPLICATION_ID),
    };

    let mut headers = HeaderMap::new();
    headers.append("hue-application-id", value);

    (headers, Json(json!({})))
}

pub fn router() -> Router<AppState> {
    Router::new().route("/v1", get(auth_v1))
}
