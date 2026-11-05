//! Paired application store and virtual link button, used by the "strict"
//! authentication mode.
//!
//! In strict mode, every application must pair through `POST /api` while the
//! virtual link button is pressed. Each paired application gets its own
//! username (the `hue-application-key`), application id and entertainment
//! client key, stored in `bifrost.auth_file`.
//!
//! The store is shared between async request handlers and the synchronous
//! DTLS PSK callback, so it uses a std [`RwLock`] (never held across an
//! `.await`) instead of a tokio mutex.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant};

use camino::{Utf8Path, Utf8PathBuf};
use chrono::{DateTime, Utc};
use openssl::memcmp;
use openssl::rand::rand_bytes;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use hue::api::HueStreamKey;

use crate::config::{AppConfig, AuthMode};
use crate::error::ApiResult;

/// Length of a generated username (same as a real Hue bridge)
const USERNAME_LENGTH: usize = 40;

/// Alphabet of a generated username
const USERNAME_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-";

/// Length of an entertainment client key, in bytes
const CLIENTKEY_LENGTH: usize = 16;

/// Shorten a secret value before it goes to a log: keep at most the first 4
/// characters.
#[must_use]
pub fn redact(value: &str) -> String {
    let prefix: String = value.chars().take(4).collect();
    format!("{prefix}…")
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairedApp {
    /// Value of the `hue-application-key` header (v2) and `{user}` path segment (v1)
    pub username: String,
    /// Value of the `hue-application-id` header, and the DTLS PSK identity
    pub application_id: Uuid,
    /// Entertainment client key (DTLS PSK), lowercase hex
    pub clientkey: String,
    pub devicetype: String,
    pub created: DateTime<Utc>,
}

impl PairedApp {
    fn generate(devicetype: &str) -> ApiResult<Self> {
        let mut key = [0u8; CLIENTKEY_LENGTH];
        rand_bytes(&mut key)?;

        Ok(Self {
            username: generate_username()?,
            application_id: Uuid::new_v4(),
            clientkey: hex::encode(key),
            devicetype: devicetype.to_string(),
            created: Utc::now(),
        })
    }

    pub fn stream_key(&self) -> ApiResult<HueStreamKey> {
        let mut key = [0u8; CLIENTKEY_LENGTH];
        hex::decode_to_slice(&self.clientkey, &mut key)?;
        Ok(HueStreamKey::new(key))
    }
}

/// Random username of [`USERNAME_LENGTH`] characters from [`USERNAME_ALPHABET`]
fn generate_username() -> ApiResult<String> {
    // Rejection sampling keeps the distribution uniform: only accept bytes
    // below the largest multiple of the alphabet size.
    let alphabet_len = USERNAME_ALPHABET.len();
    let limit = 256 - (256 % alphabet_len);

    let mut res = String::with_capacity(USERNAME_LENGTH);
    let mut buf = [0u8; 64];
    while res.len() < USERNAME_LENGTH {
        rand_bytes(&mut buf)?;
        for byte in buf.iter().map(|b| usize::from(*b)) {
            if byte < limit && res.len() < USERNAME_LENGTH {
                res.push(char::from(USERNAME_ALPHABET[byte % alphabet_len]));
            }
        }
    }
    Ok(res)
}

/// Constant-time string comparison, so a key lookup does not leak timing
fn secret_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && memcmp::eq(a.as_bytes(), b.as_bytes())
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct AuthFile {
    #[serde(default)]
    apps: Vec<PairedApp>,
}

#[derive(Debug, Default)]
struct AuthInner {
    apps: Vec<PairedApp>,
    link_open_until: Option<Instant>,
    /// Application id of the current entertainment streamer
    streamer: Option<Uuid>,
}

#[derive(Debug)]
pub struct AuthStore {
    mode: AuthMode,
    path: Utf8PathBuf,
    link_duration: Duration,
    inner: RwLock<AuthInner>,
}

impl AuthStore {
    /// Build the store from the configuration. Only strict mode reads the
    /// auth file. A missing file means no paired apps.
    pub fn from_config(config: &AppConfig) -> ApiResult<Self> {
        let store = Self::new(
            config.auth.mode,
            config.bifrost.auth_file.clone(),
            Duration::from_secs(config.auth.link_button_seconds),
        );

        if store.is_strict() {
            store.load()?;
            log::info!(
                "Authentication: strict mode, {} paired app(s) in [{}]",
                store.read().apps.len(),
                store.path
            );
        }

        Ok(store)
    }

    #[must_use]
    pub fn new(mode: AuthMode, path: Utf8PathBuf, link_duration: Duration) -> Self {
        Self {
            mode,
            path,
            link_duration,
            inner: RwLock::new(AuthInner::default()),
        }
    }

    fn load(&self) -> ApiResult<()> {
        let apps = match File::open(&self.path) {
            Ok(fd) => serde_yml::from_reader::<_, AuthFile>(fd)?.apps,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => vec![],
            Err(err) => return Err(err.into()),
        };
        self.write().apps = apps;
        Ok(())
    }

    /// Write the paired apps atomically (temp file + rename), with mode 0600
    fn save(path: &Utf8Path, apps: &[PairedApp]) -> ApiResult<()> {
        let yaml = serde_yml::to_string(&AuthFile {
            apps: apps.to_vec(),
        })?;

        let tmp = Utf8PathBuf::from(format!("{path}.tmp"));
        match fs::remove_file(&tmp) {
            Err(err) if err.kind() != std::io::ErrorKind::NotFound => return Err(err.into()),
            _ => {}
        }

        let mut fd = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        fd.write_all(yaml.as_bytes())?;
        fd.sync_all()?;
        drop(fd);

        fs::rename(&tmp, path)?;
        Ok(())
    }

    fn read(&self) -> RwLockReadGuard<'_, AuthInner> {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, AuthInner> {
        self.inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[must_use]
    pub fn is_strict(&self) -> bool {
        self.mode == AuthMode::Strict
    }

    #[must_use]
    pub const fn link_duration(&self) -> Duration {
        self.link_duration
    }

    /// Open the pairing window for the configured duration
    pub fn press_link_button(&self) {
        self.open_link_button_for(self.link_duration);
    }

    pub fn open_link_button_for(&self, duration: Duration) {
        self.write().link_open_until = Some(Instant::now() + duration);
    }

    #[must_use]
    pub fn link_button_open(&self) -> bool {
        self.read()
            .link_open_until
            .is_some_and(|until| Instant::now() < until)
    }

    /// Pair a new app, if the link button window is open. Returns `None` if
    /// the window is closed.
    pub fn pair(&self, devicetype: &str) -> ApiResult<Option<PairedApp>> {
        let mut lock = self.write();
        if lock
            .link_open_until
            .is_none_or(|until| Instant::now() >= until)
        {
            return Ok(None);
        }

        let app = PairedApp::generate(devicetype)?;
        let mut apps = lock.apps.clone();
        apps.push(app.clone());

        // Persist before the app becomes valid, so a failed write pairs nothing
        Self::save(&self.path, &apps)?;
        lock.apps = apps;
        drop(lock);

        log::info!(
            "Paired new app [{devicetype}] with username {} and application id {}",
            redact(&app.username),
            redact(&app.application_id.to_string())
        );

        Ok(Some(app))
    }

    #[must_use]
    pub fn find_by_username(&self, username: &str) -> Option<PairedApp> {
        self.read()
            .apps
            .iter()
            .find(|app| secret_eq(&app.username, username))
            .cloned()
    }

    #[must_use]
    pub fn find_by_id(&self, application_id: Uuid) -> Option<PairedApp> {
        self.read()
            .apps
            .iter()
            .find(|app| app.application_id == application_id)
            .cloned()
    }

    /// Record the application id of the current entertainment streamer
    pub fn set_streamer(&self, application_id: Option<Uuid>) {
        self.write().streamer = application_id;
    }

    /// Client key for a DTLS PSK identity. The identity is the application id
    /// (or the username, which some v1 clients send) of a paired app, and that
    /// app must be the current entertainment streamer.
    #[must_use]
    pub fn psk_for_identity(&self, identity: &[u8]) -> Option<HueStreamKey> {
        let identity = std::str::from_utf8(identity).ok()?;
        let streamer = self.read().streamer?;

        let app = Uuid::try_parse(identity).map_or_else(
            |_| self.find_by_username(identity),
            |id| self.find_by_id(id),
        )?;

        if app.application_id != streamer {
            return None;
        }

        app.stream_key().ok()
    }
}

/// Poll for the link button trigger file, about once per second. When it
/// appears, delete it and open the pairing window.
pub async fn link_button_watcher(
    store: std::sync::Arc<AuthStore>,
    trigger_file: Utf8PathBuf,
) -> ApiResult<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        if !trigger_file.exists() {
            continue;
        }

        if let Err(err) = fs::remove_file(&trigger_file) {
            log::error!("Cannot delete link button trigger file [{trigger_file}]: {err}");
        }

        store.press_link_button();
        log::info!(
            "link button pressed, pairing open for {} s",
            store.link_duration().as_secs()
        );
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn tempdir() -> Utf8PathBuf {
        let dir = Utf8PathBuf::from_path_buf(std::env::temp_dir())
            .unwrap()
            .join(format!("bifrost-auth-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn strict_store(dir: &Utf8Path) -> AuthStore {
        AuthStore::new(
            AuthMode::Strict,
            dir.join("auth.yaml"),
            Duration::from_secs(120),
        )
    }

    #[test]
    fn generated_app_shape() {
        let app = PairedApp::generate("test#app").unwrap();
        assert_eq!(app.username.len(), USERNAME_LENGTH);
        assert!(app.username.bytes().all(|b| USERNAME_ALPHABET.contains(&b)));
        assert_eq!(app.clientkey.len(), CLIENTKEY_LENGTH * 2);
        assert_eq!(app.application_id.get_version_num(), 4);
        assert!(app.stream_key().is_ok());

        let other = PairedApp::generate("test#app").unwrap();
        assert_ne!(app.username, other.username);
        assert_ne!(app.clientkey, other.clientkey);
    }

    #[test]
    fn closed_window_pairs_nothing() {
        let dir = tempdir();
        let store = strict_store(&dir);
        assert!(!store.link_button_open());
        assert!(store.pair("app").unwrap().is_none());
        assert!(!dir.join("auth.yaml").exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn store_round_trip_and_mode() {
        let dir = tempdir();
        let store = strict_store(&dir);
        store.press_link_button();
        let app1 = store.pair("app#one").unwrap().unwrap();
        let app2 = store.pair("app#two").unwrap().unwrap();

        let path = dir.join("auth.yaml");
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(!dir.join("auth.yaml.tmp").exists());

        let reloaded = strict_store(&dir);
        reloaded.load().unwrap();
        assert_eq!(
            reloaded.find_by_username(&app1.username),
            Some(app1.clone())
        );
        assert_eq!(reloaded.find_by_id(app2.application_id), Some(app2));
        assert_eq!(reloaded.find_by_username("unknown"), None);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_file_means_no_apps() {
        let dir = tempdir();
        let store = strict_store(&dir);
        store.load().unwrap();
        assert_eq!(store.read().apps, Vec::<PairedApp>::new());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn link_window_expires() {
        let dir = tempdir();
        let store = strict_store(&dir);
        store.open_link_button_for(Duration::from_millis(50));
        assert!(store.link_button_open());
        std::thread::sleep(Duration::from_millis(100));
        assert!(!store.link_button_open());
        assert!(store.pair("late").unwrap().is_none());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn psk_only_for_active_streamer() {
        let dir = tempdir();
        let store = strict_store(&dir);
        store.press_link_button();
        let app1 = store.pair("one").unwrap().unwrap();
        let app2 = store.pair("two").unwrap().unwrap();
        let id1 = app1.application_id.to_string();
        let id2 = app2.application_id.to_string();

        // nobody is streaming
        assert!(store.psk_for_identity(id1.as_bytes()).is_none());

        store.set_streamer(Some(app1.application_id));
        let key = store.psk_for_identity(id1.as_bytes()).unwrap();
        assert_eq!(hex::encode(key), app1.clientkey);
        // uppercase uuid and username are accepted too
        assert!(
            store
                .psk_for_identity(id1.to_uppercase().as_bytes())
                .is_some()
        );
        assert!(store.psk_for_identity(app1.username.as_bytes()).is_some());

        // another paired app, the old standard identity, garbage: refused
        assert!(store.psk_for_identity(id2.as_bytes()).is_none());
        assert!(
            store
                .psk_for_identity(b"01010101-0202-0303-0404-050505050505")
                .is_none()
        );
        assert!(store.psk_for_identity(b"\xff\xfe").is_none());

        store.set_streamer(None);
        assert!(store.psk_for_identity(id1.as_bytes()).is_none());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn redact_keeps_four_chars() {
        assert_eq!(redact("abcdefgh"), "abcd…");
        assert_eq!(redact("ab"), "ab…");
    }
}
