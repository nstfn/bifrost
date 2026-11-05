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

use std::fmt;
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

/// Longest accepted `devicetype` in a pairing request, in bytes
pub const MAX_DEVICETYPE_LENGTH: usize = 64;

/// Most apps that can pair during one press of the link button
pub const MAX_PAIRINGS_PER_WINDOW: u32 = 10;

/// Shorten a secret value before it goes to a log: keep at most the first 4
/// characters.
#[must_use]
pub fn redact(value: &str) -> String {
    let prefix: String = value.chars().take(4).collect();
    format!("{prefix}…")
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
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

/// Never show a full username, application id or client key
impl fmt::Debug for PairedApp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairedApp")
            .field("username", &redact(&self.username))
            .field("application_id", &redact(&self.application_id.to_string()))
            .field("clientkey", &"<redacted>")
            .field("devicetype", &self.devicetype)
            .field("created", &self.created)
            .finish()
    }
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

#[derive(Default)]
struct AuthInner {
    apps: Vec<PairedApp>,
    link_open_until: Option<Instant>,
    /// Apps paired since the link button was last pressed
    pairings_in_window: u32,
    /// Application id of the current entertainment streamer
    streamer: Option<Uuid>,
}

impl fmt::Debug for AuthInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthInner")
            .field("apps", &self.apps)
            .field("link_open_until", &self.link_open_until)
            .field("pairings_in_window", &self.pairings_in_window)
            .field("streamer", &self.streamer.map(|id| redact(&id.to_string())))
            .finish()
    }
}

pub struct AuthStore {
    mode: AuthMode,
    path: Utf8PathBuf,
    link_duration: Duration,
    inner: RwLock<AuthInner>,
}

impl fmt::Debug for AuthStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthStore")
            .field("mode", &self.mode)
            .field("path", &self.path)
            .field("link_duration", &self.link_duration)
            .field("inner", &*self.read())
            .finish()
    }
}

/// Result of one poll of the link button trigger file
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TriggerState {
    /// No trigger file
    #[default]
    Absent,
    /// A regular file was deleted, and the pairing window opened
    Pressed,
    /// A symlink was deleted, the pairing window stays closed
    SymlinkRemoved,
    /// Something that is not a regular file (a directory, ...): ignored
    NotAFile,
    /// The trigger could not be checked or deleted: ignored
    Failed,
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

        // Make the rename itself durable
        let dir = path
            .parent()
            .filter(|dir| !dir.as_str().is_empty())
            .unwrap_or_else(|| Utf8Path::new("."));
        File::open(dir)?.sync_all()?;
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
        let mut lock = self.write();
        lock.link_open_until = Some(Instant::now() + duration);
        lock.pairings_in_window = 0;
    }

    #[must_use]
    pub fn link_button_open(&self) -> bool {
        self.read()
            .link_open_until
            .is_some_and(|until| Instant::now() < until)
    }

    /// Pair a new app, if the link button window is open and has room for
    /// another app. Returns `None` otherwise.
    pub fn pair(&self, devicetype: &str) -> ApiResult<Option<PairedApp>> {
        let mut lock = self.write();
        if lock
            .link_open_until
            .is_none_or(|until| Instant::now() >= until)
        {
            return Ok(None);
        }
        if lock.pairings_in_window >= MAX_PAIRINGS_PER_WINDOW {
            log::warn!(
                "Refused pairing of [{devicetype}]: {MAX_PAIRINGS_PER_WINDOW} apps already paired since the link button was pressed"
            );
            return Ok(None);
        }

        let app = PairedApp::generate(devicetype)?;
        let mut apps = lock.apps.clone();
        apps.push(app.clone());

        // Persist before the app becomes valid, so a failed write pairs nothing
        Self::save(&self.path, &apps)?;
        lock.apps = apps;
        lock.pairings_in_window += 1;
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

impl AuthStore {
    /// Check the link button trigger file once. Only the successful delete of
    /// a regular file opens the pairing window: a symlink is deleted but does
    /// not open it, and anything else is ignored. This way a trigger that
    /// cannot be deleted (a directory, a read-only mount) cannot keep pairing
    /// open.
    pub fn poll_trigger(&self, trigger_file: &Utf8Path) -> (TriggerState, Option<std::io::Error>) {
        let meta = match fs::symlink_metadata(trigger_file) {
            Ok(meta) => meta,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return (TriggerState::Absent, None);
            }
            Err(err) => return (TriggerState::Failed, Some(err)),
        };

        let file_type = meta.file_type();
        if !file_type.is_file() && !file_type.is_symlink() {
            return (TriggerState::NotAFile, None);
        }

        // remove_file() deletes a symlink itself, never its target
        if let Err(err) = fs::remove_file(trigger_file) {
            return (TriggerState::Failed, Some(err));
        }

        if file_type.is_symlink() {
            return (TriggerState::SymlinkRemoved, None);
        }

        self.press_link_button();
        (TriggerState::Pressed, None)
    }
}

/// Log the result of a trigger poll. Each press is logged. A problem is
/// logged once, when the state changes, not on every poll. Returns true if
/// something was logged.
#[must_use]
pub fn log_trigger_state(
    trigger_file: &Utf8Path,
    previous: TriggerState,
    state: TriggerState,
    err: Option<&std::io::Error>,
    link_duration: Duration,
) -> bool {
    let err = err.map(|err| format!(": {err}")).unwrap_or_default();
    match state {
        TriggerState::Pressed => {
            log::info!(
                "link button pressed, pairing open for {} s",
                link_duration.as_secs()
            );
        }
        _ if state == previous => return false,
        TriggerState::Absent => return false,
        TriggerState::SymlinkRemoved => {
            log::warn!(
                "Link button trigger [{trigger_file}] is a symlink: deleted it, pairing stays closed"
            );
        }
        TriggerState::NotAFile => {
            log::warn!(
                "Link button trigger [{trigger_file}] is not a regular file: ignored, pairing stays closed"
            );
        }
        TriggerState::Failed => {
            log::warn!(
                "Cannot check or delete link button trigger [{trigger_file}]{err}: pairing stays closed"
            );
        }
    }
    true
}

/// Poll for the link button trigger file, about once per second
pub async fn link_button_watcher(
    store: std::sync::Arc<AuthStore>,
    trigger_file: Utf8PathBuf,
) -> ApiResult<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut previous = TriggerState::Absent;
    loop {
        interval.tick().await;

        let (state, err) = store.poll_trigger(&trigger_file);
        let _logged = log_trigger_state(
            &trigger_file,
            previous,
            state,
            err.as_ref(),
            store.link_duration(),
        );
        previous = state;
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
    fn regular_trigger_file_opens_once() {
        let dir = tempdir();
        let store = strict_store(&dir);
        let trigger = dir.join("linkbutton");
        fs::write(&trigger, b"").unwrap();

        assert_eq!(store.poll_trigger(&trigger).0, TriggerState::Pressed);
        assert!(store.link_button_open());
        assert!(!trigger.exists());

        store.open_link_button_for(Duration::ZERO);
        assert_eq!(store.poll_trigger(&trigger).0, TriggerState::Absent);
        assert!(!store.link_button_open());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn directory_trigger_never_opens_and_logs_once() {
        let dir = tempdir();
        let store = strict_store(&dir);
        let trigger = dir.join("linkbutton");
        fs::create_dir(&trigger).unwrap();

        let mut previous = TriggerState::Absent;
        let mut logged = 0;
        for _ in 0..5 {
            let (state, err) = store.poll_trigger(&trigger);
            assert_eq!(state, TriggerState::NotAFile);
            if log_trigger_state(&trigger, previous, state, err.as_ref(), Duration::ZERO) {
                logged += 1;
            }
            previous = state;
        }
        assert_eq!(logged, 1);
        assert!(!store.link_button_open());
        assert!(trigger.is_dir());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn symlink_trigger_is_deleted_but_does_not_open() {
        let dir = tempdir();
        let store = strict_store(&dir);
        let target = dir.join("target");
        let trigger = dir.join("linkbutton");
        fs::write(&target, b"").unwrap();
        std::os::unix::fs::symlink(&target, &trigger).unwrap();

        assert_eq!(store.poll_trigger(&trigger).0, TriggerState::SymlinkRemoved);
        assert!(!store.link_button_open());
        assert!(fs::symlink_metadata(&trigger).is_err());
        assert!(target.exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn undeletable_trigger_does_not_open() {
        let dir = tempdir();
        let store = strict_store(&dir);
        let sub = dir.join("ro");
        fs::create_dir(&sub).unwrap();
        let trigger = sub.join("linkbutton");
        fs::write(&trigger, b"").unwrap();
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o555)).unwrap();

        // root ignores directory permissions: nothing to test then
        let writable = fs::write(sub.join("probe"), b"").is_ok();
        if !writable {
            let (state, err) = store.poll_trigger(&trigger);
            assert_eq!(state, TriggerState::Failed);
            assert!(err.is_some());
            assert!(!store.link_button_open());
            assert!(trigger.exists());
        }

        fs::set_permissions(&sub, fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn pairings_are_capped_per_window() {
        let dir = tempdir();
        let store = strict_store(&dir);
        store.press_link_button();
        for _ in 0..MAX_PAIRINGS_PER_WINDOW {
            assert!(store.pair("app").unwrap().is_some());
        }
        assert!(store.pair("one too many").unwrap().is_none());

        store.press_link_button();
        assert!(store.pair("next window").unwrap().is_some());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn debug_output_hides_secrets() {
        let dir = tempdir();
        let store = strict_store(&dir);
        store.press_link_button();
        let app = store.pair("app").unwrap().unwrap();
        store.set_streamer(Some(app.application_id));

        for text in [format!("{app:?}"), format!("{store:?}")] {
            assert!(!text.contains(&app.username), "{text}");
            assert!(!text.contains(&app.application_id.to_string()), "{text}");
            assert!(!text.contains(&app.clientkey), "{text}");
            assert!(text.contains(&redact(&app.username)), "{text}");
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn redact_keeps_four_chars() {
        assert_eq!(redact("abcdefgh"), "abcd…");
        assert_eq!(redact("ab"), "ab…");
    }
}
