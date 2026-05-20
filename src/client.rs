//! Hybrid HTTP client — `wreq` for TLS-fingerprint impersonation, `reqwest`
//! as the fallback when impersonation hits a wall.
//!
//! ## Wire shape
//!
//! Every probe goes through `dispatch()`. By default we try the impersonated
//! client first; on a network-class error (or after the per-host kill-switch
//! trips after 3 failures in a row) we retry once with the vanilla reqwest
//! client. The actual TLS profile used is reported back via `Response::tls`
//! so output records can carry it forward.
//!
//! ## API mismatch with SPEC
//!
//! SPEC §"Crate baseline" calls for `wreq = "6"` but at build time crates.io
//! had wreq 6.x in release-candidate state (6.0.0-rc.28 latest). We use
//! `wreq = "5.3"` (latest stable) + `wreq-util = "2.2"` for the `Emulation`
//! enum — the API surface is identical for our purposes. SPEC's specific
//! version names (`Chrome131`, `Firefox133`, `Safari18`, `Edge131`) all
//! exist in 5.3 (`Safari18_2` is the closest available; SPEC calls for
//! "safari-18.2" so this is a perfect match).

use anyhow::Result;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use std::collections::HashMap;
use wreq_util::Emulation;

use crate::cli::ImpersonateMode;
use crate::ua::Family;

/// Number of consecutive impersonated failures per host before we stop trying.
const PER_HOST_KILLSWITCH: u8 = 3;

/// TLS profile actually used for a given request.
#[derive(Debug, Clone, Copy)]
pub enum TlsProfile {
    Chrome131,
    Firefox133,
    Safari182,
    Edge131,
    Vanilla,
    FallbackVanilla,
}

impl TlsProfile {
    /// Tag string emitted in JSONL `tls_impersonation` field.
    pub fn tag(&self) -> &'static str {
        match self {
            TlsProfile::Chrome131 => "chrome-131",
            TlsProfile::Firefox133 => "firefox-133",
            TlsProfile::Safari182 => "safari-18.2",
            TlsProfile::Edge131 => "edge-131",
            TlsProfile::Vanilla => "vanilla",
            TlsProfile::FallbackVanilla => "fallback:vanilla",
        }
    }

    /// UA family that should accompany this TLS profile.
    pub fn ua_family(&self) -> Family {
        match self {
            TlsProfile::Chrome131 => Family::Chrome,
            TlsProfile::Firefox133 => Family::Firefox,
            TlsProfile::Safari182 => Family::Safari,
            TlsProfile::Edge131 => Family::Edge,
            // Vanilla — pick Chrome UAs as the most innocuous default.
            TlsProfile::Vanilla | TlsProfile::FallbackVanilla => Family::Chrome,
        }
    }

    fn to_emulation(self) -> Option<Emulation> {
        match self {
            TlsProfile::Chrome131 => Some(Emulation::Chrome131),
            TlsProfile::Firefox133 => Some(Emulation::Firefox133),
            TlsProfile::Safari182 => Some(Emulation::Safari18_2),
            TlsProfile::Edge131 => Some(Emulation::Edge131),
            TlsProfile::Vanilla | TlsProfile::FallbackVanilla => None,
        }
    }
}

/// Light response shape returned by `dispatch()`.
pub struct ProbedResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: bytes::Bytes,
    pub tls: TlsProfile,
}

/// Hybrid client — owns one wreq client per profile + one reqwest fallback.
pub struct HybridClient {
    /// One wreq client per profile (constructed once, cloned per request).
    wreq_clients: HashMap<&'static str, wreq::Client>,
    /// Vanilla reqwest used when impersonation is disabled or has failed.
    reqwest: reqwest::Client,
    /// Per-host count of consecutive impersonation failures.
    kill_counter: Mutex<HashMap<String, AtomicU8>>,
    /// Per-host sticky profile assignment (rotation happens here once).
    sticky_profile: Mutex<HashMap<String, TlsProfile>>,
    /// CLI options snapshot.
    impersonate_mode: ImpersonateMode,
    tls_fallback_on: bool,
    via_proxy: bool,
    #[allow(dead_code)]
    timeout: Duration,
}

impl HybridClient {
    pub fn build(
        timeout: Duration,
        impersonate_mode: ImpersonateMode,
        tls_fallback_on: bool,
        proxy: Option<&str>,
    ) -> Result<Self> {
        let via_proxy = proxy.is_some();

        // ── reqwest fallback ───────────────────────────────────────────
        let mut rb = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(timeout)
            .connect_timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(8)
            .tcp_keepalive(Some(Duration::from_secs(30)));
        if let Some(p) = proxy {
            rb = rb.proxy(reqwest::Proxy::all(p)?);
        }
        let reqwest = rb.build()?;

        // ── wreq impersonation clients ─────────────────────────────────
        let profiles_to_build: &[TlsProfile] = match impersonate_mode {
            ImpersonateMode::Off => &[],
            ImpersonateMode::Auto => &[
                TlsProfile::Chrome131,
                TlsProfile::Firefox133,
                TlsProfile::Safari182,
                TlsProfile::Edge131,
            ],
            ImpersonateMode::Chrome => &[TlsProfile::Chrome131],
            ImpersonateMode::Firefox => &[TlsProfile::Firefox133],
            ImpersonateMode::Safari => &[TlsProfile::Safari182],
            ImpersonateMode::Edge => &[TlsProfile::Edge131],
        };

        let mut wreq_clients: HashMap<&'static str, wreq::Client> = HashMap::new();
        for p in profiles_to_build.iter().copied() {
            let emu = match p.to_emulation() {
                Some(e) => e,
                None => continue,
            };
            let mut b = wreq::Client::builder()
                .emulation(emu)
                .cert_verification(false)
                .timeout(timeout)
                .connect_timeout(timeout)
                .redirect(wreq::redirect::Policy::none())
                .pool_max_idle_per_host(8);
            if let Some(p_url) = proxy {
                b = b.proxy(wreq::Proxy::all(p_url)?);
            }
            let c = b.build()?;
            wreq_clients.insert(p.tag(), c);
        }

        Ok(Self {
            wreq_clients,
            reqwest,
            kill_counter: Mutex::new(HashMap::new()),
            sticky_profile: Mutex::new(HashMap::new()),
            impersonate_mode,
            tls_fallback_on,
            via_proxy,
            timeout,
        })
    }

    pub fn via_proxy(&self) -> bool {
        self.via_proxy
    }

    #[allow(dead_code)]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Decide which TLS profile this host should use. Sticky — same host
    /// keeps the same profile across the run so HTTP/2 connection coalescing
    /// stays intact.
    ///
    /// Public so callers (`probe.rs`) can ask BEFORE dispatch in order to
    /// pick a User-Agent whose family matches the TLS fingerprint — sending
    /// a Chrome UA with a Firefox JA3 is the easiest way to get fingerprinted
    /// as a bot.
    pub async fn pick_profile(&self, host: &str) -> TlsProfile {
        if matches!(self.impersonate_mode, ImpersonateMode::Off) {
            return TlsProfile::Vanilla;
        }
        {
            let map = self.sticky_profile.lock().await;
            if let Some(p) = map.get(host) {
                return *p;
            }
        }
        let chosen = match self.impersonate_mode {
            ImpersonateMode::Chrome => TlsProfile::Chrome131,
            ImpersonateMode::Firefox => TlsProfile::Firefox133,
            ImpersonateMode::Safari => TlsProfile::Safari182,
            ImpersonateMode::Edge => TlsProfile::Edge131,
            ImpersonateMode::Auto => {
                use rand::seq::SliceRandom;
                let mut rng = rand::thread_rng();
                *[
                    TlsProfile::Chrome131,
                    TlsProfile::Firefox133,
                    TlsProfile::Safari182,
                    TlsProfile::Edge131,
                ]
                .choose(&mut rng)
                .unwrap()
            }
            ImpersonateMode::Off => TlsProfile::Vanilla,
        };
        self.sticky_profile.lock().await.insert(host.to_string(), chosen);
        chosen
    }

    /// Is the per-host kill-switch tripped (impersonation disabled for this host)?
    async fn killswitch_active(&self, host: &str) -> bool {
        let map = self.kill_counter.lock().await;
        match map.get(host) {
            Some(n) => n.load(Ordering::Relaxed) >= PER_HOST_KILLSWITCH,
            None => false,
        }
    }

    async fn record_imp_failure(&self, host: &str) {
        let mut map = self.kill_counter.lock().await;
        let counter = map
            .entry(host.to_string())
            .or_insert_with(|| AtomicU8::new(0));
        counter.fetch_add(1, Ordering::Relaxed);
    }

    async fn reset_imp_failures(&self, host: &str) {
        let map = self.kill_counter.lock().await;
        if let Some(counter) = map.get(host) {
            counter.store(0, Ordering::Relaxed);
        }
    }

    /// Send a GET request. Tries impersonated client first (when enabled),
    /// falls back to vanilla reqwest on error if `--tls-fallback on`.
    ///
    /// `host` is the scheme+netloc used for kill-switch + sticky-profile bookkeeping.
    /// `url` is the full URL to GET.
    /// `user_agent` is the UA string for this request.
    pub async fn dispatch(
        &self,
        host: &str,
        url: &str,
        user_agent: &str,
    ) -> Result<ProbedResponse, ClientError> {
        let want_imp = !matches!(self.impersonate_mode, ImpersonateMode::Off)
            && !self.killswitch_active(host).await;

        if want_imp {
            let profile = self.pick_profile(host).await;
            if let Some(client) = self.wreq_clients.get(profile.tag()) {
                match self.send_wreq(client, url, user_agent).await {
                    Ok(mut r) => {
                        r.tls = profile;
                        self.reset_imp_failures(host).await;
                        return Ok(r);
                    }
                    Err(e) => {
                        tracing::debug!(host=%host, profile=%profile.tag(), error=%e,
                            "impersonated request failed");
                        self.record_imp_failure(host).await;
                        if !self.tls_fallback_on {
                            return Err(e);
                        }
                        // fall through to reqwest
                    }
                }
            }
        }

        // Vanilla path — either impersonation disabled, or it failed and we fall back.
        match self.send_reqwest(url, user_agent).await {
            Ok(mut r) => {
                r.tls = if want_imp { TlsProfile::FallbackVanilla } else { TlsProfile::Vanilla };
                Ok(r)
            }
            Err(e) => Err(e),
        }
    }

    async fn send_wreq(
        &self,
        client: &wreq::Client,
        url: &str,
        user_agent: &str,
    ) -> Result<ProbedResponse, ClientError> {
        let resp = client
            .get(url)
            .header("User-Agent", user_agent)
            .send()
            .await
            .map_err(|e| ClientError::network(e.to_string()))?;
        let status = resp.status().as_u16();
        let mut headers = Vec::with_capacity(resp.headers().len());
        for (k, v) in resp.headers().iter() {
            if let Ok(s) = v.to_str() {
                headers.push((k.as_str().to_string(), s.to_string()));
            }
        }
        let body = resp.bytes().await.map_err(|e| ClientError::network(e.to_string()))?;
        Ok(ProbedResponse {
            status,
            headers,
            body,
            tls: TlsProfile::Vanilla, // overwritten by caller
        })
    }

    async fn send_reqwest(
        &self,
        url: &str,
        user_agent: &str,
    ) -> Result<ProbedResponse, ClientError> {
        let resp = self
            .reqwest
            .get(url)
            .header("User-Agent", user_agent)
            .send()
            .await
            .map_err(|e| ClientError::network(e.to_string()))?;
        let status = resp.status().as_u16();
        let mut headers = Vec::with_capacity(resp.headers().len());
        for (k, v) in resp.headers().iter() {
            if let Ok(s) = v.to_str() {
                headers.push((k.as_str().to_string(), s.to_string()));
            }
        }
        let body = resp.bytes().await.map_err(|e| ClientError::network(e.to_string()))?;
        Ok(ProbedResponse {
            status,
            headers,
            body,
            tls: TlsProfile::Vanilla,
        })
    }
}

/// Unified client error — the underlying crates have different error types,
/// so we collapse them to a string + a coarse kind here.
#[derive(Debug, Clone)]
pub struct ClientError {
    pub message: String,
}

impl ClientError {
    pub fn network<S: Into<String>>(msg: S) -> Self {
        Self { message: msg.into() }
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ClientError {}

/// Type-erased dispatcher behind an Arc — what `probe.rs` actually consumes.
pub type SharedClient = Arc<HybridClient>;
