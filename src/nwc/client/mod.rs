//! The NWC client.
//!
//! The counterpart to [`crate::nnc::client`], and deliberately its shape:
//! a struct holding the connection, a lazily-connected relay client and a
//! timeout, with one thin function per method.
//!
//! Three things differ from the NNC client, and each follows from NWC
//! rather than from taste.
//!
//! **The secret is in the connection.** A `nostr+walletconnect://` URI
//! carries the key the client signs with, so `connect` takes one argument
//! where NNC takes two. A URI *is* a credential here.
//!
//! **Every method completes in its response.** NNC has two asynchronous
//! methods whose outcome arrives as a notification; NWC has none, so
//! there is no `Pending` here.
//!
//! **Notifications need a published subscription**, and the first version
//! of this client did not send one. NWC-02 has no subscribe method — a
//! wallet is meant to send what its grant permits — so this was written
//! to read the relay and nothing else. But delivery here is the
//! *intersection* of a grant and a kind `30199` subscription, and a
//! client holding only the first gets nothing. See
//! [`WalletConnect::notifications`].
//!
//! ## Why this exists
//!
//! It was written for mission 27's demo, where Alice and Bob are separate
//! processes that reach their own nodes over NWC and each other over
//! NIP-XZ. Without it the demo would have hand-rolled a fifth NWC client
//! in this estate, which is what
//! [User Story 11](https://github.com/DarkWebDivingClub/x.dwdc.club) exists
//! to stop.

use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use nostr::key::{Keys, PublicKey, SecretKey};
use nostr::signer::NostrSigner;
use futures::StreamExt;
use nostr_sdk::prelude::*;

use crate::nnc::{NncError, ResultError};
use crate::nwc::{methods::*, WalletMethod, WalletNotification, WalletNotificationType};

mod methods;

/// Kind of an NWC request.
pub const REQUEST_KIND: u16 = 23194;
/// Kind of an NWC response.
pub const RESPONSE_KIND: u16 = 23195;
/// Kind of an NWC notification.
pub const NOTIFICATION_KIND: u16 = 23197;

/// Where a wallet is, and the key to reach it with.
///
/// Parsed from `nostr+walletconnect://<wallet-pubkey>?relay=<url>&secret=<hex>`.
#[derive(Debug, Clone)]
pub struct WalletUri {
    /// The wallet service's pubkey.
    pub wallet: PublicKey,
    /// Where it listens. At least one.
    pub relays: Vec<String>,
    /// **The client's own key.** In NWC the URI is the credential.
    pub secret: SecretKey,
}

/// Why a string is not a `nostr+walletconnect://` URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UriError {
    /// Not the `nostr+walletconnect` scheme.
    Scheme,
    /// The wallet pubkey is missing or malformed.
    Wallet,
    /// No `relay` parameter.
    NoRelay,
    /// The `secret` is missing or malformed.
    Secret,
}

impl std::fmt::Display for UriError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Scheme => "not a nostr+walletconnect:// uri",
            Self::Wallet => "the wallet pubkey is missing or malformed",
            Self::NoRelay => "a uri must name at least one relay",
            Self::Secret => "the secret is missing or malformed",
        })
    }
}

impl std::error::Error for UriError {}

impl std::str::FromStr for WalletUri {
    type Err = UriError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rest = s.strip_prefix("nostr+walletconnect://").ok_or(UriError::Scheme)?;
        let (pubkey, query) = rest.split_once('?').unwrap_or((rest, ""));
        let wallet = PublicKey::parse(pubkey).map_err(|_| UriError::Wallet)?;

        let mut relays = Vec::new();
        let mut secret = None;
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let Some((k, v)) = pair.split_once('=') else { continue };
            let v = percent_decode(v);
            match k {
                "relay" => relays.push(v),
                "secret" => secret = SecretKey::parse(&v).ok(),
                _ => {}
            }
        }
        if relays.is_empty() {
            return Err(UriError::NoRelay);
        }
        Ok(Self { wallet, relays, secret: secret.ok_or(UriError::Secret)? })
    }
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(c) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(c as char);
                i += 3;
                continue;
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

/// What can go wrong talking to a wallet.
#[derive(Debug)]
pub enum Error {
    /// The wallet refused.
    ///
    /// `RESTRICTED` from a client that connected fine usually means the
    /// grant does not permit that method.
    Refused(NncError),
    /// No response arrived in time.
    TimedOut(Duration),
    /// The response did not match its method's type.
    Result(ResultError),
    /// The relay layer failed.
    Relay(String),
    /// The signer failed.
    Signer(nostr::signer::SignerError),
    /// Malformed JSON.
    Json(serde_json::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(e) => write!(f, "the wallet refused: {e}"),
            Self::TimedOut(d) => write!(f, "no response within {d:?}"),
            Self::Result(e) => write!(f, "{e}"),
            Self::Relay(e) => write!(f, "relay: {e}"),
            Self::Signer(e) => write!(f, "signer: {e}"),
            Self::Json(e) => write!(f, "json: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

/// A connection to one wallet.
pub struct WalletConnect {
    uri: WalletUri,
    keys: Keys,
    client: Client,
    timeout: Duration,
    connected: AtomicBool,
}

impl WalletConnect {
    /// Build a client from a URI.
    ///
    /// One argument where NNC takes two: the URI carries the secret, so
    /// there is no separate signer to supply.
    pub fn new(uri: WalletUri) -> Self {
        let keys = Keys::new(uri.secret.clone());
        let client = Client::builder().signer(keys.clone()).build();
        Self { uri, keys, client, timeout: Duration::from_secs(30), connected: AtomicBool::new(false) }
    }

    /// How long to wait for a response. Thirty seconds by default.
    ///
    /// **A hold invoice's payment is the exception.** `pay_invoice` against
    /// one does not return until the payee settles, which may be minutes,
    /// so a caller paying a hold invoice should raise this or drive the
    /// call from its own task.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// This client's own public key — what a grant is written for.
    pub fn public_key(&self) -> PublicKey {
        self.keys.public_key()
    }

    /// The wallet's public key.
    pub fn wallet(&self) -> PublicKey {
        self.uri.wallet
    }

    async fn bootstrap(&self) -> Result<(), Error> {
        if self.connected.load(Ordering::Relaxed) {
            return Ok(());
        }
        for relay in &self.uri.relays {
            self.client
                .add_relay(relay.as_str())
                .await
                .map_err(|e| Error::Relay(e.to_string()))?;
        }
        self.client.connect().await;
        self.connected.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// Call a method by name, with its parameters as JSON.
    ///
    /// The typed methods are better for anything that compiles: a changed
    /// field is a build failure rather than a surprise at runtime. This
    /// exists for the cases where the method is **not known until it is
    /// typed at a prompt** — a control tool, and checking whether
    /// somebody else's node implements what it advertises.
    ///
    /// It deliberately does not validate the method name. A node that
    /// does not implement it answers `NOT_IMPLEMENTED`, and hearing that
    /// from the node is the whole point: a client-side "unknown command"
    /// would answer a different question.
    pub async fn call_raw(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, Error> {
        // `FromStr` here is infallible: an unrecognised name becomes
        // `Unknown(s)` and goes out on the wire as typed, which is what
        // lets this reach a method the crate has never heard of.
        let method = WalletMethod::from_str(method).expect("infallible");
        self.send(method, params).await
    }

    /// Send a request and wait for its response.
    ///
    /// Subscribes and takes the notification stream **before** publishing,
    /// for the reason the NNC client does: the stream is a broadcast, so
    /// an answer that beats the receiver is lost and the call times out
    /// with nothing to show for it.
    pub(crate) async fn send(
        &self,
        method: WalletMethod,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, Error> {
        self.bootstrap().await?;
        let me = self.keys.public_key();

        self.client
            .subscribe(
                Filter::new()
                    .kind(Kind::Custom(RESPONSE_KIND))
                    .pubkey(me)
                    .since(Timestamp::now()),
            )
            .await
            .map_err(|e| Error::Relay(e.to_string()))?;

        let payload =
            serde_json::to_string(&serde_json::json!({"method": method.as_str(), "params": params}))?;
        let ciphertext = self
            .keys
            .nip44_encrypt(&self.uri.wallet, &payload)
            .await
            .map_err(Error::Signer)?;

        let event = EventBuilder::new(Kind::Custom(REQUEST_KIND), ciphertext)
            .tag(Tag::public_key(self.uri.wallet))
            .sign(&self.keys)
            .await
            .map_err(|e| Error::Relay(e.to_string()))?;
        let request_id = event.id;

        let mut notifications = self.client.notifications();

        self.client
            .send_event(&event)
            .await
            .map_err(|e| Error::Relay(e.to_string()))?;

        let deadline = tokio::time::Instant::now() + self.timeout;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                return Err(Error::TimedOut(self.timeout));
            }
            let next = tokio::time::timeout(left, notifications.next()).await;
            let Ok(Some(ClientNotification::Event { event, .. })) = next else {
                if next.is_err() {
                    return Err(Error::TimedOut(self.timeout));
                }
                continue;
            };
            if event.kind != Kind::Custom(RESPONSE_KIND) || event.pubkey != self.uri.wallet {
                continue;
            }
            if !event.tags.iter().any(|t| {
                let s = t.as_slice();
                s.first().map(String::as_str) == Some("e")
                    && s.get(1).map(String::as_str) == Some(request_id.to_hex().as_str())
            }) {
                continue;
            }
            let plain = self
                .keys
                .nip44_decrypt(&event.pubkey, &event.content)
                .await
                .map_err(Error::Signer)?;
            let v: serde_json::Value = serde_json::from_str(&plain)?;
            if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
                let e: NncError = serde_json::from_value(err.clone())?;
                return Err(Error::Refused(e));
            }
            return Ok(v.get("result").cloned().unwrap_or(serde_json::Value::Null));
        }
    }

    /// A stream of the notifications this wallet sends.
    ///
    /// **Take it before the thing that causes one.** A notification that
    /// arrives before the stream exists is not replayed, which is the same
    /// broadcast property `send` works around — and the reason a caller
    /// gating on `hold_invoice_accepted` must subscribe before it pays.
    ///
    /// ## Two subscriptions, and both are required
    ///
    /// Reading the relay is not enough. This service delivers to the
    /// **intersection** of a grant and a published kind `30199`
    /// subscription — a controller the owner permitted *and* who asked —
    /// so a client that only opens a relay filter is granted everything
    /// and sent nothing. There is no error: the wallet simply has no
    /// recipients, and the caller waits out its timeout.
    ///
    /// So this publishes the subscription first, encrypted to the wallet,
    /// then opens the filter. `types` is what to ask for; asking for
    /// nothing is how a client stops being sent anything.
    ///
    /// Published NWC-02 has no subscribe step, which is why the first
    /// version of this omitted one. It is a property of the service, not
    /// of the protocol, and a client written from the spec alone will
    /// hang waiting for a notification that was never addressed to it.
    pub async fn notifications(
        &self,
        types: &[crate::nwc::WalletNotificationType],
    ) -> Result<Notifications, Error> {
        self.bootstrap().await?;

        let wanted: Vec<&str> = types.iter().map(|t| t.as_str()).collect();
        let content = self
            .keys
            .nip44_encrypt(&self.uri.wallet, &serde_json::to_string(&wanted)?)
            .await
            .map_err(Error::Signer)?;
        let event = EventBuilder::new(Kind::Custom(crate::SUBSCRIPTION_KIND), content)
            .tags([Tag::identifier(self.uri.wallet.to_hex()), Tag::public_key(self.uri.wallet)])
            .sign(&self.keys)
            .await
            .map_err(|e| Error::Relay(e.to_string()))?;
        self.client.send_event(&event).await.map_err(|e| Error::Relay(e.to_string()))?;

        // The service reads the subscription off the relay, so there is a
        // window where it is published and not yet in effect. A caller
        // that paid inside that window would lose the notification it
        // published the subscription in order to receive.
        tokio::time::sleep(Duration::from_millis(500)).await;

        self.client
            .subscribe(
                Filter::new()
                    .kind(Kind::Custom(NOTIFICATION_KIND))
                    .pubkey(self.keys.public_key())
                    .since(Timestamp::now()),
            )
            .await
            .map_err(|e| Error::Relay(e.to_string()))?;
        Ok(Notifications { stream: self.client.notifications(), keys: self.keys.clone(), wallet: self.uri.wallet })
    }
}

/// Notifications from one wallet, decrypted and typed.
pub struct Notifications {
    stream: crate::nnc::client::Notifications,
    keys: Keys,
    wallet: PublicKey,
}

impl Notifications {
    /// The next notification, or `None` if the stream ended.
    pub async fn next(&mut self) -> Option<WalletNotification> {
        loop {
            let ClientNotification::Event { event, .. } = self.stream.next().await? else {
                continue;
            };
            if event.kind != Kind::Custom(NOTIFICATION_KIND) || event.pubkey != self.wallet {
                continue;
            }
            let plain = self.keys.nip44_decrypt(&event.pubkey, &event.content).await.ok()?;
            if let Ok(n) = serde_json::from_str::<WalletNotification>(&plain) {
                return Some(n);
            }
        }
    }

    /// Wait for one notification of a given type.
    ///
    /// What a caller gating on `hold_invoice_accepted` wants: block until
    /// the payer has locked in, and give up rather than wait for ever.
    pub async fn wait_for(
        &mut self,
        want: WalletNotificationType,
        within: Duration,
    ) -> Option<WalletNotification> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                return None;
            }
            match tokio::time::timeout(left, self.next()).await {
                Ok(Some(n)) if n.notification_type == want => return Some(n),
                Ok(Some(_)) => continue,
                _ => return None,
            }
        }
    }
}
