//! The NNC client.
//!
//! `nwc`'s shape: a struct holding the URI, a lazily-connected relay
//! client and a timeout, with one thin function per method. Three things
//! differ, and none is cosmetic.
//!
//! **No secret in the URI.** The client signs with its own key, and the
//! owner publishes a grant for it. So `new` takes a signer as well.
//!
//! **Two asynchronous methods**, which `nwc` has no precedent for — every
//! NWC method completes in its response.
//!
//! **Subscriptions are published events**, kind `30199`, not a method call.

mod pending;

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use nostr::key::PublicKey;
use nostr::signer::{IntoNostrSigner, NostrSigner};
use nostr_sdk::prelude::*;

use crate::nnc::{
    methods::*, ChannelClosed, ChannelOpened, Method, NncError, NodeControlUri, Notification,
    NotificationType, Request, Response, ResultError,
};

pub use pending::Pending;

/// Kind of an NNC request.
pub const REQUEST_KIND: u16 = 23198;
/// Kind of an NNC response.
pub const RESPONSE_KIND: u16 = 23199;
/// Kind of an NNC notification.
pub const NOTIFICATION_KIND: u16 = 23200;

/// The client's event stream, taken before a send rather than after.
///
/// It is a broadcast: a receiver taken after the event was delivered never
/// sees it. Naming the type keeps that ordering explicit at every call
/// site rather than buried in whichever function happens to await.
pub(crate) type Notifications =
    std::pin::Pin<Box<dyn futures::Stream<Item = ClientNotification> + Send>>;
/// Kind of a subscription.
pub const SUBSCRIPTION_KIND: u16 = 30199;

/// How long to wait for a response. A round trip.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long to wait for an asynchronous outcome.
///
/// Much longer, because it waits for an on-chain confirmation rather than a
/// round trip.
pub const DEFAULT_OUTCOME_TIMEOUT: Duration = Duration::from_secs(3600);

/// What can go wrong.
#[derive(Debug)]
pub enum Error {
    /// The node service refused.
    ///
    /// `UNAUTHORIZED` from a client that connected fine usually means the
    /// owner has not published a grant for its pubkey — a URI is not a
    /// credential in NNC.
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
            Self::Refused(e) if e.code == crate::nnc::ErrorCode::Unauthorized => write!(
                f,
                "{e} — the node service has no grant for this client's pubkey. \
                 In NNC a connection URI is not a credential: the owner must publish \
                 a kind 30198 grant naming it."
            ),
            Self::Refused(e) => write!(f, "{e}"),
            Self::TimedOut(d) => write!(f, "no answer within {d:?}"),
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
        Error::Json(e)
    }
}

/// A client for one node service.
pub struct NostrNodeControl {
    uri: NodeControlUri,
    client: Client,
    signer: Arc<dyn NostrSigner>,
    timeout: Duration,
    outcome_timeout: Duration,
    connected: std::sync::atomic::AtomicBool,
}

impl NostrNodeControl {
    /// Build a client from a URI and **your own** signer.
    ///
    /// Two arguments where NWC takes one, because NNC's URI carries no
    /// secret: it says who and where, and the signer says who you are.
    pub fn new<S>(uri: NodeControlUri, signer: S) -> Self
    where
        S: IntoNostrSigner,
    {
        let signer: Arc<dyn NostrSigner> = signer.into_nostr_signer();
        let client = Client::builder().signer(signer.clone()).build();
        Self {
            uri,
            client,
            signer,
            timeout: DEFAULT_TIMEOUT,
            outcome_timeout: DEFAULT_OUTCOME_TIMEOUT,
            connected: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// How long a synchronous command waits.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// How long an asynchronous outcome waits.
    pub fn with_outcome_timeout(mut self, timeout: Duration) -> Self {
        self.outcome_timeout = timeout;
        self
    }

    /// The node service this talks to.
    pub fn service(&self) -> PublicKey {
        self.uri.service
    }

    /// Connect, if not already. Called by every command.
    async fn bootstrap(&self) -> Result<(), Error> {
        use std::sync::atomic::Ordering;
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

    /// Send a request and wait for its response.
    ///
    /// Subscribes **before** publishing, so a fast answer is not missed —
    /// the ordering `nwc::send_request` uses for the same reason.
    async fn send(&self, request: Request) -> Result<Response, Error> {
        self.bootstrap().await?;
        let me = self.signer.get_public_key().await.map_err(Error::Signer)?;

        self.client
            .subscribe(
                Filter::new()
                    .kind(Kind::Custom(RESPONSE_KIND))
                    .pubkey(me)
                    .since(Timestamp::now()),
            )
            .await
            .map_err(|e| Error::Relay(e.to_string()))?;

        let payload = serde_json::to_string(&request)?;
        let ciphertext = self
            .signer
            .nip44_encrypt(&self.uri.service, &payload)
            .await
            .map_err(Error::Signer)?;

        let event = EventBuilder::new(Kind::Custom(REQUEST_KIND), ciphertext)
            .tag(Tag::public_key(self.uri.service))
            .sign(&self.signer)
            .await
            .map_err(|e| Error::Relay(e.to_string()))?;
        let request_id = event.id;

        // Before the send, not after. The client's notification stream is
        // a broadcast: a receiver taken later never sees what was already
        // delivered, so an answer that beats this line is lost and the
        // call times out with nothing to show for it.
        let notifications = self.client.notifications();

        self.client
            .send_event(&event)
            .await
            .map_err(|e| Error::Relay(e.to_string()))?;

        self.await_response(request_id, notifications).await
    }

    pub(crate) async fn await_response(
        &self,
        request_id: EventId,
        mut notifications: Notifications,
    ) -> Result<Response, Error> {
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
            if event.kind != Kind::Custom(RESPONSE_KIND) || event.pubkey != self.uri.service {
                continue;
            }
            let replies_to_us = event.tags.iter().any(|t| {
                let s = t.as_slice();
                s.first().map(String::as_str) == Some("e")
                    && s.get(1).map(String::as_str) == Some(request_id.to_hex().as_str())
            });
            if !replies_to_us {
                continue;
            }
            let plaintext = self
                .signer
                .nip44_decrypt(&self.uri.service, &event.content)
                .await
                .map_err(Error::Signer)?;
            return Ok(serde_json::from_str(&plaintext)?);
        }
    }

    /// Send a request and read its result as `R`.
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
        let method = Method::from_str(method).expect("infallible");
        let response = self.send(Request::new(method, params)?).await?;
        if let Some(e) = response.error {
            return Err(Error::Refused(e));
        }
        Ok(response.result.unwrap_or(serde_json::Value::Null))
    }

    async fn call<P, R>(&self, method: Method, params: P) -> Result<R, Error>
    where
        P: serde::Serialize,
        R: serde::de::DeserializeOwned,
    {
        let response = self.send(Request::new(method, params)?).await?;
        if let Some(e) = response.error {
            return Err(Error::Refused(e));
        }
        response.result_as().map_err(Error::Result)
    }
}

include!("methods.rs");
