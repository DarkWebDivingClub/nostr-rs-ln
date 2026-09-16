// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2025 Rust Nostr Developers
// Distributed under the MIT software license

//! NIP47: Wallet Connect
//!
//! <https://github.com/nostr-protocol/nips/blob/master/47.md>

use alloc::borrow::Cow;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::convert::Infallible;
use core::fmt;
use core::hash::{Hash, Hasher};
use core::str::FromStr;

use serde::ser::{SerializeMap, SerializeStruct};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use super::nip04;
#[cfg(feature = "std")]
use crate::event;
use crate::types::url::form_urlencoded::byte_serialize;
use crate::types::url::{RelayUrl, Url};
use crate::{Event, JsonUtil, PublicKey, SecretKey, Timestamp};
#[cfg(all(feature = "std", feature = "os-rng"))]
use crate::{EventBuilder, Keys, Kind, Tag};

/// NIP47 error
#[derive(Debug)]
pub enum Error {
    /// JSON error
    Json(serde_json::Error),
    /// NIP04 error
    NIP04(nip04::Error),
    /// Event Builder error
    #[cfg(feature = "std")]
    EventBuilder(event::builder::Error),
    /// Error code
    ErrorCode(NIP47Error),
    /// Can't deserialize NIP-47 response
    CantDeserializeResponse {
        /// NIP-47 response
        response: String,
        /// Deserialization error
        error: String,
    },
    /// Unsupported method
    UnsupportedMethod(Method),
    /// Unexpected result
    UnexpectedResult,
    /// Invalid URI
    InvalidURI,
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(e) => e.fmt(f),
            Self::NIP04(e) => e.fmt(f),
            #[cfg(feature = "std")]
            Self::EventBuilder(e) => e.fmt(f),
            Self::ErrorCode(e) => e.fmt(f),
            Self::CantDeserializeResponse { response, error } => write!(
                f,
                "Can't deserialize response: response={response}, error={error}"
            ),
            Self::UnsupportedMethod(name) => write!(f, "Unsupported method: {name}"),
            Self::UnexpectedResult => f.write_str("Unexpected result"),
            Self::InvalidURI => f.write_str("Invalid URI"),
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

impl From<nip04::Error> for Error {
    fn from(e: nip04::Error) -> Self {
        Self::NIP04(e)
    }
}

#[cfg(feature = "std")]
impl From<event::builder::Error> for Error {
    fn from(e: event::builder::Error) -> Self {
        Self::EventBuilder(e)
    }
}

/// NIP47 Response Error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ErrorCode {
    ///  The client is sending commands too fast.
    #[serde(rename = "RATE_LIMITED")]
    RateLimited,
    /// The command is not known of is intentionally not implemented
    #[serde(rename = "NOT_IMPLEMENTED")]
    NotImplemented,
    /// The wallet does not have enough funds to cover a fee reserve or the payment amount
    #[serde(rename = "INSUFFICIENT_BALANCE")]
    InsufficientBalance,
    /// The payment failed. This may be due to a timeout, exhausting all routes, insufficient capacity or similar.
    #[serde(rename = "PAYMENT_FAILED")]
    PaymentFailed,
    /// The invoice could not be found by the given parameters.
    #[serde(rename = "NOT_FOUND")]
    NotFound,
    /// The wallet has exceeded its spending quota
    #[serde(rename = "QUOTA_EXCEEDED")]
    QuotaExceeded,
    /// This public key is not allowed to do this operation
    #[serde(rename = "RESTRICTED")]
    Restricted,
    /// This public key has no wallet connected
    #[serde(rename = "UNAUTHORIZED")]
    Unauthorized,
    /// An internal error
    #[serde(rename = "INTERNAL")]
    Internal,
    /// The encryption scheme is not supported
    #[serde(rename = "UNSUPPORTED_ENCRYPTION")]
    UnsupportedEncryption,
    /// Other error
    #[serde(rename = "OTHER")]
    Other,
}

/// NIP47 Error message
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NIP47Error {
    /// Error Code
    pub code: ErrorCode,
    /// Human Readable error message
    pub message: String,
}

impl fmt::Display for NIP47Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [{:?}]", self.message, self.code)
    }
}

/// Method
#[derive(Debug, Clone)]
pub enum Method {
    /// Pay Invoice
    PayInvoice,
    /// Pay Keysend
    PayKeysend,
    /// Make Invoice
    MakeInvoice,
    /// Lookup Invoice
    LookupInvoice,
    /// List transactions
    ListTransactions,
    /// Get Balance
    GetBalance,
    /// Get Info
    GetInfo,
    /// Make Hold Invoice
    MakeHoldInvoice,
    /// Cancel Hold Invoice
    CancelHoldInvoice,
    /// Settle Hold Invoice
    SettleHoldInvoice,
    /// Pay Onchain
    PayOnchain,
    /// Make New Address
    MakeNewAddress,
    /// Pay Offer (BOLT-12)
    PayOffer,
    /// Make Offer (BOLT-12)
    MakeOffer,
    /// Lookup Offer
    LookupOffer,
    /// Lookup Address
    LookupAddress,
    /// List Invoices
    ListInvoices,
    /// List Offers
    ListOffers,
    /// Disable Offer
    DisableOffer,
    /// List Addresses
    ListAddresses,
    /// Pay BIP-321 URI
    PayBip321,
    /// Make BIP-321 URI
    MakeBip321,
    /// Subscribe to notifications
    SubscribeNotifications,
    /// Estimate on-chain fees
    EstimateOnchainFees,
    /// Estimate routing fees
    EstimateRoutingFees,
    /// Unknown method
    Unknown(String),
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl PartialEq for Method {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for Method {}

impl PartialOrd for Method {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Method {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl Hash for Method {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state)
    }
}

impl Method {
    /// Serialize as `&str`
    pub fn as_str(&self) -> &str {
        match self {
            Self::PayInvoice => "pay_invoice",
            Self::PayKeysend => "pay_keysend",
            Self::MakeInvoice => "make_invoice",
            Self::LookupInvoice => "lookup_invoice",
            Self::ListTransactions => "list_transactions",
            Self::GetBalance => "get_balance",
            Self::GetInfo => "get_info",
            Self::MakeHoldInvoice => "make_hold_invoice",
            Self::CancelHoldInvoice => "cancel_hold_invoice",
            Self::SettleHoldInvoice => "settle_hold_invoice",
            Self::PayOnchain => "pay_onchain",
            Self::MakeNewAddress => "make_new_address",
            Self::PayOffer => "pay_offer",
            Self::MakeOffer => "make_offer",
            Self::LookupOffer => "lookup_offer",
            Self::LookupAddress => "lookup_address",
            Self::ListInvoices => "list_invoices",
            Self::ListOffers => "list_offers",
            Self::DisableOffer => "disable_offer",
            Self::ListAddresses => "list_addresses",
            Self::PayBip321 => "pay_bip321",
            Self::MakeBip321 => "make_bip321",
            Self::SubscribeNotifications => "subscribe_notifications",
            Self::EstimateOnchainFees => "estimate_onchain_fees",
            Self::EstimateRoutingFees => "estimate_routing_fees",
            Self::Unknown(method) => method.as_str(),
        }
    }
}

impl FromStr for Method {
    type Err = Infallible;

    fn from_str(method: &str) -> Result<Self, Self::Err> {
        match method {
            "pay_invoice" => Ok(Self::PayInvoice),
            "pay_keysend" => Ok(Self::PayKeysend),
            "make_invoice" => Ok(Self::MakeInvoice),
            "lookup_invoice" => Ok(Self::LookupInvoice),
            "list_transactions" => Ok(Self::ListTransactions),
            "get_balance" => Ok(Self::GetBalance),
            "get_info" => Ok(Self::GetInfo),
            "make_hold_invoice" => Ok(Self::MakeHoldInvoice),
            "cancel_hold_invoice" => Ok(Self::CancelHoldInvoice),
            "settle_hold_invoice" => Ok(Self::SettleHoldInvoice),
            "pay_onchain" => Ok(Self::PayOnchain),
            "make_new_address" => Ok(Self::MakeNewAddress),
            "pay_offer" => Ok(Self::PayOffer),
            "make_offer" => Ok(Self::MakeOffer),
            "lookup_offer" => Ok(Self::LookupOffer),
            "lookup_address" => Ok(Self::LookupAddress),
            "list_invoices" => Ok(Self::ListInvoices),
            "list_offers" => Ok(Self::ListOffers),
            "disable_offer" => Ok(Self::DisableOffer),
            "list_addresses" => Ok(Self::ListAddresses),
            "pay_bip321" => Ok(Self::PayBip321),
            "make_bip321" => Ok(Self::MakeBip321),
            "subscribe_notifications" => Ok(Self::SubscribeNotifications),
            "estimate_onchain_fees" => Ok(Self::EstimateOnchainFees),
            "estimate_routing_fees" => Ok(Self::EstimateRoutingFees),
            m => Ok(Self::Unknown(m.to_string())),
        }
    }
}

impl Serialize for Method {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Method {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let method: String = Deserialize::deserialize(deserializer)?;
        Self::from_str(&method).map_err(serde::de::Error::custom)
    }
}

/// Nostr Wallet Connect Request
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RequestParams {
    /// Pay Invoice
    PayInvoice(PayInvoiceRequest),
    /// Pay Keysend
    PayKeysend(PayKeysendRequest),
    /// Make Invoice
    MakeInvoice(MakeInvoiceRequest),
    /// Lookup Invoice
    LookupInvoice(LookupInvoiceRequest),
    /// List Transactions
    ListTransactions(ListTransactionsRequest),
    /// Get Balance
    GetBalance,
    /// Get Info
    GetInfo,
    /// Make Hold Invoice
    MakeHoldInvoice(MakeHoldInvoiceRequest),
    /// Cancel Hold Invoice
    CancelHoldInvoice(CancelHoldInvoiceRequest),
    /// Settle Hold Invoice
    SettleHoldInvoice(SettleHoldInvoiceRequest),
    /// Pay Onchain
    PayOnchain(PayOnchainRequest),
    /// Make New Address
    MakeNewAddress,
    /// Pay Offer (BOLT-12)
    PayOffer(PayOfferRequest),
    /// Make Offer (BOLT-12)
    MakeOffer(MakeOfferRequest),
    /// Lookup Offer
    LookupOffer(LookupOfferRequest),
    /// Lookup Address
    LookupAddress(LookupAddressRequest),
    /// List Invoices
    ListInvoices(ListInvoicesRequest),
    /// List Offers
    ListOffers(ListOffersRequest),
    /// Disable Offer
    DisableOffer(DisableOfferRequest),
    /// List Addresses
    ListAddresses(ListAddressesRequest),
    /// Pay BIP-321 URI
    PayBip321(PayBip321Request),
    /// Make BIP-321 URI
    MakeBip321(MakeBip321Request),
    /// Subscribe to notifications
    SubscribeNotifications(SubscribeNotificationsRequest),
    /// Estimate on-chain fees
    EstimateOnchainFees,
    /// Estimate routing fees
    EstimateRoutingFees(EstimateRoutingFeesRequest),
}

impl Serialize for RequestParams {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            RequestParams::PayInvoice(p) => p.serialize(serializer),
            RequestParams::PayKeysend(p) => p.serialize(serializer),
            RequestParams::MakeInvoice(p) => p.serialize(serializer),
            RequestParams::LookupInvoice(p) => p.serialize(serializer),
            RequestParams::ListTransactions(p) => p.serialize(serializer),
            RequestParams::GetBalance => {
                let map = serializer.serialize_map(None)?;
                map.end()
            }
            RequestParams::GetInfo => {
                let map = serializer.serialize_map(None)?;
                map.end()
            }
            RequestParams::MakeHoldInvoice(p) => p.serialize(serializer),
            RequestParams::CancelHoldInvoice(p) => p.serialize(serializer),
            RequestParams::SettleHoldInvoice(p) => p.serialize(serializer),
            RequestParams::PayOnchain(p) => p.serialize(serializer),
            RequestParams::MakeNewAddress => {
                let map = serializer.serialize_map(None)?;
                map.end()
            }
            RequestParams::PayOffer(p) => p.serialize(serializer),
            RequestParams::MakeOffer(p) => p.serialize(serializer),
            RequestParams::LookupOffer(p) => p.serialize(serializer),
            RequestParams::LookupAddress(p) => p.serialize(serializer),
            RequestParams::ListInvoices(p) => p.serialize(serializer),
            RequestParams::ListOffers(p) => p.serialize(serializer),
            RequestParams::DisableOffer(p) => p.serialize(serializer),
            RequestParams::ListAddresses(p) => p.serialize(serializer),
            RequestParams::PayBip321(p) => p.serialize(serializer),
            RequestParams::MakeBip321(p) => p.serialize(serializer),
            RequestParams::SubscribeNotifications(p) => p.serialize(serializer),
            RequestParams::EstimateOnchainFees => {
                let map = serializer.serialize_map(None)?;
                map.end()
            }
            RequestParams::EstimateRoutingFees(p) => p.serialize(serializer),
        }
    }
}

/// Pay Invoice Request
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PayInvoiceRequest {
    /// Optional id
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Request invoice
    pub invoice: String,
    /// Optional amount in millisatoshis
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<u64>,
}

impl PayInvoiceRequest {
    /// New pay invoice request
    #[inline]
    pub fn new<S>(invoice: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            id: None,
            invoice: invoice.into(),
            amount: None,
        }
    }
}

/// TLVs to be added to the keysend payment
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeysendTLVRecord {
    /// TLV type
    #[serde(rename = "type")]
    pub tlv_type: u64,
    /// TLV value
    pub value: String,
}

/// Pay Invoice Request
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PayKeysendRequest {
    /// Optional id
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Amount in millisatoshis
    pub amount: u64,
    /// Receiver's node id
    pub pubkey: String,
    /// Optional preimage
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preimage: Option<String>,
    /// Optional TLVs to be added to the keysend payment
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tlv_records: Vec<KeysendTLVRecord>,
}

/// Make Invoice Request
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MakeInvoiceRequest {
    /// Amount in millisatoshis
    pub amount: u64,
    /// Invoice description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Invoice description hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description_hash: Option<String>,
    /// Invoice expiry in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry: Option<u64>,
}

/// Lookup Invoice Request
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LookupInvoiceRequest {
    /// Payment hash of invoice
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_hash: Option<String>,
    /// Bolt11 invoice
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invoice: Option<String>,
}

/// Transaction Type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransactionType {
    /// Incoming payments
    #[serde(rename = "incoming")]
    Incoming,
    /// Outgoing payments
    #[serde(rename = "outgoing")]
    Outgoing,
}

/// Transaction State
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TransactionState {
    /// Pending
    #[serde(rename = "pending")]
    Pending,
    /// Settled
    #[serde(rename = "settled")]
    Settled,
    /// Expired (for invoices)
    #[serde(rename = "expired")]
    Expired,
    /// Failed (for payments)
    #[serde(rename = "failed")]
    Failed,
    /// Accepted (for hold invoices)
    #[serde(rename = "accepted")]
    Accepted,
}

/// Payment method for a transaction
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentMethod {
    /// BOLT-11 lightning invoice
    Bolt11,
    /// BOLT-12 offer/refund
    Bolt12,
    /// Keysend (spontaneous payment)
    Keysend,
    /// On-chain bitcoin transaction
    Onchain,
}

/// List Transactions Request
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ListTransactionsRequest {
    /// Starting timestamp in seconds since epoch
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<Timestamp>,
    /// Ending timestamp in seconds since epoch
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<Timestamp>,
    /// Number of invoices to return
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    /// Offset of the first invoice to return
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    /// If true, include unpaid invoices
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unpaid: Option<bool>,
    /// [`TransactionType::Incoming`] for invoices, [`TransactionType::Outgoing`] for payments, [`None`] for both
    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_type: Option<TransactionType>,
    /// Filter by payment method
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_method: Option<PaymentMethod>,
}

/// Make Hold Invoice Request
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MakeHoldInvoiceRequest {
    /// Amount in millisatoshis
    pub amount: u64,
    /// Invoice description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Invoice description hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description_hash: Option<String>,
    /// Invoice expiry in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry: Option<u64>,
    /// payment_hash
    pub payment_hash: String,
    /// The minimum CLTV delta to use for the final hop
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_cltv_expiry_delta: Option<u32>,
}

/// Cancel Hold Invoice Request
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CancelHoldInvoiceRequest {
    /// payment_hash
    pub payment_hash: String,
}

/// Settle Hold Invoice Request
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SettleHoldInvoiceRequest {
    /// preimage
    pub preimage: String,
}

/// Pay Onchain Request
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PayOnchainRequest {
    /// Bitcoin address to send to
    pub address: String,
    /// Amount in satoshis
    pub amount: u64,
    /// Optional fee rate in sat/vB
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feerate: Option<u64>,
}

/// Make New Address Request (empty — no params needed)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MakeNewAddressRequest {}

/// Pay Offer Request (BOLT-12)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PayOfferRequest {
    /// BOLT-12 offer string
    pub offer: String,
    /// Optional amount in millisatoshis (for zero-amount offers)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<u64>,
    /// Optional payer note
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer_note: Option<String>,
}

/// Make Offer Request (BOLT-12)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MakeOfferRequest {
    /// Amount in millisatoshis
    pub amount: u64,
    /// Offer description
    pub description: String,
    /// Optional expiry in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry: Option<u32>,
}

/// Lookup Offer Request
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LookupOfferRequest {
    /// BOLT-12 offer string
    pub offer: String,
}

/// Lookup Address Request
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LookupAddressRequest {
    /// Bitcoin address
    pub address: String,
}

/// List Invoices Request
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ListInvoicesRequest {
    /// Starting timestamp in seconds since epoch
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<Timestamp>,
    /// Ending timestamp in seconds since epoch
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<Timestamp>,
    /// Number of invoices to return
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    /// Offset of the first invoice to return
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    /// Filter by state: "pending", "settled", "expired"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// List Offers Request
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ListOffersRequest {
    /// If true, only return active offers
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_only: Option<bool>,
    /// Number of offers to return
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    /// Offset of the first offer to return
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
}

/// Disable Offer Request
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DisableOfferRequest {
    /// BOLT-12 offer string to disable
    pub offer: String,
}

/// List Addresses Request
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ListAddressesRequest {
    /// Number of addresses to return
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    /// Offset of the first address to return
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
}

/// Pay BIP-321 URI Request
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PayBip321Request {
    /// BIP-321 `bitcoin:` URI string
    pub uri: String,
}

/// Pay BIP-321 URI Response
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PayBip321Response {
    /// Payment preimage (for lightning payments)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preimage: Option<String>,
    /// Transaction ID (for on-chain payments)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txid: Option<String>,
    /// Fees paid in millisatoshis
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fees_paid: Option<u64>,
    /// Which payment method was used: "bolt11", "bolt12", "onchain"
    pub payment_method: String,
}

/// Method entry for make_bip321 request
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Bip321MethodEntry {
    /// Payment method name (e.g. "bolt11", "bolt12", "onchain", "sp")
    pub method: String,
    /// Optional expiry in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry: Option<u64>,
    /// Optional address type (e.g. "p2tr", "p2wpkh")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_type: Option<String>,
}

/// Make BIP-321 URI Request
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MakeBip321Request {
    /// Amount in millisatoshis
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<u64>,
    /// Label for the address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Message describing the purpose
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Which payment methods to include
    #[serde(skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<Bip321MethodEntry>>,
}

/// Make BIP-321 URI Response
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct MakeBip321Response {
    /// The generated BIP-321 `bitcoin:` URI
    pub uri: String,
}

/// BIP-321 method capability for get_info
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Bip321MethodInfo {
    /// Payment method name (e.g. "bolt11", "bolt12", "onchain", "sp")
    pub method: String,
    /// Supported address types for this method
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_types: Option<Vec<String>>,
}

/// Subscribe Notifications Request
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubscribeNotificationsRequest {
    /// Notification types to subscribe to (e.g. ["payment_received", "payment_sent"])
    pub types: Vec<String>,
}

/// Subscribe Notifications Response (empty on success)
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SubscribeNotificationsResponse {}

/// Estimate Routing Fees Request
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EstimateRoutingFeesRequest {
    /// Destination node pubkey
    pub destination: String,
    /// Payment amount in millisatoshis
    pub amount: u64,
}

/// Estimate Onchain Fees Response
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct EstimateOnchainFeesResponse {
    /// Map of confirmation target (in blocks) to estimated fee rate in sat/vbyte
    pub fees: serde_json::Map<String, Value>,
}

/// Estimate Routing Fees Response
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct EstimateRoutingFeesResponse {
    /// Estimated fee in millisatoshis
    pub fee: u64,
    /// Estimated CLTV delta
    pub time_lock_delay: u32,
}

/// NIP47 Request
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Request {
    /// Request method
    pub method: Method,
    /// Params
    pub params: RequestParams,
}

#[derive(Serialize, Deserialize)]
struct RequestTemplate {
    /// Request method
    method: Method,
    /// Params
    #[serde(default)] // handle no params as `Value::Null`
    params: Value,
}

impl Request {
    /// Compose `pay_invoice` request
    #[inline]
    pub fn pay_invoice(params: PayInvoiceRequest) -> Self {
        Self {
            method: Method::PayInvoice,
            params: RequestParams::PayInvoice(params),
        }
    }

    /// Compose `pay_keysend` request
    #[inline]
    pub fn pay_keysend(params: PayKeysendRequest) -> Self {
        Self {
            method: Method::PayKeysend,
            params: RequestParams::PayKeysend(params),
        }
    }

    /// Compose `make_invoice` request
    #[inline]
    pub fn make_invoice(params: MakeInvoiceRequest) -> Self {
        Self {
            method: Method::MakeInvoice,
            params: RequestParams::MakeInvoice(params),
        }
    }

    /// Compose `lookup_invoice` request
    #[inline]
    pub fn lookup_invoice(params: LookupInvoiceRequest) -> Self {
        Self {
            method: Method::LookupInvoice,
            params: RequestParams::LookupInvoice(params),
        }
    }

    /// Compose `list_transactions` request
    #[inline]
    pub fn list_transactions(params: ListTransactionsRequest) -> Self {
        Self {
            method: Method::ListTransactions,
            params: RequestParams::ListTransactions(params),
        }
    }

    /// Compose `get_balance` request
    #[inline]
    pub fn get_balance() -> Self {
        Self {
            method: Method::GetBalance,
            params: RequestParams::GetBalance,
        }
    }

    /// Compose `get_info` request
    #[inline]
    pub fn get_info() -> Self {
        Self {
            method: Method::GetInfo,
            params: RequestParams::GetInfo,
        }
    }

    /// Compose `pay_onchain` request
    #[inline]
    pub fn pay_onchain(params: PayOnchainRequest) -> Self {
        Self {
            method: Method::PayOnchain,
            params: RequestParams::PayOnchain(params),
        }
    }

    /// Compose `make_new_address` request
    #[inline]
    pub fn make_new_address() -> Self {
        Self {
            method: Method::MakeNewAddress,
            params: RequestParams::MakeNewAddress,
        }
    }

    /// Compose `pay_offer` request
    #[inline]
    pub fn pay_offer(params: PayOfferRequest) -> Self {
        Self {
            method: Method::PayOffer,
            params: RequestParams::PayOffer(params),
        }
    }

    /// Compose `make_offer` request
    #[inline]
    pub fn make_offer(params: MakeOfferRequest) -> Self {
        Self {
            method: Method::MakeOffer,
            params: RequestParams::MakeOffer(params),
        }
    }

    /// Compose `lookup_offer` request
    #[inline]
    pub fn lookup_offer(params: LookupOfferRequest) -> Self {
        Self {
            method: Method::LookupOffer,
            params: RequestParams::LookupOffer(params),
        }
    }

    /// Compose `lookup_address` request
    #[inline]
    pub fn lookup_address(params: LookupAddressRequest) -> Self {
        Self {
            method: Method::LookupAddress,
            params: RequestParams::LookupAddress(params),
        }
    }

    /// Compose `list_invoices` request
    #[inline]
    pub fn list_invoices(params: ListInvoicesRequest) -> Self {
        Self {
            method: Method::ListInvoices,
            params: RequestParams::ListInvoices(params),
        }
    }

    /// Compose `list_offers` request
    #[inline]
    pub fn list_offers(params: ListOffersRequest) -> Self {
        Self {
            method: Method::ListOffers,
            params: RequestParams::ListOffers(params),
        }
    }

    /// Compose `disable_offer` request
    #[inline]
    pub fn disable_offer(params: DisableOfferRequest) -> Self {
        Self {
            method: Method::DisableOffer,
            params: RequestParams::DisableOffer(params),
        }
    }

    /// Compose `list_addresses` request
    #[inline]
    pub fn list_addresses(params: ListAddressesRequest) -> Self {
        Self {
            method: Method::ListAddresses,
            params: RequestParams::ListAddresses(params),
        }
    }

    /// Compose `pay_bip321` request
    #[inline]
    pub fn pay_bip321(params: PayBip321Request) -> Self {
        Self {
            method: Method::PayBip321,
            params: RequestParams::PayBip321(params),
        }
    }

    /// Compose `make_bip321` request
    #[inline]
    pub fn make_bip321(params: MakeBip321Request) -> Self {
        Self {
            method: Method::MakeBip321,
            params: RequestParams::MakeBip321(params),
        }
    }

    /// Compose `subscribe_notifications` request
    #[inline]
    pub fn subscribe_notifications(params: SubscribeNotificationsRequest) -> Self {
        Self {
            method: Method::SubscribeNotifications,
            params: RequestParams::SubscribeNotifications(params),
        }
    }

    /// Deserialize from [`Value`]
    pub fn from_value(value: Value) -> Result<Self, Error> {
        let template: RequestTemplate = serde_json::from_value(value)?;

        let params = match template.method {
            Method::PayInvoice => {
                let params: PayInvoiceRequest = serde_json::from_value(template.params)?;
                RequestParams::PayInvoice(params)
            }
            Method::PayKeysend => {
                let params: PayKeysendRequest = serde_json::from_value(template.params)?;
                RequestParams::PayKeysend(params)
            }
            Method::MakeInvoice => {
                let params: MakeInvoiceRequest = serde_json::from_value(template.params)?;
                RequestParams::MakeInvoice(params)
            }
            Method::LookupInvoice => {
                let params: LookupInvoiceRequest = serde_json::from_value(template.params)?;
                RequestParams::LookupInvoice(params)
            }
            Method::ListTransactions => {
                let params: ListTransactionsRequest = serde_json::from_value(template.params)?;
                RequestParams::ListTransactions(params)
            }
            Method::GetBalance => RequestParams::GetBalance,
            Method::GetInfo => RequestParams::GetInfo,
            Method::MakeHoldInvoice => {
                let params: MakeHoldInvoiceRequest = serde_json::from_value(template.params)?;
                RequestParams::MakeHoldInvoice(params)
            }
            Method::SettleHoldInvoice => {
                let params: SettleHoldInvoiceRequest = serde_json::from_value(template.params)?;
                RequestParams::SettleHoldInvoice(params)
            }
            Method::CancelHoldInvoice => {
                let params: CancelHoldInvoiceRequest = serde_json::from_value(template.params)?;
                RequestParams::CancelHoldInvoice(params)
            }
            Method::PayOnchain => {
                let params: PayOnchainRequest = serde_json::from_value(template.params)?;
                RequestParams::PayOnchain(params)
            }
            Method::MakeNewAddress => RequestParams::MakeNewAddress,
            Method::PayOffer => {
                let params: PayOfferRequest = serde_json::from_value(template.params)?;
                RequestParams::PayOffer(params)
            }
            Method::MakeOffer => {
                let params: MakeOfferRequest = serde_json::from_value(template.params)?;
                RequestParams::MakeOffer(params)
            }
            Method::LookupOffer => {
                let params: LookupOfferRequest = serde_json::from_value(template.params)?;
                RequestParams::LookupOffer(params)
            }
            Method::LookupAddress => {
                let params: LookupAddressRequest = serde_json::from_value(template.params)?;
                RequestParams::LookupAddress(params)
            }
            Method::ListInvoices => {
                let params: ListInvoicesRequest = serde_json::from_value(template.params)?;
                RequestParams::ListInvoices(params)
            }
            Method::ListOffers => {
                let params: ListOffersRequest = serde_json::from_value(template.params)?;
                RequestParams::ListOffers(params)
            }
            Method::DisableOffer => {
                let params: DisableOfferRequest = serde_json::from_value(template.params)?;
                RequestParams::DisableOffer(params)
            }
            Method::ListAddresses => {
                let params: ListAddressesRequest = serde_json::from_value(template.params)?;
                RequestParams::ListAddresses(params)
            }
            Method::PayBip321 => {
                let params: PayBip321Request = serde_json::from_value(template.params)?;
                RequestParams::PayBip321(params)
            }
            Method::MakeBip321 => {
                let params: MakeBip321Request = serde_json::from_value(template.params)?;
                RequestParams::MakeBip321(params)
            }
            Method::SubscribeNotifications => {
                let params: SubscribeNotificationsRequest = serde_json::from_value(template.params)?;
                RequestParams::SubscribeNotifications(params)
            }
            Method::EstimateOnchainFees => RequestParams::EstimateOnchainFees,
            Method::EstimateRoutingFees => {
                let params: EstimateRoutingFeesRequest = serde_json::from_value(template.params)?;
                RequestParams::EstimateRoutingFees(params)
            }
            Method::Unknown(name) => {
                return Err(Error::UnsupportedMethod(Method::Unknown(name)));
            }
        };

        Ok(Self {
            method: template.method,
            params,
        })
    }

    /// Create request [Event]
    #[cfg(all(feature = "std", feature = "os-rng"))]
    pub fn to_event(self, uri: &NostrWalletConnectUri) -> Result<Event, Error> {
        let encrypted = nip04::encrypt(&uri.secret, &uri.public_key, self.as_json())?;
        let keys: Keys = Keys::new(uri.secret.clone());
        Ok(EventBuilder::new(Kind::WalletConnectRequest, encrypted)
            .tag(Tag::public_key(uri.public_key))
            .sign_with_keys(&keys)?)
    }
}

impl JsonUtil for Request {
    type Err = Error;
}

impl<'de> Deserialize<'de> for Request {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: Value = Value::deserialize(deserializer).map_err(serde::de::Error::custom)?;
        Self::from_value(value).map_err(serde::de::Error::custom)
    }
}

/// NIP47 Response Result
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PayInvoiceResponse {
    /// Response preimage
    pub preimage: String,
    /// Fees paid
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fees_paid: Option<u64>,
}

/// NIP47 Response Result
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PayKeysendResponse {
    /// Response preimage
    pub preimage: String,
    /// Fees paid
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fees_paid: Option<u64>,
}

/// Make Invoice Response
//
// NOTE: don't add `type`, `state` or `fees_paid`, as they don't make sense here.
//
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct MakeInvoiceResponse {
    /// Bolt 11 invoice
    pub invoice: String,
    /// Invoice's payment hash
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_empty_string_as_none")]
    pub payment_hash: Option<String>,
    /// Invoice's description
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_empty_string_as_none")]
    pub description: Option<String>,
    /// Invoice's description hash
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_empty_string_as_none")]
    pub description_hash: Option<String>,
    /// Payment preimage
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_empty_string_as_none")]
    pub preimage: Option<String>,
    /// Amount in msats.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<u64>,
    /// Creation timestamp in seconds since epoch
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<Timestamp>,
    /// Expiration timestamp in seconds since epoch
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
}

/// Lookup Invoice Response
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct LookupInvoiceResponse {
    /// Transaction type
    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_type: Option<TransactionType>,
    /// Transaction state
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<TransactionState>,
    /// Bolt11 invoice
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_empty_string_as_none")]
    pub invoice: Option<String>,
    /// Invoice's description
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_empty_string_as_none")]
    pub description: Option<String>,
    /// Invoice's description hash
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_empty_string_as_none")]
    pub description_hash: Option<String>,
    /// Payment preimage
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_empty_string_as_none")]
    pub preimage: Option<String>,
    /// Payment hash
    pub payment_hash: String,
    /// Amount in millisatoshis
    pub amount: u64,
    /// Fees paid in millisatoshis
    pub fees_paid: u64,
    /// Creation timestamp in seconds since epoch, optional if unknown
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<Timestamp>,
    /// Expiration timestamp in seconds since epoch
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
    /// Settled timestamp in seconds since epoch
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settled_at: Option<Timestamp>,
    /// Optional metadata about the payment
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    /// Payment method used
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_method: Option<PaymentMethod>,
}

/// Get Balance Response
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct GetBalanceResponse {
    /// Balance amount in msats
    pub balance: u64,
    /// Lightning balance in msats
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lightning_balance: Option<u64>,
    /// On-chain balance in msats
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onchain_balance: Option<u64>,
}

/// Get Info Response
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct GetInfoResponse {
    /// The alias of the lightning node
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_empty_string_as_none")]
    pub alias: Option<String>,
    /// The color of the current node in hex code format
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_empty_string_as_none")]
    pub color: Option<String>,
    /// Lightning Node's public key
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_empty_string_as_none")]
    pub pubkey: Option<String>,
    /// Active network
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_empty_string_as_none")]
    pub network: Option<String>,
    /// Current block height
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_height: Option<u32>,
    /// Most Recent Block Hash
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_empty_string_as_none")]
    pub block_hash: Option<String>,
    /// Available methods for this connection
    pub methods: Vec<Method>,
    /// List of supported notifications for this connection (optional)
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notifications: Vec<String>,
    /// BIP-321 payment methods supported by this wallet
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bip321_methods: Option<Vec<Bip321MethodInfo>>,
}

/// Make Hold Invoice Response
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct MakeHoldInvoiceResponse {
    /// Transaction type
    #[serde(rename = "type")]
    pub transaction_type: TransactionType,
    /// Bolt11 invoice
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_empty_string_as_none")]
    pub invoice: Option<String>,
    /// Description
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_empty_string_as_none")]
    pub description: Option<String>,
    /// Description hash
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_empty_string_as_none")]
    pub description_hash: Option<String>,
    /// Payment hash
    pub payment_hash: String,
    /// Amount in millisatoshis
    pub amount: u64,
    /// Creation timestamp
    pub created_at: Timestamp,
    /// Expiration timestamp
    pub expires_at: Timestamp,
    /// Metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// Cancel Hold Invoice Response
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CancelHoldInvoiceResponse {}

/// Settle Hold Invoice Response
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SettleHoldInvoiceResponse {}

/// Pay Onchain Response
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PayOnchainResponse {
    /// Transaction ID
    pub txid: String,
}

/// Make New Address Response
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct MakeNewAddressResponse {
    /// Bitcoin address
    pub address: String,
}

/// Pay Offer Response (BOLT-12)
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PayOfferResponse {
    /// Payment preimage
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preimage: Option<String>,
    /// Fees paid in millisatoshis
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fees_paid: Option<u64>,
}

/// Make Offer Response (BOLT-12)
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct MakeOfferResponse {
    /// BOLT-12 offer string
    pub offer: String,
    /// Offer description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Amount in millisatoshis
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<u64>,
}

/// Lookup Offer Response
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct LookupOfferResponse {
    /// BOLT-12 offer string
    pub offer: String,
    /// Offer description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Amount in millisatoshis
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<u64>,
    /// Whether the offer is still active
    pub active: bool,
    /// Number of payments received via this offer
    pub num_payments_received: u64,
    /// Total amount received in millisatoshis
    pub total_received: u64,
}

/// Address Transaction Info
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AddressTransaction {
    /// Transaction ID
    pub txid: String,
    /// Amount in satoshis
    pub amount: u64,
    /// Timestamp in seconds since epoch
    pub timestamp: Timestamp,
}

/// Lookup Address Response
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct LookupAddressResponse {
    /// Bitcoin address
    pub address: String,
    /// Total received in satoshis
    pub total_received: u64,
    /// Transactions for this address
    pub transactions: Vec<AddressTransaction>,
}

/// List Invoices Response
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ListInvoicesResponse {
    /// List of invoices
    pub invoices: Vec<InvoiceEntry>,
}

/// Invoice Entry
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct InvoiceEntry {
    /// Bolt11 invoice
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invoice: Option<String>,
    /// Invoice description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Payment hash
    pub payment_hash: String,
    /// Amount in millisatoshis
    pub amount: u64,
    /// State: "pending", "settled", "expired"
    pub state: String,
    /// Payment preimage
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preimage: Option<String>,
    /// Creation timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<Timestamp>,
    /// Expiration timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
    /// Settlement timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settled_at: Option<Timestamp>,
}

/// List Offers Response
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ListOffersResponse {
    /// List of offers
    pub offers: Vec<OfferEntry>,
}

/// Offer Entry
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct OfferEntry {
    /// BOLT-12 offer string
    pub offer: String,
    /// Offer description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Amount in millisatoshis
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<u64>,
    /// Whether the offer is active
    pub active: bool,
    /// Number of payments received via this offer
    pub num_payments_received: u64,
    /// Total amount received in millisatoshis
    pub total_received: u64,
}

/// Disable Offer Response
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DisableOfferResponse {}

/// List Addresses Response
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ListAddressesResponse {
    /// List of addresses
    pub addresses: Vec<AddressEntry>,
}

/// Address Entry
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct AddressEntry {
    /// Bitcoin address
    pub address: String,
    /// Total received in satoshis
    pub total_received: u64,
}

/// NIP47 Response Result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseResult {
    /// Pay Invoice
    PayInvoice(PayInvoiceResponse),
    /// Pay Keysend
    PayKeysend(PayKeysendResponse),
    /// Make Invoice
    MakeInvoice(MakeInvoiceResponse),
    /// Lookup Invoice
    LookupInvoice(LookupInvoiceResponse),
    /// List Invoices
    ListTransactions(Vec<LookupInvoiceResponse>),
    /// Get Balance
    GetBalance(GetBalanceResponse),
    /// Get Info
    GetInfo(GetInfoResponse),
    /// Make Hold Invoice
    MakeHoldInvoice(MakeHoldInvoiceResponse),
    /// Cancel Hold Invoice
    CancelHoldInvoice(CancelHoldInvoiceResponse),
    /// Settle Hold Invoice
    SettleHoldInvoice(SettleHoldInvoiceResponse),
    /// Pay Onchain
    PayOnchain(PayOnchainResponse),
    /// Make New Address
    MakeNewAddress(MakeNewAddressResponse),
    /// Pay Offer (BOLT-12)
    PayOffer(PayOfferResponse),
    /// Make Offer (BOLT-12)
    MakeOffer(MakeOfferResponse),
    /// Lookup Offer
    LookupOffer(LookupOfferResponse),
    /// Lookup Address
    LookupAddress(LookupAddressResponse),
    /// List Invoices
    ListInvoices(ListInvoicesResponse),
    /// List Offers
    ListOffers(ListOffersResponse),
    /// Disable Offer
    DisableOffer(DisableOfferResponse),
    /// List Addresses
    ListAddresses(ListAddressesResponse),
    /// Pay BIP-321 URI
    PayBip321(PayBip321Response),
    /// Make BIP-321 URI
    MakeBip321(MakeBip321Response),
    /// Subscribe Notifications
    SubscribeNotifications(SubscribeNotificationsResponse),
    /// Estimate On-chain Fees
    EstimateOnchainFees(EstimateOnchainFeesResponse),
    /// Estimate Routing Fees
    EstimateRoutingFees(EstimateRoutingFeesResponse),
}

impl Serialize for ResponseResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            ResponseResult::PayInvoice(p) => p.serialize(serializer),
            ResponseResult::PayKeysend(p) => p.serialize(serializer),
            ResponseResult::MakeInvoice(p) => p.serialize(serializer),
            ResponseResult::LookupInvoice(p) => p.serialize(serializer),
            ResponseResult::ListTransactions(p) => {
                let mut state = serializer.serialize_struct("ListTransactions", 1)?;
                state.serialize_field("transactions", p)?;
                state.end()
            }
            ResponseResult::GetBalance(p) => p.serialize(serializer),
            ResponseResult::GetInfo(p) => p.serialize(serializer),
            ResponseResult::MakeHoldInvoice(p) => p.serialize(serializer),
            ResponseResult::CancelHoldInvoice(p) => p.serialize(serializer),
            ResponseResult::SettleHoldInvoice(p) => p.serialize(serializer),
            ResponseResult::PayOnchain(p) => p.serialize(serializer),
            ResponseResult::MakeNewAddress(p) => p.serialize(serializer),
            ResponseResult::PayOffer(p) => p.serialize(serializer),
            ResponseResult::MakeOffer(p) => p.serialize(serializer),
            ResponseResult::LookupOffer(p) => p.serialize(serializer),
            ResponseResult::LookupAddress(p) => p.serialize(serializer),
            ResponseResult::ListInvoices(p) => p.serialize(serializer),
            ResponseResult::ListOffers(p) => p.serialize(serializer),
            ResponseResult::DisableOffer(p) => p.serialize(serializer),
            ResponseResult::ListAddresses(p) => p.serialize(serializer),
            ResponseResult::PayBip321(p) => p.serialize(serializer),
            ResponseResult::MakeBip321(p) => p.serialize(serializer),
            ResponseResult::SubscribeNotifications(p) => p.serialize(serializer),
            ResponseResult::EstimateOnchainFees(p) => p.serialize(serializer),
            ResponseResult::EstimateRoutingFees(p) => p.serialize(serializer),
        }
    }
}

/// NIP47 Response
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Response {
    /// Request Method
    pub result_type: Method,
    /// NIP47 Error
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<NIP47Error>,
    /// NIP47 Result
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<ResponseResult>,
}

/// NIP47 Response
#[derive(Debug, Clone, Deserialize)]
struct ResponseTemplate {
    /// Request Method
    pub result_type: Method,
    /// NIP47 Error
    pub error: Option<NIP47Error>,
    /// NIP47 Result
    pub result: Option<Value>,
}

impl Response {
    /// Deserialize from [Event]
    #[inline]
    pub fn from_event(uri: &NostrWalletConnectUri, event: &Event) -> Result<Self, Error> {
        let decrypt_res: String = nip04::decrypt(&uri.secret, &event.pubkey, &event.content)?;
        Self::from_json(&decrypt_res).map_err(|e| Error::CantDeserializeResponse {
            response: decrypt_res,
            error: e.to_string(),
        })
    }

    /// Deserialize from JSON string
    pub fn from_value(value: Value) -> Result<Self, Error> {
        let template: ResponseTemplate = serde_json::from_value(value)?;

        if let Some(result) = template.result {
            let result = match template.result_type {
                Method::PayInvoice => {
                    let result: PayInvoiceResponse = serde_json::from_value(result)?;
                    ResponseResult::PayInvoice(result)
                }
                Method::PayKeysend => {
                    let result: PayKeysendResponse = serde_json::from_value(result)?;
                    ResponseResult::PayKeysend(result)
                }
                Method::MakeInvoice => {
                    let result: MakeInvoiceResponse = serde_json::from_value(result)?;
                    ResponseResult::MakeInvoice(result)
                }
                Method::LookupInvoice => {
                    let result: LookupInvoiceResponse = serde_json::from_value(result)?;
                    ResponseResult::LookupInvoice(result)
                }
                Method::ListTransactions => {
                    let transactions: Value = result
                        .get("transactions")
                        .cloned()
                        .ok_or(Error::UnexpectedResult)?;
                    let result: Vec<LookupInvoiceResponse> = serde_json::from_value(transactions)?;
                    ResponseResult::ListTransactions(result)
                }
                Method::GetBalance => {
                    let result: GetBalanceResponse = serde_json::from_value(result)?;
                    ResponseResult::GetBalance(result)
                }
                Method::GetInfo => {
                    let result: GetInfoResponse = serde_json::from_value(result)?;
                    ResponseResult::GetInfo(result)
                }
                Method::MakeHoldInvoice => {
                    let result: MakeHoldInvoiceResponse = serde_json::from_value(result)?;
                    ResponseResult::MakeHoldInvoice(result)
                }
                Method::CancelHoldInvoice => {
                    let result: CancelHoldInvoiceResponse = serde_json::from_value(result)?;
                    ResponseResult::CancelHoldInvoice(result)
                }
                Method::SettleHoldInvoice => {
                    let result: SettleHoldInvoiceResponse = serde_json::from_value(result)?;
                    ResponseResult::SettleHoldInvoice(result)
                }
                Method::PayOnchain => {
                    let result: PayOnchainResponse = serde_json::from_value(result)?;
                    ResponseResult::PayOnchain(result)
                }
                Method::MakeNewAddress => {
                    let result: MakeNewAddressResponse = serde_json::from_value(result)?;
                    ResponseResult::MakeNewAddress(result)
                }
                Method::PayOffer => {
                    let result: PayOfferResponse = serde_json::from_value(result)?;
                    ResponseResult::PayOffer(result)
                }
                Method::MakeOffer => {
                    let result: MakeOfferResponse = serde_json::from_value(result)?;
                    ResponseResult::MakeOffer(result)
                }
                Method::LookupOffer => {
                    let result: LookupOfferResponse = serde_json::from_value(result)?;
                    ResponseResult::LookupOffer(result)
                }
                Method::LookupAddress => {
                    let result: LookupAddressResponse = serde_json::from_value(result)?;
                    ResponseResult::LookupAddress(result)
                }
                Method::ListInvoices => {
                    let result: ListInvoicesResponse = serde_json::from_value(result)?;
                    ResponseResult::ListInvoices(result)
                }
                Method::ListOffers => {
                    let result: ListOffersResponse = serde_json::from_value(result)?;
                    ResponseResult::ListOffers(result)
                }
                Method::DisableOffer => {
                    let result: DisableOfferResponse = serde_json::from_value(result)?;
                    ResponseResult::DisableOffer(result)
                }
                Method::ListAddresses => {
                    let result: ListAddressesResponse = serde_json::from_value(result)?;
                    ResponseResult::ListAddresses(result)
                }
                Method::PayBip321 => {
                    let result: PayBip321Response = serde_json::from_value(result)?;
                    ResponseResult::PayBip321(result)
                }
                Method::MakeBip321 => {
                    let result: MakeBip321Response = serde_json::from_value(result)?;
                    ResponseResult::MakeBip321(result)
                }
                Method::SubscribeNotifications => {
                    let result: SubscribeNotificationsResponse = serde_json::from_value(result)?;
                    ResponseResult::SubscribeNotifications(result)
                }
                Method::EstimateOnchainFees => {
                    let result: EstimateOnchainFeesResponse = serde_json::from_value(result)?;
                    ResponseResult::EstimateOnchainFees(result)
                }
                Method::EstimateRoutingFees => {
                    let result: EstimateRoutingFeesResponse = serde_json::from_value(result)?;
                    ResponseResult::EstimateRoutingFees(result)
                }
                Method::Unknown(name) => {
                    return Err(Error::UnsupportedMethod(Method::Unknown(name)));
                }
            };

            Ok(Self {
                result_type: template.result_type,
                error: template.error,
                result: Some(result),
            })
        } else {
            Ok(Self {
                result_type: template.result_type,
                error: template.error,
                result: None,
            })
        }
    }

    /// Covert [Response] to [PayInvoiceResponse]
    pub fn to_pay_invoice(self) -> Result<PayInvoiceResponse, Error> {
        if let Some(e) = self.error {
            return Err(Error::ErrorCode(e));
        }

        if let Some(ResponseResult::PayInvoice(result)) = self.result {
            return Ok(result);
        }

        Err(Error::UnexpectedResult)
    }

    /// Covert [Response] to [PayKeysendResponse]
    pub fn to_pay_keysend(self) -> Result<PayKeysendResponse, Error> {
        if let Some(e) = self.error {
            return Err(Error::ErrorCode(e));
        }

        if let Some(ResponseResult::PayKeysend(result)) = self.result {
            return Ok(result);
        }

        Err(Error::UnexpectedResult)
    }

    /// Covert [Response] to [MakeInvoiceResponse]
    pub fn to_make_invoice(self) -> Result<MakeInvoiceResponse, Error> {
        if let Some(e) = self.error {
            return Err(Error::ErrorCode(e));
        }

        if let Some(ResponseResult::MakeInvoice(result)) = self.result {
            return Ok(result);
        }

        Err(Error::UnexpectedResult)
    }

    /// Covert [Response] to [LookupInvoiceResponse]
    pub fn to_lookup_invoice(self) -> Result<LookupInvoiceResponse, Error> {
        if let Some(e) = self.error {
            return Err(Error::ErrorCode(e));
        }

        if let Some(ResponseResult::LookupInvoice(result)) = self.result {
            return Ok(result);
        }

        Err(Error::UnexpectedResult)
    }

    /// Covert [Response] to list of [LookupInvoiceResponse]
    pub fn to_list_transactions(self) -> Result<Vec<LookupInvoiceResponse>, Error> {
        if let Some(e) = self.error {
            return Err(Error::ErrorCode(e));
        }

        if let Some(ResponseResult::ListTransactions(result)) = self.result {
            return Ok(result);
        }

        Err(Error::UnexpectedResult)
    }

    /// Covert [Response] to [GetBalanceResponse]
    pub fn to_get_balance(self) -> Result<GetBalanceResponse, Error> {
        if let Some(e) = self.error {
            return Err(Error::ErrorCode(e));
        }

        if let Some(ResponseResult::GetBalance(result)) = self.result {
            return Ok(result);
        }

        Err(Error::UnexpectedResult)
    }

    /// Covert [Response] to [GetInfoResponse]
    pub fn to_get_info(self) -> Result<GetInfoResponse, Error> {
        if let Some(e) = self.error {
            return Err(Error::ErrorCode(e));
        }

        if let Some(ResponseResult::GetInfo(result)) = self.result {
            return Ok(result);
        }

        Err(Error::UnexpectedResult)
    }

    /// Convert [Response] to [PayOnchainResponse]
    pub fn to_pay_onchain(self) -> Result<PayOnchainResponse, Error> {
        if let Some(e) = self.error {
            return Err(Error::ErrorCode(e));
        }

        if let Some(ResponseResult::PayOnchain(result)) = self.result {
            return Ok(result);
        }

        Err(Error::UnexpectedResult)
    }

    /// Convert [Response] to [MakeNewAddressResponse]
    pub fn to_make_new_address(self) -> Result<MakeNewAddressResponse, Error> {
        if let Some(e) = self.error {
            return Err(Error::ErrorCode(e));
        }

        if let Some(ResponseResult::MakeNewAddress(result)) = self.result {
            return Ok(result);
        }

        Err(Error::UnexpectedResult)
    }

    /// Convert [Response] to [PayOfferResponse]
    pub fn to_pay_offer(self) -> Result<PayOfferResponse, Error> {
        if let Some(e) = self.error {
            return Err(Error::ErrorCode(e));
        }

        if let Some(ResponseResult::PayOffer(result)) = self.result {
            return Ok(result);
        }

        Err(Error::UnexpectedResult)
    }

    /// Convert [Response] to [MakeOfferResponse]
    pub fn to_make_offer(self) -> Result<MakeOfferResponse, Error> {
        if let Some(e) = self.error {
            return Err(Error::ErrorCode(e));
        }

        if let Some(ResponseResult::MakeOffer(result)) = self.result {
            return Ok(result);
        }

        Err(Error::UnexpectedResult)
    }

    /// Convert [Response] to [LookupOfferResponse]
    pub fn to_lookup_offer(self) -> Result<LookupOfferResponse, Error> {
        if let Some(e) = self.error {
            return Err(Error::ErrorCode(e));
        }

        if let Some(ResponseResult::LookupOffer(result)) = self.result {
            return Ok(result);
        }

        Err(Error::UnexpectedResult)
    }

    /// Convert [Response] to [SubscribeNotificationsResponse]
    pub fn to_subscribe_notifications(self) -> Result<SubscribeNotificationsResponse, Error> {
        if let Some(e) = self.error {
            return Err(Error::ErrorCode(e));
        }

        if let Some(ResponseResult::SubscribeNotifications(result)) = self.result {
            return Ok(result);
        }

        Err(Error::UnexpectedResult)
    }

    /// Convert [Response] to [PayBip321Response]
    pub fn to_pay_bip321(self) -> Result<PayBip321Response, Error> {
        if let Some(e) = self.error {
            return Err(Error::ErrorCode(e));
        }

        if let Some(ResponseResult::PayBip321(result)) = self.result {
            return Ok(result);
        }

        Err(Error::UnexpectedResult)
    }

    /// Convert [Response] to [LookupAddressResponse]
    pub fn to_lookup_address(self) -> Result<LookupAddressResponse, Error> {
        if let Some(e) = self.error {
            return Err(Error::ErrorCode(e));
        }

        if let Some(ResponseResult::LookupAddress(result)) = self.result {
            return Ok(result);
        }

        Err(Error::UnexpectedResult)
    }

    /// Convert [Response] to [ListInvoicesResponse]
    pub fn to_list_invoices(self) -> Result<ListInvoicesResponse, Error> {
        if let Some(e) = self.error {
            return Err(Error::ErrorCode(e));
        }

        if let Some(ResponseResult::ListInvoices(result)) = self.result {
            return Ok(result);
        }

        Err(Error::UnexpectedResult)
    }

    /// Convert [Response] to [ListOffersResponse]
    pub fn to_list_offers(self) -> Result<ListOffersResponse, Error> {
        if let Some(e) = self.error {
            return Err(Error::ErrorCode(e));
        }

        if let Some(ResponseResult::ListOffers(result)) = self.result {
            return Ok(result);
        }

        Err(Error::UnexpectedResult)
    }

    /// Convert [Response] to [DisableOfferResponse]
    pub fn to_disable_offer(self) -> Result<DisableOfferResponse, Error> {
        if let Some(e) = self.error {
            return Err(Error::ErrorCode(e));
        }

        if let Some(ResponseResult::DisableOffer(result)) = self.result {
            return Ok(result);
        }

        Err(Error::UnexpectedResult)
    }

    /// Convert [Response] to [ListAddressesResponse]
    pub fn to_list_addresses(self) -> Result<ListAddressesResponse, Error> {
        if let Some(e) = self.error {
            return Err(Error::ErrorCode(e));
        }

        if let Some(ResponseResult::ListAddresses(result)) = self.result {
            return Ok(result);
        }

        Err(Error::UnexpectedResult)
    }
}

impl JsonUtil for Response {
    type Err = Error;
}

impl<'de> Deserialize<'de> for Response {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: Value = Value::deserialize(deserializer).map_err(serde::de::Error::custom)?;
        Self::from_value(value).map_err(serde::de::Error::custom)
    }
}

#[inline]
fn url_encode<T>(data: T) -> String
where
    T: AsRef<[u8]>,
{
    byte_serialize(data.as_ref()).collect()
}

/// NIP47 URI Scheme
pub const NOSTR_WALLET_CONNECT_URI_SCHEME: &str = "nostr+walletconnect";

#[allow(missing_docs)]
#[deprecated(since = "0.45.0", note = "Use NostrWalletConnectUri instead")]
pub type NostrWalletConnectURI = NostrWalletConnectUri;

/// Nostr Connect URI
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NostrWalletConnectUri {
    /// App Pubkey
    pub public_key: PublicKey,
    /// URL of the relay of choice where the `App` is connected and the `Signer` must send and listen for messages.
    pub relays: Vec<RelayUrl>,
    /// 32-byte randomly generated hex encoded string
    pub secret: SecretKey,
    /// A lightning address that clients can use to automatically setup the lud16 field on the user's profile if they have none configured.
    pub lud16: Option<String>,
}

impl NostrWalletConnectUri {
    /// Create a new URI
    #[inline]
    pub fn new(
        public_key: PublicKey,
        relays: Vec<RelayUrl>,
        random_secret_key: SecretKey,
        lud16: Option<String>,
    ) -> Self {
        Self {
            public_key,
            relays,
            secret: random_secret_key,
            lud16,
        }
    }

    /// Parse NWC URI
    pub fn parse<S>(uri: S) -> Result<Self, Error>
    where
        S: AsRef<str>,
    {
        let url: Url = Url::parse(uri.as_ref()).map_err(|_| Error::InvalidURI)?;

        if url.scheme() != NOSTR_WALLET_CONNECT_URI_SCHEME {
            return Err(Error::InvalidURI);
        }

        if let Some(pubkey) = url.domain() {
            let public_key = PublicKey::from_hex(pubkey).map_err(|_| Error::InvalidURI)?;

            let mut relays: Vec<RelayUrl> = Vec::new();
            let mut secret: Option<SecretKey> = None;
            let mut lud16: Option<String> = None;

            for (key, value) in url.query_pairs() {
                match key {
                    Cow::Borrowed("relay") => {
                        if let Ok(relay_url) = RelayUrl::parse(value.as_ref()) {
                            relays.push(relay_url);
                        }
                    }
                    Cow::Borrowed("secret") => {
                        secret = SecretKey::from_hex(value.as_ref()).ok();
                    }
                    Cow::Borrowed("lud16") => {
                        lud16 = Some(value.to_string());
                    }
                    _ => (),
                }
            }

            // If relays aren't empty and the secret is set, return
            if let (false, Some(secret)) = (relays.is_empty(), secret) {
                return Ok(Self {
                    public_key,
                    relays,
                    secret,
                    lud16,
                });
            }
        }

        Err(Error::InvalidURI)
    }
}

impl FromStr for NostrWalletConnectUri {
    type Err = Error;

    fn from_str(uri: &str) -> Result<Self, Self::Err> {
        Self::parse(uri)
    }
}

impl fmt::Display for NostrWalletConnectUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut relays_str: String = String::new();

        for relay_url in self.relays.iter() {
            // trailing slash is removed, this breaks some clients
            let relay_url: &str = relay_url.as_str_without_trailing_slash();

            relays_str.push_str("&relay=");
            relays_str.push_str(&url_encode(relay_url));
        }

        write!(
            f,
            "{NOSTR_WALLET_CONNECT_URI_SCHEME}://{}?secret={}{relays_str}",
            self.public_key,
            self.secret.to_secret_hex(),
        )?;
        if let Some(lud16) = &self.lud16 {
            write!(f, "&lud16={}", url_encode(lud16))?;
        }
        Ok(())
    }
}

impl Serialize for NostrWalletConnectUri {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'a> Deserialize<'a> for NostrWalletConnectUri {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        let uri: String = String::deserialize(deserializer)?;
        Self::from_str(&uri).map_err(serde::de::Error::custom)
    }
}

/// NIP-47 NotificationType
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum NotificationType {
    /// A payment was successfully received by the wallet
    #[serde(rename = "payment_received")]
    PaymentReceived,
    /// A payment was successfully sent by the wallet
    #[serde(rename = "payment_sent")]
    PaymentSent,
    /// A hold invoice has enough funds locked
    #[serde(rename = "hold_invoice_accepted")]
    HoldInvoiceAccepted,
}

impl fmt::Display for NotificationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NotificationType::PaymentReceived => write!(f, "payment_received"),
            NotificationType::PaymentSent => write!(f, "payment_sent"),
            NotificationType::HoldInvoiceAccepted => write!(f, "hold_invoice_accepted"),
        }
    }
}

impl FromStr for NotificationType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "payment_received" => Ok(NotificationType::PaymentReceived),
            "payment_sent" => Ok(NotificationType::PaymentSent),
            "hold_invoice_accepted" => Ok(NotificationType::HoldInvoiceAccepted),
            _ => Err(Error::InvalidURI),
        }
    }
}

/// NIP-47 Notification
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Notification {
    /// Notification type
    pub notification_type: NotificationType,
    /// Notification result
    pub notification: NotificationResult,
}

/// NIP-47 Notification
#[derive(Debug, Clone, Deserialize)]
pub struct NotificationTemplate {
    /// Notification type
    pub notification_type: NotificationType,
    /// Notification result
    pub notification: Value,
}

impl Notification {
    /// Deserialize from [Event]
    #[inline]
    pub fn from_event(uri: &NostrWalletConnectUri, event: &Event) -> Result<Self, Error> {
        let decrypt_res: String = nip04::decrypt(&uri.secret, &event.pubkey, &event.content)?;
        Self::from_json(decrypt_res)
    }

    /// Deserialize from JSON string
    pub fn from_value(value: Value) -> Result<Self, Error> {
        let template: NotificationTemplate = serde_json::from_value(value)?;

        let result = template.notification;
        let result = match template.notification_type {
            NotificationType::PaymentReceived => {
                let result: PaymentNotification = serde_json::from_value(result)?;
                NotificationResult::PaymentReceived(result)
            }
            NotificationType::PaymentSent => {
                let result: PaymentNotification = serde_json::from_value(result)?;
                NotificationResult::PaymentSent(result)
            }
            NotificationType::HoldInvoiceAccepted => {
                let result: HoldInvoiceAcceptedNotification = serde_json::from_value(result)?;
                NotificationResult::HoldInvoiceAccepted(result)
            }
        };

        Ok(Self {
            notification_type: template.notification_type,
            notification: result,
        })
    }

    /// Convert [Notification] to [PaymentNotification]
    pub fn to_pay_notification(self) -> Result<PaymentNotification, Error> {
        if let NotificationResult::PaymentReceived(result) = self.notification {
            return Ok(result);
        }
        if let NotificationResult::PaymentSent(result) = self.notification {
            return Ok(result);
        }

        Err(Error::UnexpectedResult)
    }

    /// Convert [Notification] to [HoldInvoiceAcceptedNotification]
    pub fn to_holdinvoice_accepted_notification(
        self,
    ) -> Result<HoldInvoiceAcceptedNotification, Error> {
        if let NotificationResult::HoldInvoiceAccepted(result) = self.notification {
            return Ok(result);
        }

        Err(Error::UnexpectedResult)
    }
}

impl JsonUtil for Notification {
    type Err = Error;
}

impl<'de> Deserialize<'de> for Notification {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: Value = Value::deserialize(deserializer).map_err(serde::de::Error::custom)?;
        Self::from_value(value).map_err(serde::de::Error::custom)
    }
}

/// NIP47 Notification Result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotificationResult {
    /// Payment received
    PaymentReceived(PaymentNotification),
    /// Payment sent
    PaymentSent(PaymentNotification),
    /// Hold invoice accepted (locked in)
    HoldInvoiceAccepted(HoldInvoiceAcceptedNotification),
}

impl Serialize for NotificationResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            NotificationResult::PaymentReceived(p) => p.serialize(serializer),
            NotificationResult::PaymentSent(p) => p.serialize(serializer),
            NotificationResult::HoldInvoiceAccepted(p) => p.serialize(serializer),
        }
    }
}

/// NIP-47 payment notification
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PaymentNotification {
    /// Transaction type
    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_type: Option<TransactionType>,
    /// Transaction state
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<TransactionState>,
    /// Bolt11 invoice
    pub invoice: String,
    /// Invoice's description
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_empty_string_as_none")]
    pub description: Option<String>,
    /// Invoice's description hash
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_empty_string_as_none")]
    pub description_hash: Option<String>,
    /// Payment preimage
    pub preimage: String,
    /// Payment hash
    pub payment_hash: String,
    /// Amount in millisatoshis
    pub amount: u64,
    /// Fees paid in millisatoshis
    pub fees_paid: u64,
    /// Creation timestamp in seconds since epoch, optional if unknown
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<Timestamp>,
    /// Expiration timestamp in seconds since epoch
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
    /// Settled timestamp in seconds since epoch
    pub settled_at: Timestamp,
    /// Optional metadata about the payment
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// Hold Invoice accepted notification
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct HoldInvoiceAcceptedNotification {
    /// Transaction type
    #[serde(rename = "type")]
    pub transaction_type: TransactionType,
    /// Transaction state
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<TransactionState>,
    /// Bolt11 invoice
    pub invoice: String,
    /// Description
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_empty_string_as_none")]
    pub description: Option<String>,
    /// Description hash
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_empty_string_as_none")]
    pub description_hash: Option<String>,
    /// Payment hash
    pub payment_hash: String,
    /// Amount in millisatoshis
    pub amount: u64,
    /// Creation timestamp
    pub created_at: Timestamp,
    /// Expiration timestamp
    pub expires_at: Timestamp,
    /// Settled deadline in blockheight
    pub settle_deadline: u32,
    /// Optional metadata about the payment
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// NNC (Nostr Node Control) notification type
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum NncNotificationType {
    /// A channel has been opened and is ready
    #[serde(rename = "channel_opened")]
    ChannelOpened,
    /// A channel has been closed
    #[serde(rename = "channel_closed")]
    ChannelClosed,
}

impl fmt::Display for NncNotificationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NncNotificationType::ChannelOpened => write!(f, "channel_opened"),
            NncNotificationType::ChannelClosed => write!(f, "channel_closed"),
        }
    }
}

impl FromStr for NncNotificationType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "channel_opened" => Ok(NncNotificationType::ChannelOpened),
            "channel_closed" => Ok(NncNotificationType::ChannelClosed),
            _ => Err(Error::InvalidURI),
        }
    }
}

/// NNC channel opened notification
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChannelOpenedNotification {
    /// Channel ID
    pub id: String,
    /// Short channel ID (block x tx x vout format)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_channel_id: Option<String>,
    /// Counterparty node public key
    pub peer_pubkey: String,
    /// Channel capacity in millisatoshis
    pub capacity: u64,
    /// Local balance in millisatoshis
    pub local_balance: u64,
    /// Remote balance in millisatoshis
    pub remote_balance: u64,
    /// Funding transaction ID
    pub funding_txid: String,
    /// Whether the channel is private (unannounced)
    pub is_private: bool,
}

/// NNC channel closed notification
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChannelClosedNotification {
    /// Channel ID
    pub id: String,
    /// Short channel ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_channel_id: Option<String>,
    /// Counterparty node public key
    pub peer_pubkey: String,
    /// Channel capacity in millisatoshis
    pub capacity: u64,
    /// Closing transaction ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closing_txid: Option<String>,
    /// Close type: "cooperative", "force", or "unknown"
    pub close_type: String,
}

/// NNC notification result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NncNotificationResult {
    /// Channel opened
    ChannelOpened(ChannelOpenedNotification),
    /// Channel closed
    ChannelClosed(ChannelClosedNotification),
}

impl Serialize for NncNotificationResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            NncNotificationResult::ChannelOpened(p) => p.serialize(serializer),
            NncNotificationResult::ChannelClosed(p) => p.serialize(serializer),
        }
    }
}

/// NNC notification (wrapper with type + result)
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NncNotification {
    /// Notification type
    pub notification_type: NncNotificationType,
    /// Notification result
    pub notification: NncNotificationResult,
}

/// NNC Notification deserialization template
#[derive(Debug, Clone, Deserialize)]
struct NncNotificationTemplate {
    /// Notification type
    pub notification_type: NncNotificationType,
    /// Notification result
    pub notification: Value,
}

impl NncNotification {
    /// Deserialize from JSON [`Value`]
    pub fn from_value(value: Value) -> Result<Self, Error> {
        let template: NncNotificationTemplate = serde_json::from_value(value)?;

        let result = template.notification;
        let result = match template.notification_type {
            NncNotificationType::ChannelOpened => {
                let result: ChannelOpenedNotification = serde_json::from_value(result)?;
                NncNotificationResult::ChannelOpened(result)
            }
            NncNotificationType::ChannelClosed => {
                let result: ChannelClosedNotification = serde_json::from_value(result)?;
                NncNotificationResult::ChannelClosed(result)
            }
        };

        Ok(Self {
            notification_type: template.notification_type,
            notification: result,
        })
    }

    /// Convert [NncNotification] to [ChannelOpenedNotification]
    pub fn to_channel_opened(self) -> Result<ChannelOpenedNotification, Error> {
        if let NncNotificationResult::ChannelOpened(result) = self.notification {
            return Ok(result);
        }
        Err(Error::UnexpectedResult)
    }

    /// Convert [NncNotification] to [ChannelClosedNotification]
    pub fn to_channel_closed(self) -> Result<ChannelClosedNotification, Error> {
        if let NncNotificationResult::ChannelClosed(result) = self.notification {
            return Ok(result);
        }
        Err(Error::UnexpectedResult)
    }
}

impl JsonUtil for NncNotification {
    type Err = Error;
}

impl<'de> Deserialize<'de> for NncNotification {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: Value = Value::deserialize(deserializer).map_err(serde::de::Error::custom)?;
        Self::from_value(value).map_err(serde::de::Error::custom)
    }
}

fn deserialize_empty_string_as_none<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: fmt::Display,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    match opt {
        Some(s) if s.is_empty() => Ok(None),
        Some(s) => T::from_str(&s).map(Some).map_err(serde::de::Error::custom),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;

    #[test]
    fn test_method_eq() {
        assert_eq!(Method::GetBalance, Method::GetBalance);

        assert_eq!(
            Method::PayInvoice,
            Method::Unknown(String::from("pay_invoice"))
        );
        assert_eq!(
            Method::PayKeysend,
            Method::Unknown(String::from("pay_keysend"))
        );
        assert_eq!(
            Method::MakeInvoice,
            Method::Unknown(String::from("make_invoice"))
        );
        assert_eq!(
            Method::LookupInvoice,
            Method::Unknown(String::from("lookup_invoice"))
        );
        assert_eq!(
            Method::ListTransactions,
            Method::Unknown(String::from("list_transactions"))
        );
        assert_eq!(
            Method::GetBalance,
            Method::Unknown(String::from("get_balance"))
        );
        assert_eq!(Method::GetInfo, Method::Unknown(String::from("get_info")));
        assert_eq!(
            Method::MakeHoldInvoice,
            Method::Unknown(String::from("make_hold_invoice"))
        );
        assert_eq!(
            Method::CancelHoldInvoice,
            Method::Unknown(String::from("cancel_hold_invoice"))
        );
        assert_eq!(
            Method::SettleHoldInvoice,
            Method::Unknown(String::from("settle_hold_invoice"))
        );
        assert_eq!(
            Method::Unknown(String::from("unknown_method")),
            Method::Unknown(String::from("unknown_method"))
        );
    }

    #[test]
    fn test_method_ne() {
        assert_ne!(Method::GetBalance, Method::GetInfo);
        assert_ne!(Method::GetInfo, Method::Unknown(String::from("test")));
    }

    #[test]
    fn test_uri() {
        let pubkey =
            PublicKey::from_str("b889ff5b1513b641e2a139f661a661364979c5beee91842f8f0ef42ab558e9d4")
                .unwrap();
        let relay_url = RelayUrl::parse("wss://relay.damus.io").unwrap();
        let secret =
            SecretKey::from_str("71a8c14c1407c113601079c4302dab36460f0ccd0ad506f1f2dc73b5100e4f3c")
                .unwrap();
        let uri = NostrWalletConnectUri::new(
            pubkey,
            vec![relay_url],
            secret,
            Some("nostr@nostr.com".to_string()),
        );
        assert_eq!(
            uri.to_string(),
            "nostr+walletconnect://b889ff5b1513b641e2a139f661a661364979c5beee91842f8f0ef42ab558e9d4?secret=71a8c14c1407c113601079c4302dab36460f0ccd0ad506f1f2dc73b5100e4f3c&relay=wss%3A%2F%2Frelay.damus.io&lud16=nostr%40nostr.com".to_string()
        );
    }

    #[test]
    fn test_parse_uri() {
        let uri = "nostr+walletconnect://b889ff5b1513b641e2a139f661a661364979c5beee91842f8f0ef42ab558e9d4?secret=71a8c14c1407c113601079c4302dab36460f0ccd0ad506f1f2dc73b5100e4f3c&relay=wss%3A%2F%2Frelay.damus.io&lud16=nostr%40nostr.com";
        let uri = NostrWalletConnectUri::from_str(uri).unwrap();

        let pubkey =
            PublicKey::from_str("b889ff5b1513b641e2a139f661a661364979c5beee91842f8f0ef42ab558e9d4")
                .unwrap();
        let relay_url = RelayUrl::parse("wss://relay.damus.io").unwrap();
        let secret =
            SecretKey::from_str("71a8c14c1407c113601079c4302dab36460f0ccd0ad506f1f2dc73b5100e4f3c")
                .unwrap();
        assert_eq!(
            uri,
            NostrWalletConnectUri::new(
                pubkey,
                vec![relay_url],
                secret,
                Some("nostr@nostr.com".to_string())
            )
        );
    }

    #[test]
    fn test_get_info_request() {
        let request = Request::get_info();

        // Serialize
        let json = request.as_json();

        // Test if JSON string matches
        assert_eq!(json, "{\"method\":\"get_info\",\"params\":{}}");

        // Test parsing
        assert_eq!(Request::from_json(json).unwrap(), request);
    }

    #[test]
    fn test_get_balance_request() {
        let request = Request::get_balance();

        // Serialize
        let json = request.as_json();

        // Test if JSON string matches
        assert_eq!(json, "{\"method\":\"get_balance\",\"params\":{}}");

        // Test parsing
        assert_eq!(Request::from_json(json).unwrap(), request);
    }

    #[test]
    fn test_pay_invoice_request() {
        let request = Request {
            method: Method::PayInvoice,
            params: RequestParams::PayInvoice(PayInvoiceRequest { id: None, invoice: "lnbc210n1pj99rx0pp5ehevgz9nf7d97h05fgkdeqxzytm6yuxd7048axru03fpzxxvzt7shp5gv7ef0s26pw5gy5dpwvsh6qgc8se8x2lmz2ev90l9vjqzcns6u6scqzzsxqyz5vqsp".to_string(), amount: None }),
        };

        assert_eq!(Request::from_json(request.as_json()).unwrap(), request);

        assert_eq!(request.as_json(), "{\"method\":\"pay_invoice\",\"params\":{\"invoice\":\"lnbc210n1pj99rx0pp5ehevgz9nf7d97h05fgkdeqxzytm6yuxd7048axru03fpzxxvzt7shp5gv7ef0s26pw5gy5dpwvsh6qgc8se8x2lmz2ev90l9vjqzcns6u6scqzzsxqyz5vqsp\"}}");
    }

    #[test]
    fn test_parse_request() {
        let request = "{\"params\":{\"invoice\":\"lnbc210n1pj99rx0pp5ehevgz9nf7d97h05fgkdeqxzytm6yuxd7048axru03fpzxxvzt7shp5gv7ef0s26pw5gy5dpwvsh6qgc8se8x2lmz2ev90l9vjqzcns6u6scqzzsxqyz5vqsp5rdjyt9jr2avv2runy330766avkweqp30ndnyt9x6dp5juzn7q0nq9qyyssq2mykpgu04q0hlga228kx9v95meaqzk8a9cnvya305l4c353u3h04azuh9hsmd503x6jlzjrsqzark5dxx30s46vuatwzjhzmkt3j4tgqu35rms\"},\"method\":\"pay_invoice\"}";

        let request = Request::from_json(request).unwrap();

        assert_eq!(request.method, Method::PayInvoice);

        if let RequestParams::PayInvoice(pay) = request.params {
            assert_eq!(pay.invoice, "lnbc210n1pj99rx0pp5ehevgz9nf7d97h05fgkdeqxzytm6yuxd7048axru03fpzxxvzt7shp5gv7ef0s26pw5gy5dpwvsh6qgc8se8x2lmz2ev90l9vjqzcns6u6scqzzsxqyz5vqsp5rdjyt9jr2avv2runy330766avkweqp30ndnyt9x6dp5juzn7q0nq9qyyssq2mykpgu04q0hlga228kx9v95meaqzk8a9cnvya305l4c353u3h04azuh9hsmd503x6jlzjrsqzark5dxx30s46vuatwzjhzmkt3j4tgqu35rms".to_string());
        } else {
            panic!("Invalid request params");
        }
    }

    #[test]
    fn test_serialization_list_transactions() {
        let response_result = Response {
            result: Some(ResponseResult::ListTransactions(vec![
                LookupInvoiceResponse {
                    transaction_type: Some(TransactionType::Incoming),
                    state: Some(TransactionState::Expired),
                    invoice: Some(String::from("abcd")),
                    description: Some(String::from("string")),
                    amount: 123,
                    fees_paid: 1,
                    created_at: Some(Timestamp::from(123456)),
                    expires_at: Some(Timestamp::from(1234567)),
                    description_hash: None,
                    payment_hash: String::new(),
                    metadata: None,
                    payment_method: None,
                    settled_at: None,
                    preimage: None,
                },
            ])),
            result_type: Method::ListTransactions,
            error: None,
        };
        let response_result_json = serde_json::to_string(&response_result).unwrap();
        let reponse_result_deserialized: Response =
            serde_json::from_str(&response_result_json).unwrap();
        assert_eq!(response_result, reponse_result_deserialized)
    }

    #[test]
    fn test_parse_list_transactions_result() {
        let json = r#"{
            "result_type": "list_transactions",
            "result": {
                "transactions": [
                    {
                       "type": "incoming",
                       "state": "expired",
                       "invoice": "abcd",
                       "description": "string",
                       "payment_hash": "",
                       "amount": 123,
                       "fees_paid": 1,
                       "created_at": 123456,
                       "expires_at": 1234567
                   }
                ]
            }
        }"#;
        let result = Response::from_json(json).unwrap();
        assert_eq!(result.result_type, Method::ListTransactions);
        assert!(result.error.is_none());
        assert_eq!(
            result.result,
            Some(ResponseResult::ListTransactions(vec![
                LookupInvoiceResponse {
                    transaction_type: Some(TransactionType::Incoming),
                    state: Some(TransactionState::Expired),
                    invoice: Some(String::from("abcd")),
                    description: Some(String::from("string")),
                    amount: 123,
                    fees_paid: 1,
                    created_at: Some(Timestamp::from(123456)),
                    expires_at: Some(Timestamp::from(1234567)),
                    description_hash: None,
                    payment_hash: String::new(),
                    metadata: None,
                    payment_method: None,
                    settled_at: None,
                    preimage: None
                }
            ]))
        )
    }

    #[test]
    fn test_notifications_parse_and_serialization() {
        let json = r#"{
            "notification_type": "payment_received",
            "notification": {
                "type": "incoming",
                "state": "settled",
                "invoice": "abcd",
                "description": "string1",
                "description_hash": "string2",
                "preimage": "string3",
                "payment_hash": "string4",
                "amount": 1234,
                "fees_paid": 123,
                "created_at": 123456789,
                "expires_at": 546132287,
                "settled_at": 843548111,
                "metadata": {}
            }
        }"#;
        let notification_parsed = Notification::from_json(json).unwrap();
        assert_eq!(
            notification_parsed.notification_type,
            NotificationType::PaymentReceived
        );
        let notification_result = NotificationResult::PaymentReceived(PaymentNotification {
            transaction_type: Some(TransactionType::Incoming),
            state: Some(TransactionState::Settled),
            invoice: String::from("abcd"),
            description: Some(String::from("string1")),
            description_hash: Some(String::from("string2")),
            preimage: String::from("string3"),
            payment_hash: String::from("string4"),
            amount: 1234,
            fees_paid: 123,
            created_at: Some(Timestamp::from_secs(123456789)),
            expires_at: Some(Timestamp::from_secs(546132287)),
            settled_at: Timestamp::from_secs(843548111),
            metadata: Some(Value::Object(serde_json::Map::new())),
        });
        assert_eq!(notification_parsed.notification, notification_result);

        let notification_json = serde_json::to_string(&notification_parsed).unwrap();
        let reponse_result_deserialized: Notification =
            serde_json::from_str(&notification_json).unwrap();
        assert_eq!(notification_parsed, reponse_result_deserialized)
    }

    // Issues:
    // - https://github.com/rust-nostr/nostr/issues/1078
    // - https://github.com/getAlby/hub/issues/1746
    #[test]
    fn test_parse_get_info_response_with_empty_strings() {
        let json = r#"{"alias":"","color":"","pubkey":"","network":"","block_height":0,"block_hash":"","methods":["pay_invoice","pay_keysend","get_info","get_balance"],"notifications":[],"lud16":""}"#;
        let response: GetInfoResponse = serde_json::from_str(json).unwrap();

        assert_eq!(
            response,
            GetInfoResponse {
                alias: None,
                color: None,
                pubkey: None,
                network: None,
                block_height: Some(0),
                block_hash: None,
                methods: vec![
                    Method::PayInvoice,
                    Method::PayKeysend,
                    Method::GetInfo,
                    Method::GetBalance,
                ],
                notifications: Vec::new()
            }
        );
    }
}
