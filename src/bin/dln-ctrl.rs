//! `dln-ctrl` — a command line for a node that speaks NWC or NNC.
//!
//! Mission 28. It exists because nothing in this estate was a client a
//! person could type into: every consumer of these protocols was a test
//! harness or a service, and
//! [mission 27](https://github.com/DarkWebDivingClub/x.dwdc.club) spent an
//! afternoon finding four defects that are each **one call against a
//! running node** — at a ten-minute signet round trip apiece, because
//! there was no way to ask.
//!
//! ## The shape
//!
//! ```text
//! dln-ctrl <protocol> <method> [params-json] [-n]
//! dln-ctrl <protocol> notify [types...]
//! ```
//!
//! The method is **not enumerated**. Its name goes on the wire as typed
//! and `params` is the JSON object the wire carries, which buys three
//! things a subcommand-per-method surface does not:
//!
//! - names are verbatim from the specification, so there is no
//!   translation layer for one to drift in;
//! - every method works on the day this ships, and every method added
//!   after it, with no argument parsing to extend;
//! - **a method this crate has never heard of** can be called, which is
//!   exactly what checking somebody else's node needs.
//!
//! ## Credentials, and why the two protocols differ
//!
//! NWC's URI carries a secret key, so `$NWC_URI` is the whole credential.
//! NNC's does not — it says who and where, and a signer says who you are —
//! so `nnc` needs `$NNC_URI` **and** `$NNC_SECRET`. That asymmetry is the
//! protocols', not this tool's.
//!
//! A URI is a credential. Prefer the environment: an argument is visible
//! in `ps` to every user on the machine, and nothing here prints one back.

use std::io::Write as _;
use std::process::ExitCode;
use std::time::Duration;

use nostr::key::Keys;
use nostr_ln::nnc::client::NostrNodeControl;
use nostr_ln::nnc::uri::NodeControlUri;
use nostr_ln::nwc::client::{WalletConnect, WalletUri};
use nostr_ln::nwc::WalletNotificationType;
use nostr_ln::nnc::NotificationType;

/// Long enough for a hold invoice to be settled by somebody else, which
/// is the slowest thing any of these calls legitimately waits for.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

fn main() -> ExitCode {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => return die(format!("could not start a runtime: {e}")),
    };
    match rt.block_on(run()) {
        Ok(code) => code,
        Err(e) => die(e),
    }
}

fn die(message: impl std::fmt::Display) -> ExitCode {
    eprintln!("dln-ctrl: {message}");
    ExitCode::FAILURE
}

/// Print usage. Deliberately shows a real invocation per shape rather
/// than a grammar — the grammar is two lines and the examples are what
/// somebody needs.
fn usage() -> String {
    "\
usage:
  dln-ctrl nwc <method> [params-json] [-n] [--json]
  dln-ctrl nnc <method> [params-json] [-n] [--json]
  dln-ctrl <nwc|nnc> notify [types...]
  dln-ctrl <nwc|nnc> methods

examples:
  dln-ctrl nwc get_info
  dln-ctrl nwc make_invoice '{\"amount\":120000,\"description\":\"x\"}'
  dln-ctrl nwc make_hold_invoice '{\"amount\":250000,\"payment_hash\":\"ab..\"}' -n
  dln-ctrl nnc open_channel '{\"pubkey\":\"02ab..\",\"amount_sats\":2000000}' -n
  dln-ctrl nnc notify channel_opened

-n subscribes *before* sending, then streams what the call causes until
   interrupted. Notifications are ephemeral: subscribing afterwards can
   miss the answer with nothing to replay it.

environment:
  NWC_URI      nostr+walletconnect://…   (carries its own secret)
  NNC_URI      nostr+nodecontrol://…     (carries no secret)
  NNC_SECRET   the key you sign with, for nnc only

A URI is a credential. Prefer the environment to an argument, which is
visible in `ps` to every user on the machine."
        .to_string()
}

async fn run() -> Result<ExitCode, String> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();

    let json_out = take_flag(&mut args, "--json");
    let notify_after = take_flag(&mut args, "-n") | take_flag(&mut args, "--notify");
    let uri_arg = take_value(&mut args, "--uri");

    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        println!("{}", usage());
        return Ok(ExitCode::SUCCESS);
    }

    let protocol = args.remove(0);
    if args.is_empty() {
        return Err(format!("{protocol}: a method is required\n\n{}", usage()));
    }
    let method = args.remove(0);

    // Anything left is params for a call, or types for `notify`.
    match (protocol.as_str(), method.as_str()) {
        ("nwc", "notify") => nwc_notify(uri_arg, &args).await,
        ("nnc", "notify") => nnc_notify(uri_arg, &args).await,
        ("nwc", "methods") => {
            for m in nostr_ln::nwc::WalletMethod::ALL {
                println!("{m}");
            }
            Ok(ExitCode::SUCCESS)
        }
        ("nnc", "methods") => {
            for m in nostr_ln::nnc::Method::ALL {
                println!("{m}");
            }
            Ok(ExitCode::SUCCESS)
        }
        ("nwc", _) => nwc_call(uri_arg, &method, params(&args)?, json_out, notify_after).await,
        ("nnc", _) => nnc_call(uri_arg, &method, params(&args)?, json_out, notify_after).await,
        (p, _) => Err(format!("unknown protocol {p:?} — expected nwc or nnc\n\n{}", usage())),
    }
}

/// The params object, or `{}`.
///
/// A method with no parameters is the common case and typing `'{}'` for
/// it is noise, so absence means the empty object rather than an error.
fn params(rest: &[String]) -> Result<serde_json::Value, String> {
    match rest.first() {
        None => Ok(serde_json::json!({})),
        Some(s) => serde_json::from_str(s)
            .map_err(|e| format!("params are not JSON: {e}\n  got: {s}")),
    }
}

fn take_flag(args: &mut Vec<String>, name: &str) -> bool {
    if let Some(i) = args.iter().position(|a| a == name) {
        args.remove(i);
        true
    } else {
        false
    }
}

fn take_value(args: &mut Vec<String>, name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    args.remove(i);
    if i < args.len() {
        Some(args.remove(i))
    } else {
        None
    }
}

/// Read a credential from an argument or the environment.
///
/// The error names the variable and never echoes what was found, because
/// what was found is a secret and this message goes to a terminal that
/// may be logged.
fn credential(arg: Option<String>, var: &str) -> Result<String, String> {
    arg.or_else(|| std::env::var(var).ok())
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| format!("no credential: set ${var}"))
}

// ── NWC ──────────────────────────────────────────────────────────────

fn wallet(uri_arg: Option<String>) -> Result<WalletConnect, String> {
    let raw = credential(uri_arg, "NWC_URI")?;
    // The parse error is not shown. It would quote the URI back, and the
    // URI is a secret key.
    let uri: WalletUri = raw
        .parse()
        .map_err(|_| "NWC_URI is not a nostr+walletconnect:// URI".to_string())?;
    Ok(WalletConnect::new(uri).with_timeout(DEFAULT_TIMEOUT))
}

async fn nwc_call(
    uri_arg: Option<String>,
    method: &str,
    params: serde_json::Value,
    json_out: bool,
    notify_after: bool,
) -> Result<ExitCode, String> {
    let w = wallet(uri_arg)?;

    // **Subscribe before sending.** The whole point of -n: a notification
    // that arrives before the stream exists is gone, because these kinds
    // are ephemeral and no relay stores them.
    let stream = if notify_after {
        let types = WalletNotificationType::ALL;
        eprintln!("subscribed to {}", join(types.iter().map(|t| t.as_str())));
        Some(w.notifications(&types).await.map_err(|e| e.to_string())?)
    } else {
        None
    };

    match w.call_raw(method, params).await {
        Ok(v) => {
            emit(&v, json_out);
            if let Some(mut stream) = stream {
                eprintln!("waiting for notifications — ^C to stop");
                while let Some(n) = stream.next().await {
                    println!(
                        "{}",
                        serde_json::to_string(&n).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
                    );
                    let _ = std::io::stdout().flush();
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => Err(refusal(e)),
    }
}

async fn nwc_notify(uri_arg: Option<String>, types: &[String]) -> Result<ExitCode, String> {
    let w = wallet(uri_arg)?;
    let types = wanted_wallet_types(types);
    let mut stream = w.notifications(&types).await.map_err(|e| e.to_string())?;

    // Said before waiting, so "nothing arrived" is distinguishable from
    // "nothing was asked for" — which is the failure that cost mission 27
    // a run, twice, from two independent causes.
    eprintln!("subscribed to {}", join(types.iter().map(|t| t.as_str())));
    eprintln!("waiting — ^C to stop");

    while let Some(n) = stream.next().await {
        println!(
            "{}",
            serde_json::to_string(&n).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
        );
        let _ = std::io::stdout().flush();
    }
    Ok(ExitCode::SUCCESS)
}

/// The types to ask for: named ones, or everything this crate knows.
///
/// **Everything is the right default.** A caller rarely knows which
/// notification a given method produces — `open_channel` produces
/// `channel_opened`, and nothing about the method name says so — and
/// subscribing narrowly is how `-n` waits for something nobody asked for.
///
/// An unrecognised name becomes `Unknown` and is sent anyway, for the
/// same reason the method name is: the node's answer is the interesting
/// one, and a client-side rejection would answer a different question.
fn wanted_wallet_types(names: &[String]) -> Vec<WalletNotificationType> {
    if names.is_empty() {
        return WalletNotificationType::ALL.to_vec();
    }
    names
        .iter()
        .map(|n| {
            WalletNotificationType::ALL
                .iter()
                .find(|t| t.as_str() == n)
                .cloned()
                .unwrap_or_else(|| WalletNotificationType::Unknown(n.clone()))
        })
        .collect()
}

/// The same, for the node-control plane.
fn wanted_node_types(names: &[String]) -> Vec<NotificationType> {
    if names.is_empty() {
        return NotificationType::ALL.to_vec();
    }
    names
        .iter()
        .map(|n| {
            NotificationType::ALL
                .iter()
                .find(|t| t.as_str() == n)
                .cloned()
                .unwrap_or_else(|| NotificationType::Unknown(n.clone()))
        })
        .collect()
}

// ── NNC ──────────────────────────────────────────────────────────────

fn node(uri_arg: Option<String>) -> Result<NostrNodeControl, String> {
    let raw = credential(uri_arg, "NNC_URI")?;
    let uri: NodeControlUri = raw
        .parse()
        .map_err(|_| "NNC_URI is not a nostr+nodecontrol:// URI".to_string())?;

    // Two credentials where NWC needs one. The NNC URI carries no secret:
    // it says who and where, and this says who you are.
    let secret = credential(None, "NNC_SECRET")?;
    let keys = Keys::parse(&secret).map_err(|_| "NNC_SECRET is not a key".to_string())?;

    Ok(NostrNodeControl::new(uri, keys).with_timeout(DEFAULT_TIMEOUT))
}

async fn nnc_call(
    uri_arg: Option<String>,
    method: &str,
    mut params: serde_json::Value,
    json_out: bool,
    notify_after: bool,
) -> Result<ExitCode, String> {
    let n = node(uri_arg)?;

    if notify_after {
        // **Opt in, or subscribe into silence.** `open_channel` and
        // `close_channel` carry a `notify` field and the node honours a
        // false one — `notify_false` in the mandatory suite proves it. A
        // -n that subscribed correctly and forgot this would wait forever
        // on a node that was told not to send.
        if matches!(method, "open_channel" | "close_channel") {
            if let Some(obj) = params.as_object_mut() {
                obj.entry("notify").or_insert(serde_json::Value::Bool(true));
            }
        }
        let types = NotificationType::ALL;
        n.set_subscription(&types).await.map_err(|e| e.to_string())?;
        eprintln!("subscribed to {}", join(types.iter().map(|t| t.as_str())));
    }

    match n.call_raw(method, params).await {
        Ok(v) => {
            emit(&v, json_out);
            if notify_after {
                eprintln!("waiting for notifications — ^C to stop");
                n.handle_notifications(|note| async move {
                    println!(
                        "{}",
                        serde_json::to_string(&note)
                            .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
                    );
                    let _ = std::io::stdout().flush();
                    // `true` keeps the stream open; this ends at ^C.
                    Ok(true)
                })
                .await
                .map_err(|e| e.to_string())?;
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => Err(nnc_refusal(e)),
    }
}

async fn nnc_notify(uri_arg: Option<String>, types: &[String]) -> Result<ExitCode, String> {
    let n = node(uri_arg)?;
    let types = wanted_node_types(types);
    n.set_subscription(&types).await.map_err(|e| e.to_string())?;
    eprintln!("subscribed to {}", join(types.iter().map(|t| t.as_str())));
    eprintln!("waiting — ^C to stop");

    n.handle_notifications(|note| async move {
        println!(
            "{}",
            serde_json::to_string(&note).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
        );
        let _ = std::io::stdout().flush();
        // `true` keeps the stream open; this ends at ^C.
        Ok(true)
    })
    .await
    .map_err(|e| e.to_string())?;
    Ok(ExitCode::SUCCESS)
}

// ── output ───────────────────────────────────────────────────────────

/// Pretty by default, compact with `--json`.
///
/// Both are the response verbatim — there is no rendering layer that
/// could show something the node did not say.
fn emit(v: &serde_json::Value, json_out: bool) {
    let s = if json_out {
        serde_json::to_string(v)
    } else {
        serde_json::to_string_pretty(v)
    };
    println!("{}", s.unwrap_or_else(|e| format!("could not render the response: {e}")));
}

/// A refusal, with its code, for a caller that will read the exit status.
///
/// `RESTRICTED` from a client that connected fine means the grant does
/// not permit the method, and saying so here saves the next person the
/// hour it cost the last one.
///
/// Two functions rather than one generic: the two protocols have
/// separate error enums, and the shared part — an `NncError` with a code
/// and a message — is small enough that plumbing a trait through would
/// cost more than it saves.
fn coded(err: &nostr_ln::nnc::NncError) -> String {
    let hint = if format!("{:?}", err.code).contains("Restricted") {
        "  (the grant may not permit this method)"
    } else {
        ""
    };
    format!("{:?}: {}{hint}", err.code, err.message)
}

fn refusal(e: nostr_ln::nwc::client::Error) -> String {
    match &e {
        nostr_ln::nwc::client::Error::Refused(err) => coded(err),
        other => other.to_string(),
    }
}

fn nnc_refusal(e: nostr_ln::nnc::client::Error) -> String {
    match &e {
        nostr_ln::nnc::client::Error::Refused(err) => coded(err),
        other => other.to_string(),
    }
}

fn join<'a>(items: impl Iterator<Item = &'a str>) -> String {
    items.collect::<Vec<_>>().join(", ")
}
