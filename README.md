# nostr-rs-ln

> The repository is `nostr-rs-ln`; the crate is **`nostr-ln`**. The
> language marker belongs to the repository, because every repository here
> shares one GitHub namespace and the name is the only place it can go —
> while crates.io is already the Rust registry. `nostr-rs-nwc` does the
> same thing: the repository carries `-rs` and the crate inside it is
> called `nostr`. See
> [ways-of-working](https://github.com/Red-Token/net.h3/blob/master/doc/wow/ways-of-working.md#repository-naming).


The service side of **NNC** ([NIP-XX]) and **NWC** ([NIP-47]): grants,
limits, and the request pipeline. A node implements a handler; this crate
owns everything between a relay and that handler.

## Why it exists

NIP-XX's request pipeline existed **four times** in this project and no two
copies agreed. Five bugs are filed against one of them, including an
authorization bypass. Three codebases carry near-identical `usage_profile`
modules — one bug copied three times, not three bugs.

**A second implementation of a specification is a second interpretation of
it.**

## What it owns

| | |
|---|---|
| `grant` | kind `30198` — owner verification, `d` and `p` tags, idempotency, revocation, `OTHERS` |
| `profile` | `UsageProfile`: `methods`, `control`, `notifications`, `quota` |
| `limit` | `RateLimitRule` and its bucket — continuous refill, non-mutating checks |
| `subscription` | kind `30199` — what a controller wants, intersected with what its grant permits |
| `nnc` | NIP-XX as types: sixteen methods, two notifications, the request and response envelopes |
| `nnc::client` | `NostrNodeControl` — one thin function per method. Behind the `client` feature |
| `service` | the handler traits, the dispatch, and the pipeline that orders them |
| `service::transport` | relay I/O, NIP-44, the info events. Behind the `transport` feature |

Mission 13.2 adds the handler traits, the dispatch and the seven-step
pipeline; 13.3 adds NIP-44 transport and the info events.

## The checks cannot be skipped

`VerifiedGrant` **cannot be constructed** without the owner set and the
node's own pubkey. A consumer cannot forget the check that
[dln-node#1] forgot — it was declared, written by a setter nobody called,
and never read — because the type it needs does not exist until the check
has run.

Absent configuration fails **closed**: an empty owner list refuses every
grant rather than accepting any.

## Three properties worth knowing

- **Deny by default, on all three maps.** Absent or empty grants nothing. A
  spending grant does not authorise an administrative call, and neither
  entitles a controller to be told anything.
- **Checking a limit never mutates.** Limits are evaluated at pipeline step
  4 and consumed at step 7, so a refused or failed request charges nothing.
- **A subscription authorizes nothing.** It says what a controller *wants*;
  its grant says what it *may have*; delivery is the intersection. Narrow
  the grant and delivery stops at once, without the subscription event
  changing — the node does not own that event and cannot delete it.

## The pipeline

A node writes a handler. This crate owns everything else, in this order:

```text
1 decode      NIP-44, parse
2 resolve     not in methods() -> NOT_IMPLEMENTED
3 authorize   grant, else OTHERS, else UNAUTHORIZED / RESTRICTED
4 validate    a cost from unvalidated parameters is garbage
5 limits      a. rate       first, so that preparing is not free
              b. prepare    the node selects a route or feerate; nothing moves
              c. quota      absolute, against the prepared cost
6 execute     the prepared operation
7 commit      the quoted cost — the number that was checked
```

**This is not the order NIP-XX gives.** That order checks the quota against
a cost derived from the request, which excludes fees — so a node spends
`amount + fee` while recording `amount`, on every spending call. See
[issue 1](https://github.com/DarkWebDivingClub/nostr-rs-ln/issues/1).

Two orderings carry weight beyond tidiness. **Authorize precedes validate**,
so a caller with no grant learns nothing about which parameters are
acceptable. **Rate precedes prepare**, so nobody can make the node compute a
thousand routes for free.

`prepare` returns the cost **and the selection** — the route, the feerate —
so `execute` acts on that choice rather than making it again, which is how
the two could otherwise differ.

## Reconnecting re-reads, rather than resuming

```rust
Service::new(signer, relays, owners)
    .control(node)      // 13198 published, 23198 served
    .run().await        // no .wallet() — 13194 never published,
                        // 23194 answered NOT_IMPLEMENTED
```

Grants arrive over the same relay as requests, so a disconnected service is
not answering anything either — there is no window in which it enforces
stale grants, and no reason to refuse while away.

**But a reconnect must re-read, not resume.** A subscription with
`since(now)` would silently miss a revocation published during the gap, and
the service would go on enforcing a grant that no longer exists. Both
durable kinds are addressable, so reading current state is one query and
needs no history.

Reconnection is not in the SDK's notification stream — it carries events,
relay messages and shutdown — so it is observed by watching relay status.

## A node cannot advertise what it does not implement

```rust
#[nostr_ln::service]
impl ControlService for MyNode {
    fn list_channels(..) { .. }
    fn list_peers(..) { .. }
}
// methods() is generated: &["list_channels", "list_peers"]
```

Every trait method defaults to `NOT_IMPLEMENTED`, so a node writes only
what it serves. `methods()` has **no** default, so forgetting the macro is
a compile error rather than a node that advertises nothing and denies
everything at runtime — and writing `methods()` by hand is refused, because
a hand-written list can disagree with the impl it describes. Both are
compile-fail tests.

## The client

```rust
let nnc = NostrNodeControl::new(uri, signer);      // a signer, not Keys
let channels = nnc.list_channels().await?;
```

**Two arguments where NWC takes one.** An NWC URI carries a secret the
wallet service generated, and holding it *is* the permission. An NNC URI
carries only the service pubkey and relays — the client signs with **its
own** key, and the owner publishes a grant for it. A URI is not a
credential here, which is why `UNAUTHORIZED` says so rather than reporting
a bare code.

Fourteen methods are three lines each, as `nwc`'s are. The two asynchronous
ones get **two functions apiece**:

```rust
let pending = nnc.open_channel(req).await?;   // acknowledged
let opened  = pending.await?;                 // confirmed, later

nnc.open_channel_without_notification(req).await?;   // notify: false
```

Not one function with a flag returning `Option`: the caller passes `notify`
at the call site, so the compiler already knows, and an `Option` it must
unwrap for a case that cannot happen is a downgrade. **Dropping the handle
is not the same as `notify: false`** — the node still sends an event nobody
reads — which is why fire-and-forget has its own function rather than
"just don't await".

`Pending` is owned and `Send + 'static`, so it can be spawned or stored: a
dashboard cannot block a request thread for six blocks. Dropping it
unsubscribes.

The `client` feature is off by default, so a consumer wanting only the
types and the access layer does not pull a relay stack.

## `dln-ctrl` — the same client, from a prompt

```bash
cargo install --path . --features cli   # or: apt install dln-ctrl
export NWC_URI='nostr+walletconnect://…'
```

Nothing in this estate was a client a person could type into. Every
consumer of these protocols was a test harness or a service, and the cost
showed: four defects found in one afternoon, three of which are **one
call against a running node**, each reached by building a demo and
waiting six minutes for a channel.

**The method is not enumerated.** Its name goes on the wire as typed and
`params` is the JSON object the wire carries:

```bash
dln-ctrl nwc get_info
dln-ctrl nwc make_invoice '{"amount":120000,"description":"x"}'
dln-ctrl nnc list_channels
```

So names are verbatim from the specification — no translation layer for
one to drift in — every method works on the day it ships, and **a method
this crate has never heard of** can still be called, which is exactly
what checking somebody else's node needs:

```bash
$ dln-ctrl nwc estimate_onchain_fees '{"fees":{"1":0}}'
dln-ctrl: NotImplemented: estimate_onchain_fees is not implemented
$ echo $?
1
```

That answer came from the node. A client-side "unknown command" would
have answered a different question.

### Three things it is for

**Does the node work, and what does it claim?**

```bash
dln-ctrl nwc get_info          # what it serves
dln-ctrl nwc methods           # what this client knows
```

The difference between those two lists is the conformance question.

**Does my grant cover this?** Call it and read the refusal:

```bash
$ dln-ctrl nwc list_invoices
dln-ctrl: Restricted: this controller may not call that method  (the grant may not permit this method)
```

**Is it sending notifications at all?**

```bash
$ dln-ctrl nwc notify
warning: this node does not advertise channel_opened — it advertises payment_received, …
subscribed to payment_received, payment_sent, hold_invoice_accepted
waiting — ^C to stop
```

### `-n` subscribes before it calls

```bash
dln-ctrl nwc make_hold_invoice '{"amount":250000,"payment_hash":"ab…"}' -n
dln-ctrl nnc open_channel '{"pubkey":"02ab…","amount_sats":2000000}' -n
```

**This is not ergonomics.** These notification kinds are ephemeral —
`20000 ≤ n < 30000`, which [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md)
says relays are not expected to store. Call `open_channel`, then run
`notify`, and the answer may already have come and gone with nothing to
replay it. `-n` subscribes *first*, so the window never exists.

It also sets `notify: true` for the methods that carry the field.
Without that it would subscribe correctly and wait forever on a node that
was told not to send.

The first example is a maker's whole flow in one command: mint the hold
invoice, print it, hang until somebody locks in.

### Credentials

`NWC_URI` is the whole credential — the URI carries a secret key. NNC's
does not, so `nnc` needs `NNC_URI` **and** `NNC_SECRET`.

A URI is a credential: nothing here prints one back, not in a parse
error and not in a refusal. Prefer the environment to `--uri`, which is
visible in `ps` to every user on the machine.

The `cli` feature is off by default and adds no dependencies of its own —
the argument parsing is forty lines, so the library that every node and
tool links stays at five dependencies.

## The types are checked against the specification, not against themselves

`vectors/nnc.json` is generated **from `XX.md`** by
`examples/generate_nnc_vectors.rs`: every `jsonc` block under a method
heading is an example the document asserts.

```sh
cargo run --example generate_nnc_vectors -- ~/git/nips/XX.md > vectors/nnc.json
```

That distinction earns its keep. A round-trip test encodes and decodes
through the same code and cannot notice a disagreement with the
specification — it was a vector that caught `channel_opened` carrying no
`state` field while `list_channels` does, after a hand-written test had
passed by using JSON invented to match the types.

## Testing

Thirty-eight tests, no chain, no node and no relay:

```sh
cargo test
```

Several are a filed bug: [#1] owner verification, [#2] `rate` and not
`access_rate`, [#4] `since` advancing on withdrawal only, [#5] a rate that
can express one coin a week at all.

[NIP-XX]: https://github.com/DarkWebDivingClub/nips/blob/master/XX.md
[NIP-47]: https://github.com/nostr-protocol/nips/blob/master/47.md
[dln-node#1]: https://github.com/DarkWebDivingClub/dln-node/issues/1
[#1]: https://github.com/DarkWebDivingClub/dln-node/issues/1
[#2]: https://github.com/DarkWebDivingClub/dln-node/issues/2
[#4]: https://github.com/DarkWebDivingClub/dln-node/issues/4
[#5]: https://github.com/DarkWebDivingClub/dln-node/issues/5
