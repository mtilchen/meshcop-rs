# Design: commissioner session driver

Status: phase 1 is implemented (see "Phasing" and "Phase 1 as built").
Phases 2–4 are not.

The "Problem" section describes the library as it was before phase 1.

## Problem

`Commissioner` is a `&mut self` object that only makes progress while the
caller is awaiting one of its methods. Keeping a session alive over time is
therefore the application's job:

- Keep-alives must be scheduled by the caller between its own requests and
  `next_event()` calls (`CommissionerConfig::keepalive_interval` documents
  this).
- Only one request can be in flight, because every operation borrows the
  commissioner mutably and runs its own receive loop.
- Unsolicited notifications are only read while some operation or
  `next_event()` is running.
- Recovering from a rejected keep-alive or a lost DTLS session is left to
  the application.

Both bundled applications reimplement the same scheduling:

- `ot-commissioner-cli` has `handle_scheduled_keepalive`,
  `refresh_keepalive_before_command` and `COMMAND_KEEPALIVE_HEADROOM`. It
  refreshes the keep-alive before commands that might outlast the deadline.
- `meshcop-netdiag` tracks `last_keep_alive` and rejects a node timeout that
  would not fit inside the keep-alive interval.

Two findings in the PR #4 review were bugs in this duplicated code. The C++
reference commissioner owns its keep-alive timer internally.

## Goals

- The default path is a single call: connect, handshake and petition. After
  that the session stays alive without application involvement.
- Methods take `&self`, and handles are cheap to clone, so independent
  tasks can issue requests concurrently.
- Events are delivered as a `Stream`.
- Recovery (reconnect and re-petition) is a configuration choice with safe
  defaults, not application code.
- Callers who need control can take it: manual keep-alives, recovery
  disabled, a raw CoAP request escape hatch, and the existing sans-I/O
  layers.
- Tests stay deterministic under the scripted harness and paused Tokio time.

## Non-goals

- Runtime neutrality for the `meshcop` crate. It already depends on Tokio.
  `meshcop-dtls` stays runtime-neutral and is unaffected.
- CCM and TCAT.
- Replacing the in-house CoAP codec.
- Keeping the current `&mut self` `Commissioner` as a second public API.
  Two commissioner APIs would double the surface to document, test and
  mutation-gate. The crate is pre-1.0, so replacement is the cheaper option.

## Architecture

```text
 app tasks ──clone──► Commissioner (handle) ──mpsc<Command>──►┐
                         │  ▲                                  │
                         │  └──watch<SessionStatus>────────────┤
 app tasks ◄──Events (broadcast<CommissionerEvent>)────────────┤
                                                               ▼
                                   ┌──────────── driver task ────────────┐
                                   │ UDP socket + DtlsSession            │
                                   │ pending: token → PendingRequest     │
                                   │ retransmit deadlines                │
                                   │ keep-alive deadline                 │
                                   │ joiner sessions + JoinerHandler     │
                                   │ mesh-local prefix cache             │
                                   │ recovery state machine              │
                                   └─────────────────────────────────────┘
```

The driver is one task running a `select!` loop over:

1. commands from handles,
2. the next protected datagram from the border agent,
3. the earliest retransmission deadline,
4. the keep-alive deadline, and
5. the recovery backoff deadline.

Cancel safety has been checked:

- `meshcop_dtls::driver::recv_application_data` awaits only the socket
  receive, which Tokio documents as cancel-safe for `UdpSocket`.
- DTLS state changes synchronously, after a whole datagram arrives.

The existing `wait_for_response` already races that receive against a
timer.

### Request matching

The per-request `wait_for_response` loop turns into a pending-request table:

- **Direct requests** are keyed by CoAP token. They carry the encoded wire,
  the RFC 7252 retransmission schedule, the absolute exchange deadline, and
  a `oneshot::Sender<Result<CoapMessage>>`.
- **Proxied requests** are keyed by the inner token plus the destination.
  - An incoming UDP_RX is decapsulated and matched on both.
  - Each retransmission still gets a fresh outer UDP_TX identity, as it does
    today.
- **Empty ACKs** stop retransmission but leave the entry pending, waiting
  for the separate response.
- **Resets** fail the matching entry.
- **Unmatched responses** are dropped, as they are today.
- **Unsolicited messages** go through the existing
  `route_unsolicited_message` path and become events.

This is a generalization of `route_incoming`, which matches exactly one
expected request today.

### Concurrency limit

RFC 7252 §4.7 defaults NSTART to 1 outstanding interaction per server, and
Thread meshes have little bandwidth.

- `max_in_flight` bounds application requests. It defaults to 1.
- Requests beyond the limit wait in a FIFO queue inside the driver.
- Session-control messages (petition, keep-alive, resign) use one reserved
  slot outside the limit, so a slow proxied `DIAG_GET` can never delay a
  keep-alive past the Leader's timeout. As a result, up to two exchanges
  with the border agent can be outstanding. That is a deliberate deviation
  from NSTART = 1, justified by session liveness.

### Handle lifetime and shutdown

- `resign().await` sends the resign request, waits for the answer, then
  stops the driver. Later calls on any clone return a `SessionClosed`
  error.
- When the last handle is dropped, the command channel closes. The driver
  sends a best-effort resign with a short timeout and exits.
  - `Events` receivers do not keep the driver alive.
  - A handle clone kept inside a long-lived task does keep it alive; the
    docs must say so.
- An explicit `resign()` stays the recommended path. AGENTS.md asks
  inspection tools to resign before they exit.
- Dropping the handle is not a substitute for `resign()` at program exit.
  When `#[tokio::main]` returns, the runtime shuts down and cancels spawned
  tasks, so the driver's best-effort resign may never be sent. The border
  agent then holds the session until the Leader times it out.

### Spawning

`connect` spawns the driver itself; the driver task is never returned to
the caller.

1. **Setup runs on the caller's task, before anything is spawned.**
   - Bind the socket.
   - Run the DTLS handshake.
   - Petition, unless the session was opened with `connect_only`.

   Connection and petition failures, including `PetitionRejected`, come back
   directly from `connect`. No channel is involved.
2. **The established session is moved into a `tokio::spawn`ed driver.**
   Spawning requires:
   - a Tokio runtime context (either flavor);
   - a `Send + 'static` driver, which `JoinerHandler: Send` already
     supports.
3. **The driver's end is observable without a join handle:**
   - `status()` changes to `Closed { reason }`, and is reported as closed
     if the driver's `watch` sender is dropped;
   - `SessionLost` and `RecoveryAbandoned` are emitted as events;
   - every later call on any clone returns `Error::SessionClosed`.

A hyper-style constructor that returns
`(Commissioner, Events, SessionDriver)`, where the caller spawns the
`SessionDriver` future, would be purely additive. It is deferred until a
caller needs to choose where the driver runs, for example in a `LocalSet`,
on a specific runtime, or inside an instrumented task.

## Public API sketch

Names are placeholders.

```rust
let (commissioner, mut events) = CommissionerConfig::builder("my-commissioner")
    .pskc(pskc)
    .keep_alive(KeepAlive::Automatic)                  // default
    .recovery(Recovery::reconnect())                   // default; see "Recovery"
    .max_in_flight(1)                                  // default
    .event_capacity(64)                                // default
    .joiner_handler(joiner_handler)                    // e.g. StaticJoinerHandler
    .connect(border_agent)                             // DTLS + petition
    .await?;

let active = commissioner.get_active_dataset(DatasetFlags::ALL).await?;

tokio::spawn({
    let commissioner = commissioner.clone();
    async move { commissioner.energy_scan(/* … */).await }
});

while let Some(event) = events.next().await {
    match event {
        CommissionerEvent::SessionLost { reason } => { /* … */ }
        CommissionerEvent::JoinerFinalized { .. } => { /* … */ }
        _ => {}
    }
}

commissioner.resign().await?;
```

Surface changes:

- **`connect` petitions by default. `connect_only` opens the DTLS session
  without petitioning,** for work that does not need the commissioner role.
  - `commissioner.petition().await` upgrades a connect-only session. The
    driver starts automatic keep-alives once the petition is accepted.
  - A connect-only session sends no keep-alives, because there is no
    commissioner session to keep alive.
  - Operations that need an active session return
    `Error::InvalidState` until a petition is accepted.
  - Recovery re-establishes DTLS and petitions again only if the session
    was active when it was lost.
  - An unpetitioned session is short-lived: the measured border agent
    closes it about 50 s after the handshake, whether or not it is in use
    (see "Findings"). In connect-only mode a peer close is therefore
    normal. The driver reports `Idle` and re-runs the handshake the next
    time a request needs the session, rather than treating the close as a
    failure.
  - Diagnostics need a petition. On the measured border agent, `UDP_TX`
    sent from an unpetitioned session is silently dropped. The
    `session_id_required` checks on the diagnostic methods stay.
- **`connect` returns `(Commissioner, Events)`.** A subscription taken
  after `connect` returns could miss events emitted in between; returning
  the first subscriber from `connect` closes that gap.
  - `commissioner.subscribe()` adds more subscribers.
  - A caller that does not want events drops the receiver.
- **`Events`** implements `futures_core::Stream<Item = CommissionerEvent>`
  and also has an inherent `async fn next()`, so simple callers need no
  stream combinator crate. This adds `futures-core` as a dependency: it is
  small, widely used, and the standard home of the `Stream` trait.
- **`status()`** returns a `SessionStatus`: `Connecting`, `Connected`
  (DTLS up, not petitioned), `Idle` (connect-only session closed by the
  peer, reopened on demand), `Active { session_id }`,
  `Recovering { attempt }` or `Closed { reason }`. It comes
  from a `watch` channel. It replaces `state()` and `session_id()`.
- **`request(Destination, CoapRequest) -> Result<CoapMessage>`** is the
  escape hatch for MeshCoP resources without a typed method, such as vendor
  TLVs or newer Thread resources.
  - `Destination` is `BorderAgent` or `Mesh { address, port }`; the latter
    is sent through UDP_TX.
  - The driver assigns message IDs and tokens, so a raw request gets
    retransmission, matching and the in-flight limit for free.
- **Typed operations** (datasets, commands, diagnostics, `send_to_joiner`)
  keep their names and signatures but take `&self`.
- **Removed from the public API:**
  - `next_event()`, replaced by `Events`.
  - `socket()`, since the driver owns the socket.
  - `disconnect()`, replaced by `resign()` or dropping the handle.
- **Kept as runtime setters:** `set_joiner_handler` and
  `clear_joiner_handler` (see "Phase 1 as built").
- **`CommissionerEvent` becomes `#[non_exhaustive]`,** so lifecycle events
  can be added without a breaking change.

### Keep-alive modes

```rust
pub enum KeepAlive {
    /// The driver sends keep-alives every `keepalive_interval` (default).
    Automatic,
    /// The application calls `Commissioner::keep_alive()`; the driver never
    /// schedules one.
    Manual,
}
```

In `Automatic` mode the outcomes are:

- **Accept:** re-arm the deadline.
- **Reject, Pending, or exchange failure:** the session is lost (see
  Recovery).

The CLI already treats a Pending keep-alive as fatal, and this keeps that
behavior. `KeepAliveResponse` events are still emitted in both modes.

## Recovery

```rust
pub enum Recovery {
    /// Report the loss and close.
    Never,
    /// Re-establish the session according to the policy.
    Reconnect(ReconnectPolicy),
}

pub struct ReconnectPolicy {
    max_attempts: Option<u32>,            // None = unbounded
    initial_backoff: Duration,
    max_backoff: Duration,                // exponential, with jitter
    on_conflict: ConflictPolicy,          // GiveUp (default) | Retry
    restore_commissioner_dataset: bool,   // default true
    resolver: Option<Arc<dyn BorderAgentResolver>>,
}
```

### Triggers

| Trigger                                  | Re-petition over the same DTLS session | New DTLS session, then petition |
|------------------------------------------|:---:|:---:|
| Keep-alive answered with Reject          | ✓ first; falls back to the next column on failure | |
| Keep-alive exchange timed out            | | ✓ |
| DTLS alert or record-layer failure       | | ✓ |
| Socket I/O error                         | | ✓ |

### Events

Each attempt emits one or more of these:

- `SessionLost { reason }`
- `Reconnecting { attempt, delay }`
- `SessionRestored { session_id }`
- `RecoveryAbandoned { reason }`

`status()` follows the same transitions.

### Rules

1. **Requests in flight fail; they are not replayed.** Every pending and
   queued request fails with `Error::SessionLost`.
   - An operation such as `MGMT_ACTIVE_SET` is not safe to resend blindly
     on a new session, so the application decides what to retry.
   - Replaying reads automatically is possible later but is not in scope
     now.
2. **A conflict gives up by default.** A petition can be rejected because
   another commissioner is active.
   - The default `on_conflict` is `GiveUp`: emit `RecoveryAbandoned` with
     the existing commissioner ID.
   - `Retry` keeps backing off until the session is free. It suits
     unattended daemons, but it will take the network back after an
     operator deliberately used another tool, so it must be opted into.
3. **The commissioner dataset is restored.** When a session ends, the
   Leader drops the commissioner's data, including steering data, so
   joiners are no longer steered to us after a re-petition. (This is from
   OpenThread's Leader behavior; confirm it against the Thread 1.4 spec
   before relying on it.)
   - The driver remembers the last commissioner dataset the application set
     successfully, including writes made through `enable_joiner` and
     `enable_all_joiners`.
   - With `restore_commissioner_dataset` on, the driver re-applies it under
     the new session ID before emitting `SessionRestored`.
   - Either way, the application can re-apply its own state when it sees
     `SessionRestored`.
4. **Session-scoped state is reset.**
   - The mesh-local prefix cache is cleared.
   - In-progress joiner DTLS sessions are dropped; each joiner restarts its
     own handshake.
   - The `JoinerHandler` is kept.
5. **The address may be re-resolved.** Border-agent ports are usually
   dynamic, and a restarted agent often comes back on a new one.
   - Without a resolver, recovery reconnects to the original address.
   - With a `BorderAgentResolver`, the driver asks for the current address
     before each new DTLS session.
   - This is the hook that future mDNS `_meshcop._udp` discovery plugs
     into.

### Default policy (decided)

The default is `Recovery::Reconnect`:

- a bounded number of attempts (initially 5, configurable);
- `GiveUp` when another commissioner holds the session;
- commissioner dataset restore on.

The default path should just work, and this default cannot take a session
from another commissioner. `Recovery::Never` remains available.

## Joiner handler

`JoinerHandler` is a synchronous `&mut self` trait and will run on the
driver task.

- A handler that blocks, such as one that looks up PSKds in a database,
  delays keep-alives and every other exchange.
- Proposal: keep the trait synchronous and document that it must not block.
  `StaticJoinerHandler` already meets that bar.
- If an async lookup is needed later, add an async trait variant rather
  than making the driver wait on a handler it does not control.

## Event delivery

- Events go out on a bounded `tokio::sync::broadcast` channel. The capacity
  defaults to 64 and is set with `event_capacity`.
- A slow consumer must never apply backpressure to the driver; a stalled
  driver misses keep-alives and loses the session.
- When a receiver falls behind, `Events` yields
  `CommissionerEvent::Lagged { missed }` and then resumes with the oldest
  event still buffered.
- Events emitted while no receiver exists are discarded.

## Testing

- **Transport abstraction.** The driver talks to a small internal transport
  trait with two implementations: live (UDP plus `DtlsSession`) and
  scripted.
- **Scripted harness.** `ScriptedMeshcopTransport` changes from a
  synchronous request→responses exchange into an async queue. The driver
  can then observe timing, and scripts can inject unsolicited messages and
  failures at chosen moments.
  - About 37 commissioner tests and 29 CLI interpreter tests use it today;
    they will all need porting.
  - Most assertions (observed requests, parsed results) should carry over
    unchanged.
- **New deterministic tests**, under `start_paused` time:
  - keep-alive fires at the interval with no application activity;
  - a keep-alive is sent on time while an application request is stalled;
  - a Reject leads to re-petition and `SessionRestored`;
  - a conflict leads to `RecoveryAbandoned`;
  - the commissioner dataset is restored;
  - pending requests fail with `SessionLost`;
  - `Lagged` is reported when a receiver overflows;
  - dropping the last handle sends a resign;
  - `max_in_flight` queues requests in order;
  - concurrent proxied requests are matched by inner token.
- **Interop.** The OpenThread interop suite, including its packet-loss
  injection, exercises the driver end to end.
- **Mutation gate.** Update the `targeted` globs in `tools/ci/mutants.sh`
  for the new files.

## Migration

- **`ot-commissioner-cli`:**
  - Delete the keep-alive scheduling and the pre-command refresh.
  - Feed the REPL's event log from `Events`.
  - Replace `start` with a new `connect`, and `stop` with `resign`.
- **`meshcop-netdiag`:**
  - Delete `last_keep_alive` and the check that the node timeout fits
    inside the keep-alive interval.
  - `Collector` holds a handle instead of `&mut Commissioner`.
  - Querying routers in parallel is a later change, bounded by
    `max_in_flight`.
- **Examples and live tests:** port them to the new API. They keep
  resigning before exit.
- **Documentation:**
  - `docs/PARITY.md`: keep-alive is now library-owned, like the reference
    commissioner.
  - `README.md` and `CLAUDE.md`: update the "keep-alives are
    application-driven" notes.
  - `CommissionerConfig::keepalive_interval`: update its doc comment.

## Phase 1 as built

Where the implementation departs from, or makes concrete, the design above:

- **The joiner handler is still set at runtime.** `set_joiner_handler` and
  `clear_joiner_handler` stay on the handle rather than moving to the builder,
  because the CLI replaces the handler whenever `joiner enable` changes the
  enabled set. They return `Result`, failing with `SessionClosed` once the
  session has ended.
- **Commands travel on an unbounded channel, and the driver handles them
  last.** Request commands carry a reply channel their caller awaits, so each
  caller has at most one queued. `set_joiner_handler` and
  `clear_joiner_handler` stay synchronous and carry no reply, so a caller
  looping on them can grow the queue. The driver's loop takes due timers
  first, then received datagrams, then commands, so no volume of commands
  can delay a keep-alive, a retransmission, or a response. Timers before
  datagrams also means a response that arrives with its deadline already
  due is not accepted.
- **A dropped request is withdrawn.** Dropping the future of a request, for
  example under `tokio::time::timeout`, tells the driver. A queued request
  is then never sent, and a sent one stops being retransmitted and frees its
  slot; a late answer to it is dropped as unmatched.
- **One keep-alive at a time, and nothing new while resigning.** A second
  `keep_alive()` while one is outstanding fails with `InvalidState`, and once
  a resignation is outstanding, new requests, keep-alives, and resignations
  fail with `InvalidState("commissioner is resigning")`.
- **Read-modify-write steering updates are serialized.** `enable_joiner`
  holds a lock across its read and write of the commissioner dataset, and
  the other commissioner dataset writes take the same lock, so concurrent
  calls from cloned handles cannot drop a joiner.
- **A stopped task is reported.** If the driver task stops without ending the
  session (a panicking `JoinerHandler`, or runtime shutdown), `status()`
  reports `Closed` with `CloseReason::TaskStopped`. No `SessionLost` event
  is published in that case; the event stream just ends.
- **`resign()` also closes an unpetitioned session.** On a connect-only
  session there is nothing to resign, so it just ends the session.
- **`resign()` always ends the session**, even when the border agent does not
  confirm it; the error then reports the missing confirmation.
- **Recovery is not implemented.** Every session loss closes the session with
  a `CloseReason` and publishes `SessionLost`, which matches
  `Recovery::Never`. There is no `recovery` setting yet.
- **`max_in_flight` is fixed at 1** and not configurable yet.
- **Peer close.** `meshcop-dtls` now reports an authenticated `close_notify`
  as `Error::PeerClosed`. A connect-only session treats it as normal (status
  `Idle`, reopened on the next request); an active one ends with
  `CloseReason::PeerClosed`. A datagram may carry several records, and the
  session keeps the ones after the record it returns for the next receive,
  so a `close_notify` sent in the same datagram as application data is
  still seen.
- **Response matching is bound to the route and to response codes.**
  - A message arriving directly from the border agent can only answer,
    acknowledge, or reset a direct exchange, and one arriving in UDP_RX only
    a proxied exchange. A mesh device therefore cannot complete a keep-alive
    or other border-agent exchange.
  - The UDP_RX source address is not compared with the request's
    destination. Answers to anycast (ALOC) and multicast requests come from
    another address, and a device holding the network key can forge mesh
    source addresses anyway.
  - Tokens are 4 random bytes, unique among in-flight exchanges, rather than
    the message ID, so they cannot be predicted from earlier traffic.
  - Only 2.xx, 4.xx, and 5.xx codes can answer a request, so a notification
    or a reserved code class cannot complete one even if its token matches.
  - Only a strictly empty ACK (no token, options, or payload) stops
    retransmission.
- **Closing does not send `close_notify`.** Ending a session drops the DTLS
  state without telling the border agent, which then keeps its side until
  its own timeout. This predates phase 1; sending `close_notify` on close is
  a follow-up.
- **Known limitations.**
  - A retransmitted confirmable response is not acknowledged again once its
    exchange has completed, and duplicate confirmable notifications are not
    filtered, because there is no record of recently seen message IDs.
  - Message IDs count up from 1 for each driver and wrap without tracking
    RFC 7252's exchange lifetime. With one application request in flight,
    reusing an ID within its lifetime would take tens of thousands of
    requests in a few minutes.
  - The scripted harness delivers a proxied request's scripted answers in
    UDP_RX from the request's destination. Tests that need an answer at a
    chosen time, or one that depends on the assigned token, use
    `ScriptedMeshcopTransport::deliver`.
- **Runtimes.** The driver is `Send` and started with `tokio::spawn`, which
  also works on a `LocalRuntime` (stable since Tokio 1.51). The examples run
  on `#[tokio::main(flavor = "local")]`.

Verified against the live OpenThread border agent: an active session sent
keep-alives at 30 s and 60 s with no application activity and served a proxied
request afterwards, and a connect-only session went `Idle` at 50 s and reopened
for the next request.

## Phasing

1. **The driver itself.** Driver task, pending-request table, transport
   trait, async scripted harness, `Events`, automatic and manual
   keep-alive, `connect` and `connect_only`, `Recovery::Never` only,
   `max_in_flight` of 1. Port the CLI, netdiag, examples and tests. This is
   the breaking change.
2. **Recovery.** Reconnect policy (which becomes the default here),
   lifecycle events, commissioner dataset restore, conflict handling.
3. **Concurrency in practice.** `max_in_flight` above 1, and parallel
   `netdiag` queries.
4. **Discovery.** A `BorderAgentResolver` backed by mDNS, tracked separately
   because it adds a DNS-SD dependency.

## Decisions

- `connect` petitions; `connect_only` does not, and the session can be
  upgraded later with `petition()`.
- The default recovery policy is bounded `Reconnect`.
- The event buffer holds 64 events by default and is configurable.
- `connect` spawns the driver internally. A constructor that returns the
  driver future is additive and is deferred.

## Findings from the live border agent

Measured on 2026-09-23 against one border agent: `OpenThread BorderRouter
#45DB`, found over mDNS at 192.168.5.209:49156. Other vendors may behave
differently; nothing below has been checked beyond this one agent.

| Check | Unpetitioned | Petitioned |
|---|---|---|
| `MGMT_ACTIVE_GET` (mesh-local prefix, channel) | 2.04, values match the configured dataset | 2.04 |
| `UDP_TX` carrying `DIAG_GET.req` to the Leader ALOC | no answer and no error within 10 s | `UDP_RX` answered 2.04 with RLOC16 and Leader Data |
| Session lifetime, fully idle | closed with a warning-level `close_notify` alert at 49 s | not measured here |
| Session lifetime, `MGMT_ACTIVE_GET` every 10 s | closed with `close_notify` at 50 s | not measured |

Consequences for this design:

- **`connect_only`** suits reading datasets but not diagnostics. The border
  agent drops proxied traffic silently instead of rejecting it, so a
  missing library-side check would look like a timeout, not an error.
- **An unpetitioned session lasts about 50 s from the handshake, and
  activity does not extend it.** The driver must not hard-code 50 s. It
  reacts to the peer's `close_notify`.
- **`close_notify` currently surfaces as `Error::Crypto`.** `meshcop-dtls`
  `decode_alert_error` maps every alert to the same crypto error. The
  driver must tell an orderly peer close apart from a fatal alert:
  - in connect-only mode, `close_notify` is normal and leads to `Idle`;
  - in an active session, it is a `SessionLost` reason distinct from a
    handshake or crypto failure.

  This calls for a dedicated `meshcop-dtls` error variant, for example
  `PeerClosed`.
- **Petition and resign were answered with an empty ACK followed by a
  separate response.** The pending-request table must keep an entry open
  after an empty ACK, as described under "Request matching".
- **The border agent's address had changed** from the 192.168.4.48:49156
  in AGENTS.md to 192.168.5.209:49156. This is the `BorderAgentResolver`
  case in practice.

## Open questions

- Do other border agents behave the same way when unpetitioned? This
  covers Apple, Google, eero and SmartThings agents, all of which are
  visible on the local network.
