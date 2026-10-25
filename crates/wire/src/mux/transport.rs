//! `MuxTransport`: glues the sans-io `Multiplexer` to a concrete bidi
//! byte pipe + spawns the I/O loop. Used by `ws::native` (tokio spawn)
//! and `ws::wasm` (wasm_bindgen spawn_local). The CF DO flavor drives
//! the mux directly without this wrapper (callback I/O).

use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::{Mutex, mpsc, oneshot};

use crate::clock::Clock;
use crate::metadata::Metadata;
use crate::status::WireCode;
use crate::transport::{Inbound, StreamTransport, TransportContext};

use super::slot::{Role, SlotIndex};
use super::state::{Event, Multiplexer, MuxConfig, MuxError};
use super::stream::MuxStream;
use super::wire::StreamKey;

/// Trait for the underlying message-oriented byte pipe (one WS message
/// = one mux frame). Implemented by the ws-native + ws-wasm adapters.
pub trait MessagePipe: Send + 'static {
    type SendError: std::error::Error + Send + Sync + 'static;
    type RecvError: std::error::Error + Send + Sync + 'static;

    fn send_message(
        &mut self,
        bytes: Bytes,
    ) -> impl std::future::Future<Output = Result<(), Self::SendError>> + Send;

    /// A protected frame must reach the carrier through its current authority
    /// callback. A pipe that cannot do this must never send the frame.
    fn send_message_authorized(
        &mut self,
        _bytes: Bytes,
        _authority: &crate::WriteAuthority,
    ) -> impl std::future::Future<Output = std::io::Result<()>> + Send {
        async {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "pipe cannot authorize writes",
            ))
        }
    }

    fn recv_message(
        &mut self,
    ) -> impl std::future::Future<Output = Result<Option<Bytes>, Self::RecvError>> + Send;
}

/// Commands the I/O loop accepts. The MuxTransport's public API funnels
/// through these so `Multiplexer` can stay sans-io.
///
/// Everything but `Open` names an existing stream, and names it by the
/// same `StreamKey` the wire uses. A bare slot index would not do: a
/// command travels a channel and is served later, by which time the peer
/// may have seated a different stream in that index.
pub(crate) enum Command {
    Open {
        method_id: u32,
        headers: Metadata,
        reply: oneshot::Sender<Result<MuxStream, MuxError>>,
    },
    SendBody {
        key: StreamKey,
        payload: Bytes,
        reply: oneshot::Sender<Result<(), MuxError>>,
        authority: Option<crate::WriteAuthority>,
    },
    CloseSend {
        key: StreamKey,
        trailer: Option<crate::metadata::Trailer>,
        reply: oneshot::Sender<Result<(), MuxError>>,
        authority: Option<crate::WriteAuthority>,
    },
    Reset {
        key: StreamKey,
        code: WireCode,
    },
    Consumed {
        key: StreamKey,
        bytes: u32,
    },
}

#[derive(Clone)]
pub struct MuxTransport {
    cmd_tx: mpsc::UnboundedSender<Command>,
    inbound_rx: Arc<Mutex<mpsc::Receiver<Inbound<MuxStream>>>>,
    /// What the enclosing session vouches for: the peer it authenticated,
    /// and the keying material it can export. A mux is carried by
    /// something else — a WebSocket, a QUIC connection — and only that
    /// carrier knows either. It is held here as well as in the driver so
    /// outbound callers read the same facts inbound ones are handed.
    context: TransportContext,
}

#[derive(Debug, thiserror::Error)]
pub enum MuxTransportError {
    #[error("mux: {0}")]
    Mux(#[from] MuxError),
    #[error("transport closed")]
    Closed,
}

impl MuxTransport {
    /// Spawn the I/O loop using the default native spawn (tokio).
    /// Wasm callers use `spawn_with` instead, passing
    /// `wasm_bindgen_futures::spawn_local`.
    #[cfg(not(target_family = "wasm"))]
    pub fn spawn<const N: usize, C: Clock + Clone, P: MessagePipe>(
        role: Role,
        clock: C,
        config: MuxConfig,
        pipe: P,
        context: TransportContext,
    ) -> Self {
        Self::spawn_with::<N, C, P, _>(role, clock, config, pipe, context, |fut| {
            tokio::spawn(fut);
        })
    }

    /// Spawn the I/O loop using a caller-provided spawn function.
    /// Native callers pass `tokio::spawn`; wasm callers pass
    /// `wasm_bindgen_futures::spawn_local`.
    ///
    /// The spawn function MUST poll the future to completion in
    /// the background — it should not block.
    pub fn spawn_with<const N: usize, C: Clock + Clone, P: MessagePipe, F>(
        role: Role,
        clock: C,
        config: MuxConfig,
        pipe: P,
        context: TransportContext,
        spawn: F,
    ) -> Self
    where
        F: FnOnce(std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>),
    {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (inbound_tx, inbound_rx) = mpsc::channel((N / 2).max(1));

        let mux = Multiplexer::<N, C>::new(role, clock, config);
        let driver = MuxDriver::<N, C, P> {
            mux,
            pipe,
            cmd_rx,
            cmd_tx: cmd_tx.downgrade(),
            inbound_tx,
            slot_to_chans: Default::default(),
            pending_sends: Default::default(),
            authorities: Default::default(),
            context: context.clone(),
        };
        spawn(Box::pin(driver.run()));

        Self {
            cmd_tx,
            inbound_rx: Arc::new(Mutex::new(inbound_rx)),
            context,
        }
    }
}

impl StreamTransport for MuxTransport {
    type Stream = MuxStream;
    type Error = MuxTransportError;

    fn context(&self) -> TransportContext {
        self.context.clone()
    }

    async fn open(&self, method_id: u32, headers: Metadata) -> Result<Self::Stream, Self::Error> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Open {
                method_id,
                headers,
                reply: tx,
            })
            .map_err(|_| MuxTransportError::Closed)?;
        rx.await
            .map_err(|_| MuxTransportError::Closed)?
            .map_err(Into::into)
    }

    async fn accept(&self) -> Result<Option<Inbound<Self::Stream>>, Self::Error> {
        let mut rx = self.inbound_rx.lock().await;
        Ok(rx.recv().await)
    }
}

struct MuxDriver<const N: usize, C: Clock + Clone, P: MessagePipe> {
    mux: Multiplexer<N, C>,
    pipe: P,
    cmd_rx: mpsc::UnboundedReceiver<Command>,
    /// Weak by design: the driver must not keep its own command channel
    /// alive. Real transport/stream owners hold the strong senders.
    cmd_tx: mpsc::WeakUnboundedSender<Command>,
    inbound_tx: mpsc::Sender<Inbound<MuxStream>>,
    /// Per-slot channels owned by application halves. `Body`/`End`/
    /// `Reset` events are forwarded into the slot's recv channel; the
    /// I/O loop sends Body acks to the slot's send-side oneshots.
    slot_to_chans: std::collections::HashMap<SlotIndex, SlotChannels>,
    /// At most one blocked send per slot; `SendHalf::send_body` takes
    /// `&mut self`, so well-formed callers cannot create a second one.
    pending_sends: std::collections::HashMap<SlotIndex, PendingSend>,
    authorities: std::collections::HashMap<StreamKey, crate::WriteAuthority>,
    context: TransportContext,
}

struct PendingSend {
    payload: Bytes,
    reply: oneshot::Sender<Result<(), MuxError>>,
}

struct SlotChannels {
    recv_tx: mpsc::UnboundedSender<Result<Bytes, std::io::Error>>,
    trailer_tx: Option<oneshot::Sender<crate::metadata::Trailer>>,
}

impl<const N: usize, C: Clock + Clone, P: MessagePipe> MuxDriver<N, C, P> {
    async fn run(mut self) {
        loop {
            tokio::select! {
                key = futures::future::poll_fn(|cx| {
                    for (key, authority) in &self.authorities {
                        if let std::task::Poll::Ready(Err(_)) = authority.poll_check(cx) {
                            return std::task::Poll::Ready(*key);
                        }
                    }
                    std::task::Poll::Pending
                }) => {
                    self.authorities.remove(&key);
                    if let Some(slot) = self.live(key) {
                        self.dispatch_event(Event::ResetStream { slot, code: WireCode::PermissionDenied });
                        self.mux.reset(slot, WireCode::PermissionDenied);
                    }
                },
                cmd = self.cmd_rx.recv() => match cmd {
                    Some(c) => self.handle_command(c).await,
                    None => break,
                },
                msg = self.pipe.recv_message() => match msg {
                    Ok(Some(bytes)) => self.handle_inbound(bytes).await,
                    Ok(None) | Err(_) => break,
                },
            }
            if !self.flush_outbound().await {
                break;
            }
        }
    }

    async fn handle_command(&mut self, cmd: Command) {
        match cmd {
            Command::Open {
                method_id,
                headers,
                reply,
            } => {
                let result = self
                    .cmd_tx_clone()
                    .ok_or(MuxError::Protocol(
                        "transport owner disappeared while opening stream",
                    ))
                    .and_then(|cmd_tx| {
                        self.mux
                            .open(method_id, headers)
                            .and_then(|slot| self.register_stream(slot, cmd_tx))
                    });
                let _ = reply.send(result);
            }
            Command::SendBody {
                key,
                payload,
                reply,
                authority,
            } => match self.live(key) {
                Some(slot) => {
                    if let Some(authority) = authority {
                        self.authorities.entry(key).or_insert(authority);
                    }
                    self.start_send(slot, payload, reply);
                }
                None => {
                    let _ = reply.send(Err(MuxError::SlotClosed(key.stream_id)));
                }
            },
            Command::CloseSend {
                key,
                trailer,
                reply,
                authority,
            } => {
                let result = match self.live(key) {
                    Some(slot) => {
                        if let Some(authority) = authority {
                            self.authorities.entry(key).or_insert(authority);
                        }
                        self.mux.close_send(slot, trailer)
                    }
                    None => Err(MuxError::SlotClosed(key.stream_id)),
                };
                let _ = reply.send(result);
            }
            Command::Reset { key, code } => {
                self.authorities.remove(&key);
                if let Some(slot) = self.live(key) {
                    self.fail_pending_send(slot);
                    self.mux.reset(slot, code);
                }
            }
            Command::Consumed { key, bytes } => {
                if let Some(slot) = self.live(key)
                    && let Err(error) = self.mux.consume(slot, bytes)
                {
                    tracing::warn!("mux consume error: {error}");
                }
            }
        }
    }

    /// Resolve a command's stream key to the slot it may act on.
    ///
    /// A command is written when its stream is alive and served some time
    /// later, and `MuxRecvHalf`'s drop writes one after the caller has
    /// finished with the stream entirely. If the index has since been
    /// re-seated — a fresh `open`, or a peer's `Open` on an index whose
    /// terminals have both crossed — the stream the command names no
    /// longer exists, and the one occupying its index belongs to someone
    /// else. Refuse rather than act on the wrong stream.
    fn live(&self, key: StreamKey) -> Option<SlotIndex> {
        (self.mux.generation(key.stream_id) == Some(key.generation)).then_some(key.stream_id)
    }

    /// Wire a freshly-seated slot to a `MuxStream`: the driver keeps the
    /// sending ends, the stream keeps the receiving ends and the key that
    /// names it for as long as it lives.
    ///
    /// The generation is read back from the mux rather than assumed, so a
    /// stream can only ever be handed a key the state machine agrees with.
    fn register_stream(
        &mut self,
        slot: SlotIndex,
        cmd_tx: mpsc::UnboundedSender<Command>,
    ) -> Result<MuxStream, MuxError> {
        self.authorities.retain(|key, _| key.stream_id != slot);
        let generation = self
            .mux
            .generation(slot)
            .ok_or(MuxError::Protocol("mux seated no stream in this slot"))?;
        let (recv_tx, recv_rx) = mpsc::unbounded_channel();
        let (trailer_tx, trailer_rx) = oneshot::channel();
        self.slot_to_chans.insert(
            slot,
            SlotChannels {
                recv_tx,
                trailer_tx: Some(trailer_tx),
            },
        );
        Ok(MuxStream::new(
            StreamKey::new(slot, generation),
            cmd_tx,
            recv_rx,
            trailer_rx,
        ))
    }

    fn cmd_tx_clone(&self) -> Option<mpsc::UnboundedSender<Command>> {
        self.cmd_tx.upgrade()
    }

    fn start_send(
        &mut self,
        slot: SlotIndex,
        payload: Bytes,
        reply: oneshot::Sender<Result<(), MuxError>>,
    ) {
        if self.pending_sends.contains_key(&slot) {
            let _ = reply.send(Err(MuxError::Protocol(
                "concurrent send_body calls on one stream",
            )));
            return;
        }
        match self.mux.try_send_body(slot, payload) {
            Ok(super::state::SendBodyOutcome::Accepted) => {
                let _ = reply.send(Ok(()));
            }
            Ok(super::state::SendBodyOutcome::Blocked(payload)) => {
                self.pending_sends
                    .insert(slot, PendingSend { payload, reply });
            }
            Err(error) => {
                let _ = reply.send(Err(error));
            }
        }
    }

    /// Retry one send after peer credit arrives or the staged Body drains.
    /// Returns true when a new Body was accepted and needs flushing.
    fn retry_pending_send(&mut self, slot: SlotIndex) -> bool {
        let Some(pending) = self.pending_sends.remove(&slot) else {
            return false;
        };
        match self.mux.try_send_body(slot, pending.payload) {
            Ok(super::state::SendBodyOutcome::Accepted) => {
                let _ = pending.reply.send(Ok(()));
                true
            }
            Ok(super::state::SendBodyOutcome::Blocked(payload)) => {
                self.pending_sends.insert(
                    slot,
                    PendingSend {
                        payload,
                        reply: pending.reply,
                    },
                );
                false
            }
            Err(error) => {
                let _ = pending.reply.send(Err(error));
                false
            }
        }
    }

    fn retry_pending_sends(&mut self) -> bool {
        let slots: Vec<_> = self.pending_sends.keys().copied().collect();
        let mut accepted = false;
        for slot in slots {
            accepted |= self.retry_pending_send(slot);
        }
        accepted
    }

    fn fail_pending_send(&mut self, slot: SlotIndex) {
        if let Some(pending) = self.pending_sends.remove(&slot) {
            let _ = pending.reply.send(Err(MuxError::SlotClosed(slot)));
        }
    }

    async fn handle_inbound(&mut self, bytes: Bytes) {
        match self.mux.recv(&bytes) {
            Ok(events) => {
                for ev in events {
                    self.dispatch_event(ev);
                }
            }
            Err(e) => {
                tracing::warn!("mux recv error: {e}");
            }
        }
    }

    fn dispatch_event(&mut self, ev: Event) {
        match ev {
            Event::NewIncomingStream {
                slot,
                method_id,
                headers,
            } => {
                let Some(stream) = self
                    .cmd_tx_clone()
                    .and_then(|cmd_tx| self.register_stream(slot, cmd_tx).ok())
                else {
                    self.mux.reset(slot, WireCode::Cancelled);
                    return;
                };
                let inbound = Inbound {
                    method_id,
                    headers,
                    stream,
                    context: self.context.clone(),
                };
                if let Err(error) = self.inbound_tx.try_send(inbound) {
                    let code = match error {
                        mpsc::error::TrySendError::Full(_) => WireCode::ResourceExhausted,
                        mpsc::error::TrySendError::Closed(_) => WireCode::Cancelled,
                    };
                    self.mux.reset(slot, code);
                    self.dispatch_event(Event::ResetStream { slot, code });
                }
            }
            Event::BodyChunk { slot, payload } => {
                let delivered = self
                    .slot_to_chans
                    .get(&slot)
                    .is_some_and(|chans| chans.recv_tx.send(Ok(payload)).is_ok());
                if !delivered {
                    self.slot_to_chans.remove(&slot);
                    self.fail_pending_send(slot);
                    self.mux.reset(slot, WireCode::Cancelled);
                }
            }
            Event::EndStream { slot, trailer } => {
                if let Some(mut chans) = self.slot_to_chans.remove(&slot)
                    && let Some(t) = chans.trailer_tx.take()
                {
                    let _ = t.send(trailer);
                }
            }
            Event::ResetStream { slot, code } => {
                self.authorities.retain(|key, _| key.stream_id != slot);
                self.fail_pending_send(slot);
                if let Some(mut chans) = self.slot_to_chans.remove(&slot)
                    && let Some(t) = chans.trailer_tx.take()
                {
                    let _ = t.send(crate::metadata::Trailer::from_status(code, "reset"));
                }
            }
            Event::PeerCredit { slot, .. } => {
                self.retry_pending_send(slot);
            }
        }
    }

    /// Flush staged frames, then retry sends that were waiting only for the
    /// one-frame staging slot to drain. Credit-blocked sends remain pending
    /// until their peer's Credit event arrives.
    async fn flush_outbound(&mut self) -> bool {
        loop {
            while let Some(bytes) = self.mux.next_outbound() {
                let Some((key, kind)) = super::wire::keyed_frame_header(&bytes) else {
                    return false;
                };
                let authority = if matches!(kind, crate::FrameKind::Body | crate::FrameKind::End) {
                    self.authorities.get(&key)
                } else {
                    None
                };
                let result = if let Some(authority) = authority {
                    self.pipe.send_message_authorized(bytes, authority).await
                } else {
                    self.pipe
                        .send_message(bytes)
                        .await
                        .map_err(std::io::Error::other)
                };
                if let Err(e) = result {
                    tracing::warn!("pipe send: {e}");
                    return false;
                }
                if matches!(kind, crate::FrameKind::End | crate::FrameKind::Reset) {
                    self.authorities.remove(&key);
                }
            }
            if !self.retry_pending_sends() {
                return true;
            }
        }
    }
}

#[cfg(test)]
mod tests;
