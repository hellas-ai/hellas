//! `Multiplexer` — the sans-io state machine.

use bytes::Bytes;

use crate::clock::Clock;
use crate::frame::{CreditFrame, EndFrame, Frame, OpenFrame, ResetFrame};
use crate::metadata::{Metadata, Trailer};
use crate::status::WireCode;

use super::slot::{Role, SlotIndex, StreamSlot};
use super::wire::{StreamKey, decode_keyed_frame, encode_keyed_frame};

#[derive(Clone, Copy, Debug)]
pub struct MuxConfig {
    /// Maximum unconsumed body bytes in either direction on one stream.
    /// This is also the maximum size of one atomic Body frame.
    pub stream_window: u32,
}

impl Default for MuxConfig {
    fn default() -> Self {
        Self {
            stream_window: super::DEFAULT_STREAM_WINDOW,
        }
    }
}

/// Events surfaced by `recv()` to the application driver. Each event
/// corresponds to a state-machine-validated incoming frame.
#[derive(Clone, Debug)]
pub enum Event {
    NewIncomingStream {
        slot: SlotIndex,
        method_id: u32,
        headers: Metadata,
    },
    BodyChunk {
        slot: SlotIndex,
        payload: Bytes,
    },
    EndStream {
        slot: SlotIndex,
        trailer: Trailer,
    },
    ResetStream {
        slot: SlotIndex,
        code: WireCode,
    },
    /// Peer added more credit; outbound flow may resume on this slot.
    PeerCredit {
        slot: SlotIndex,
        additional_bytes: u32,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum MuxError {
    #[error("at capacity (no free slot of our parity)")]
    AtCapacity,
    #[error("slot {0} is closed")]
    SlotClosed(SlotIndex),
    #[error("payload {len} exceeds body-frame max {limit}")]
    BodyTooLarge { len: usize, limit: usize },
    #[error("frame: {0}")]
    Frame(#[from] crate::frame::FrameError),
    #[error("protocol error: {0}")]
    Protocol(&'static str),
}

/// Result of attempting to hand one Body to the sans-I/O mux.
///
/// `Blocked` is readiness, not failure. The async transport driver owns the
/// payload and completes the caller's future once peer credit or queue space
/// becomes available.
#[derive(Debug)]
pub enum SendBodyOutcome {
    Accepted,
    Blocked(Bytes),
}

pub struct Multiplexer<const N: usize, C: Clock> {
    streams: [Option<StreamSlot>; N],
    /// Bitmap of free slot indices. `1` = free. One u64 word per 64 slots;
    /// allocated on construction since stable Rust can't size this as a
    /// const-generic array.
    free_mask: Vec<u64>,
    role: Role,
    /// At most one outbound frame is "currently being shipped" to the
    /// wire. Application driver polls `next_outbound` to drain.
    pending_write: Option<Bytes>,
    /// Slots whose local terminal frame has been emitted by
    /// `next_outbound` but whose free has been deferred until the
    /// caller has actually flushed the frame to the wire. We need
    /// this because a transport that backpressures will call
    /// `set_pending_write(Some(bytes))` to re-stash the terminal
    /// frame; if we'd freed the slot eagerly, the snapshot would
    /// contain a `pending_write` whose `(stream_id, generation)`
    /// references a freed slot and restore would reject. Drained at
    /// the top of `next_outbound` when `pending_write` is `None` —
    /// at that point the caller has implicitly acked by asking for
    /// the next frame.
    pending_terminal_free: Vec<SlotIndex>,
    /// Round-robin pointer for scheduling outbound from slots.
    rr: u16,
    clock: C,
    config: MuxConfig,
}

// The mux is not `Sync`; the sans-io contract assumes exclusive
// `&mut Multiplexer` access from a single driver (one CF DO
// callback, one connection task, etc.). Sharing across concurrent
// callbacks is undefined: stale `pending_terminal_free` reads, lost
// pushes, and out-of-order `next_outbound` drains would all break
// the snapshot invariants. Wrap in a `Mutex` if a transport ever
// needs cross-task access.
impl<const N: usize, C: Clock> Multiplexer<N, C> {
    pub fn new(role: Role, clock: C, config: MuxConfig) -> Self {
        let mut free_mask = vec![0u64; N.div_ceil(64)];
        // Mark all parity-owned slots free, others as not-our-domain.
        // We track ALL slots; just keep peer-owned slots out of the
        // free mask (we never allocate them; peer does).
        for i in 0..N as u16 {
            if role.owns_slot(i) {
                free_mask[(i / 64) as usize] |= 1u64 << (i % 64);
            }
        }
        Self {
            streams: [const { None }; N],
            free_mask,
            role,
            pending_write: None,
            pending_terminal_free: Vec::new(),
            rr: 0,
            clock,
            config,
        }
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn config(&self) -> &MuxConfig {
        &self.config
    }

    /// The generation currently seated in a slot, if the slot has ever
    /// been used.
    ///
    /// A slot index is recycled, so an index on its own does not name a
    /// stream — the `(index, generation)` pair does. That is already how
    /// every frame on the wire is addressed; this lets everything above
    /// the state machine address a stream the same way.
    pub fn generation(&self, idx: SlotIndex) -> Option<u16> {
        self.slot(idx).map(|slot| slot.generation)
    }

    fn lowest_free(&self) -> Option<SlotIndex> {
        for (word_idx, word) in self.free_mask.iter().enumerate() {
            if *word != 0 {
                let bit = word.trailing_zeros() as u16;
                return Some(word_idx as u16 * 64 + bit);
            }
        }
        None
    }

    fn mark_used(&mut self, idx: SlotIndex) {
        let word = idx / 64;
        let bit = idx % 64;
        self.free_mask[word as usize] &= !(1u64 << bit);
    }

    fn mark_free(&mut self, idx: SlotIndex) {
        // Only mark free if we own this parity; otherwise the peer
        // owns the slot and we shouldn't claim it.
        if self.role.owns_slot(idx) {
            let word = idx / 64;
            let bit = idx % 64;
            self.free_mask[word as usize] |= 1u64 << bit;
        }
    }

    fn slot(&self, idx: SlotIndex) -> Option<&StreamSlot> {
        self.streams.get(idx as usize)?.as_ref()
    }

    fn slot_mut(&mut self, idx: SlotIndex) -> Option<&mut StreamSlot> {
        self.streams.get_mut(idx as usize)?.as_mut()
    }

    // -- Local actions -------------------------------------------------------

    /// Allocate a slot and queue an OPEN frame. Returns the slot index.
    pub fn open(&mut self, method_id: u32, headers: Metadata) -> Result<SlotIndex, MuxError> {
        // Reclaim any slots whose local terminal frame has been
        // emitted but not yet reaped. Without this, an `open()`
        // call right after a `reset()`+`next_outbound()` cycle
        // wouldn't see the just-closed slot as free.
        self.drain_pending_terminal_free();
        let idx = self.lowest_free().ok_or(MuxError::AtCapacity)?;
        // Compute new generation from any prior occupant (we keep a
        // generation counter even when slot is Empty by carrying it forward
        // through the Option<StreamSlot>'s prior values; for simplicity
        // we just start at generation=0 first time and bump on each reuse).
        let prev_gen = self
            .streams
            .get(idx as usize)
            .and_then(|s| s.as_ref().map(|s| s.generation))
            .unwrap_or(0u16);
        let next_gen = prev_gen.wrapping_add(1);

        let now = self.clock.now();
        let mut slot = StreamSlot::open(method_id, now, self.config.stream_window);
        slot.generation = next_gen;
        // Queue the OPEN frame for scheduler.
        slot.send_queue
            .push_back(Frame::Open(OpenFrame { method_id, headers }));
        self.streams[idx as usize] = Some(slot);
        self.mark_used(idx);
        Ok(idx)
    }

    /// Try to queue one body chunk on this slot.
    ///
    /// Closed streams and invalid frames are errors. Exhausted peer credit or
    /// the previous Body still occupying the one-frame staging slot are
    /// transient readiness states returned as [`SendBodyOutcome::Blocked`].
    pub fn try_send_body(
        &mut self,
        idx: SlotIndex,
        payload: Bytes,
    ) -> Result<SendBodyOutcome, MuxError> {
        if payload.len() > self.config.stream_window as usize {
            return Err(MuxError::BodyTooLarge {
                len: payload.len(),
                limit: self.config.stream_window as usize,
            });
        }
        let slot = self
            .slot_mut(idx)
            .ok_or(MuxError::Protocol("send on empty slot"))?;
        if slot.local_terminal {
            return Err(MuxError::SlotClosed(idx));
        }
        if (slot.peer_recv_credit as usize) < payload.len() {
            return Ok(SendBodyOutcome::Blocked(payload));
        }
        // SendHalf single-frame contract: only one Body may be staged per
        // slot. The async driver retains and retries a blocked payload.
        let has_body_queued = slot.send_queue.iter().any(|f| matches!(f, Frame::Body(_)));
        if has_body_queued {
            return Ok(SendBodyOutcome::Blocked(payload));
        }
        if slot.send_queue.len() >= crate::mux::slot::SLOT_QUEUE_CAP {
            return Err(MuxError::Protocol("send queue full"));
        }
        slot.peer_recv_credit -= payload.len() as u32;
        slot.send_queue.push_back(Frame::Body(payload));
        Ok(SendBodyOutcome::Accepted)
    }

    /// Close the send side. Optionally with a trailer.
    pub fn close_send(&mut self, idx: SlotIndex, trailer: Option<Trailer>) -> Result<(), MuxError> {
        let slot = self
            .slot_mut(idx)
            .ok_or(MuxError::Protocol("close on empty slot"))?;
        if slot.local_terminal {
            return Ok(());
        }
        if slot.send_queue.len() >= crate::mux::slot::SLOT_QUEUE_CAP {
            return Err(MuxError::Protocol("close while queue full"));
        }
        let trailer = trailer.unwrap_or_default();
        let end = EndFrame {
            status: trailer.status,
            trailer,
        };
        slot.local_terminal = true;
        // End frame goes at the BACK — any in-flight Body should ship
        // first.
        slot.send_queue.push_back(Frame::End(end));
        Ok(())
    }

    /// Cancel both directions. Idempotent.
    pub fn reset(&mut self, idx: SlotIndex, code: WireCode) {
        let Some(slot) = self.slot_mut(idx) else {
            return;
        };
        if slot.local_terminal && slot.peer_terminal {
            return;
        }
        slot.local_terminal = true;
        slot.peer_terminal = true;
        // Reset takes priority over any in-flight frames — push to front
        // and drop everything behind it (they'd be irrelevant on the
        // closed stream anyway).
        slot.send_queue.clear();
        slot.send_queue
            .push_front(Frame::Reset(ResetFrame { code }));
    }

    /// Return receive credit after the application takes ownership of a Body.
    ///
    /// Credit is tied to consumption rather than socket receipt, so the
    /// advertised window genuinely bounds bytes queued inside the transport.
    /// Multiple consumption notifications that arrive before the next wire
    /// flush are coalesced into one Credit frame.
    pub fn consume(&mut self, idx: SlotIndex, bytes: u32) -> Result<(), MuxError> {
        if bytes == 0 {
            return Ok(());
        }
        let Some(slot) = self.slot_mut(idx) else {
            // A peer may send Body followed by End before the application
            // polls the buffered Body. No credit is useful after reclamation.
            return Ok(());
        };
        if slot.peer_terminal {
            return Ok(());
        }
        let available = slot.local_credit_high_water - slot.local_recv_credit;
        if bytes > available {
            return Err(MuxError::Protocol("consumed more body bytes than received"));
        }
        slot.local_recv_credit += bytes;
        if let Some(Frame::Credit(credit)) = slot
            .send_queue
            .iter_mut()
            .find(|frame| matches!(frame, Frame::Credit(_)))
        {
            credit.additional_bytes = credit.additional_bytes.saturating_add(bytes);
        } else {
            slot.send_queue.push_front(Frame::Credit(CreditFrame {
                additional_bytes: bytes,
            }));
        }
        Ok(())
    }

    // -- I/O surface ---------------------------------------------------------

    /// Drain the next outbound encoded frame. Returns `Some(bytes)` to
    /// ship; `None` if nothing pending.
    ///
    /// Round-robins through slots; honors the single-pending invariant.
    pub fn next_outbound(&mut self) -> Option<Bytes> {
        if let Some(pending) = self.pending_write.take() {
            return Some(pending);
        }
        // Caller is asking for the next frame without re-stashing the
        // previous one, so any terminal frame we emitted last call is
        // now considered shipped. Free its slot before scanning so a
        // newly-opened slot can reclaim the index.
        self.drain_pending_terminal_free();
        for _ in 0..N {
            let idx = self.rr;
            self.rr = (self.rr + 1) % (N as u16);
            let Some(slot) = self.streams.get_mut(idx as usize).and_then(|s| s.as_mut()) else {
                continue;
            };
            if let Some(frame) = slot.send_queue.pop_front() {
                let key = StreamKey {
                    stream_id: idx,
                    generation: slot.generation,
                };
                let was_terminal = matches!(frame, Frame::End(_) | Frame::Reset(_));
                let queue_empty_after_pop = slot.send_queue.is_empty();
                let both_terminal = slot.local_terminal && slot.peer_terminal;
                let bytes = encode_keyed_frame(key, &frame);
                // Queue idx for deferred free if EITHER:
                //   (a) we just emitted a terminal frame — the
                //       free-on-ship-ack contract applies.
                //   (b) the slot is now both-terminal AND its
                //       queue is empty AFTER this pop — the slot
                //       has no more work to do; a non-terminal
                //       frame (e.g. a Credit) just drained the
                //       last buffered byte. Without this push the
                //       slot would orphan: state=Closed, bit
                //       clear, no path back to maybe_free_slot.
                let needs_defer = was_terminal || (both_terminal && queue_empty_after_pop);
                if needs_defer && !self.pending_terminal_free.contains(&idx) {
                    self.pending_terminal_free.push(idx);
                }
                return Some(bytes);
            }
        }
        None
    }

    /// Tidy up state that becomes inconsistent when a recv-side
    /// terminal frees a slot that has lingering deferred-free or
    /// pending-write references. Called after `maybe_free_slot`
    /// fires inside the recv path. Three things to scrub:
    ///   1. Stale entry in `pending_terminal_free` (the slot is
    ///      already free, so the deferred drain would no-op but
    ///      we should keep the list honest).
    ///   2. `pending_write` keyed to this idx — its slot is gone,
    ///      so the bytes would fail snapshot restoration
    ///      validation. Drop them; the peer's terminal already
    ///      tore down the stream on their side.
    fn clean_up_after_remote_free(&mut self, idx: SlotIndex) {
        self.pending_terminal_free.retain(|&i| i != idx);
        if let Some(bytes) = &self.pending_write
            && bytes.len() >= 4
        {
            let stream_id = u16::from_be_bytes([bytes[0], bytes[1]]);
            if stream_id == idx {
                self.pending_write = None;
            }
        }
    }

    /// Reap slots in the deferred terminal-free list. Called by
    /// `next_outbound` (when `pending_write` is `None`, signaling
    /// the caller has implicitly acked the previous emission) and
    /// `open` (so a freshly-closed slot can be reallocated).
    ///
    /// Entries whose slot can't yet be freed — e.g. a `reset()`
    /// queued a Reset frame after the terminal emit — are KEPT
    /// in the list so the next round of draining (after the queued
    /// frame ships) can finish the job.
    fn drain_pending_terminal_free(&mut self) {
        if self.pending_terminal_free.is_empty() {
            return;
        }
        let drained = core::mem::take(&mut self.pending_terminal_free);
        for idx in drained {
            if !self.maybe_free_slot(idx) {
                self.pending_terminal_free.push(idx);
            }
        }
    }

    /// Try to free a slot. Returns `true` if the slot was reclaimed.
    ///
    /// A slot may be freed iff (a) both sides have signalled terminal
    /// AND (b) no outbound frames remain in the slot's send_queue —
    /// the latter handles the case where `close_send` queued an End,
    /// the End was emitted (deferred-free), and the app then called
    /// `reset()` which queued a Reset. Clearing send_queue here would
    /// silently drop that Reset; callers must keep the slot occupied
    /// until the queued terminal is actually emitted.
    fn maybe_free_slot(&mut self, idx: SlotIndex) -> bool {
        let Some(slot) = self.slot(idx) else {
            return false;
        };
        if !(slot.peer_terminal && slot.local_terminal) {
            return false;
        }
        if !slot.send_queue.is_empty() {
            return false;
        }
        self.mark_free(idx);
        true
    }

    /// Feed an inbound keyed-frame's bytes. Validates, applies state
    /// transitions, returns observable events. Stale-generation frames are
    /// discarded with no event.
    pub fn recv(&mut self, bytes: &[u8]) -> Result<Vec<Event>, MuxError> {
        let keyed = decode_keyed_frame(bytes)?;
        let idx = keyed.key.stream_id;
        if idx as usize >= N {
            return Err(MuxError::Protocol("stream id out of range"));
        }
        let mut events = Vec::new();

        // Handle Open specially — slot may be Empty (legitimate fresh open)
        // or in some terminal/transitional state.
        if let Frame::Open(open) = &keyed.frame {
            // Open from peer: must be peer-owned parity.
            if self.role.owns_slot(idx) {
                return Err(MuxError::Protocol("peer opened a slot owned by our parity"));
            }
            // Stale-generation check: if slot exists, compare gens.
            if let Some(existing) = self.slot(idx) {
                if !existing.is_closed() {
                    return Err(MuxError::Protocol("peer re-opened active slot"));
                }
                // Slot closed; peer can reuse but must bump generation.
                if keyed.key.generation == existing.generation {
                    return Err(MuxError::Protocol(
                        "peer reused slot without bumping generation",
                    ));
                }
            }
            let now = self.clock.now();
            let mut slot = StreamSlot::open(open.method_id, now, self.config.stream_window);
            slot.generation = keyed.key.generation;
            self.streams[idx as usize] = Some(slot);
            // The fresh slot record overwrites a Closed predecessor.
            // Any leftover references to the OLD slot — a deferred
            // terminal-free entry or a `pending_write` keyed to the
            // prior generation — would now point at a slot whose
            // state machine has wound forward, breaking invariant
            // I2 (term_free idx must be in HalfClosedLocal/Closed)
            // and I4 (pending_write key must match an occupied
            // slot). Scrub them.
            self.clean_up_after_remote_free(idx);
            events.push(Event::NewIncomingStream {
                slot: idx,
                method_id: open.method_id,
                headers: open.headers.clone(),
            });
            return Ok(events);
        }

        // Non-Open frames: slot must exist with matching generation.
        let slot = match self.slot_mut(idx) {
            Some(s) => s,
            None => return Ok(events), // stale; drop silently
        };
        if slot.generation != keyed.key.generation {
            return Ok(events); // stale-generation drop
        }
        if slot.peer_terminal {
            return Ok(events); // peer already terminal; drop late frames
        }

        match keyed.frame {
            Frame::Open(_) => unreachable!("handled above"),
            Frame::Body(payload) => {
                let n = payload.len() as u32;
                if n > slot.local_recv_credit {
                    // Peer overran our credit. Reset their stream.
                    let code = WireCode::ResourceExhausted;
                    slot.peer_terminal = true;
                    slot.local_terminal = true;
                    slot.send_queue.clear();
                    slot.send_queue
                        .push_front(Frame::Reset(ResetFrame { code }));
                    events.push(Event::ResetStream { slot: idx, code });
                    return Ok(events);
                }
                slot.local_recv_credit -= n;
                // Forward the chunk via the event channel; do NOT also
                // retain it in recv_buf. The driver that surfaces
                // BodyChunk events is responsible for forwarding bytes
                // to the application; recv_buf is dead code in the
                // events-flow path.
                //
                // Credit does not refill here. The receive half returns it
                // through `consume()` only when the application polls this
                // Body from its transport queue.
                events.push(Event::BodyChunk { slot: idx, payload });
            }
            Frame::End(end) => {
                slot.peer_terminal = true;
                events.push(Event::EndStream {
                    slot: idx,
                    trailer: end.trailer,
                });
                if self.maybe_free_slot(idx) {
                    self.clean_up_after_remote_free(idx);
                }
            }
            Frame::Reset(r) => {
                slot.peer_terminal = true;
                slot.local_terminal = true;
                // Peer aborted — any frames we had queued for this
                // stream are pointless. Drop them so the slot can be
                // reclaimed immediately rather than waiting for a
                // terminal emit that the peer doesn't care about.
                slot.send_queue.clear();
                events.push(Event::ResetStream {
                    slot: idx,
                    code: r.code,
                });
                self.maybe_free_slot(idx);
                self.clean_up_after_remote_free(idx);
            }
            Frame::Credit(c) => {
                slot.peer_recv_credit = slot.peer_recv_credit.saturating_add(c.additional_bytes);
                events.push(Event::PeerCredit {
                    slot: idx,
                    additional_bytes: c.additional_bytes,
                });
            }
        }
        Ok(events)
    }
}

#[cfg(test)]
mod tests;
