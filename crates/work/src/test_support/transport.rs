use bytes::Bytes;
use hellas_wire::DefaultClock;
use hellas_wire::mux::{MessagePipe, MuxConfig, MuxTransport, Role as MuxRole};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::mpsc;

const EXPORTER: [u8; 32] = [0x5e; 32];

struct Pipe {
    out: mpsc::UnboundedSender<Bytes>,
    inbox: mpsc::UnboundedReceiver<Bytes>,
    gate: Option<Arc<CarrierGate>>,
    strict_send: bool,
}

/// Backpressure at the carrier handoff, after RPC encoding and mux queue/credit work.
pub struct CarrierGate {
    pub remaining: AtomicUsize,
    pub sent: AtomicUsize,
    pub blocked: tokio::sync::Notify,
    pub ready: futures::task::AtomicWaker,
}

impl MessagePipe for Pipe {
    type SendError = std::io::Error;
    type RecvError = std::io::Error;

    async fn send_message(&mut self, bytes: Bytes) -> Result<(), Self::SendError> {
        let sent = self.out.send(bytes).map_err(std::io::Error::other);
        if self.strict_send { sent } else { Ok(()) }
    }

    async fn recv_message(&mut self) -> Result<Option<Bytes>, Self::RecvError> {
        Ok(self.inbox.recv().await)
    }

    async fn send_message_authorized(
        &mut self,
        bytes: Bytes,
        authority: &hellas_wire::WriteAuthority,
    ) -> std::io::Result<()> {
        futures::future::poll_fn(|cx| {
            authority.poll_write(cx, &mut |cx| {
                if let Some(gate) = &self.gate {
                    gate.ready.register(cx.waker());
                    if gate.remaining.load(Ordering::SeqCst) == 0 {
                        gate.blocked.notify_one();
                        return std::task::Poll::Pending;
                    }
                    gate.remaining.fetch_sub(1, Ordering::SeqCst);
                    gate.sent.fetch_add(1, Ordering::SeqCst);
                }
                std::task::Poll::Ready(
                    self.out
                        .send(bytes.clone())
                        .map(|()| bytes.len())
                        .map_err(std::io::Error::other),
                )
            })
        })
        .await?;
        Ok(())
    }
}

fn session() -> hellas_wire::TransportContext {
    hellas_wire::TransportContext {
        open_exporter: Some(EXPORTER),
        ..hellas_wire::TransportContext::default()
    }
}

pub fn transport_pair() -> (MuxTransport, MuxTransport) {
    transport_pair_with_context(session(), session())
}

pub fn transport_pair_with_context(
    client_context: hellas_wire::TransportContext,
    server_context: hellas_wire::TransportContext,
) -> (MuxTransport, MuxTransport) {
    pair(client_context, server_context, None, false)
}

pub fn transport_pair_with_server_gate(
    context: hellas_wire::TransportContext,
    gate: Arc<CarrierGate>,
) -> (MuxTransport, MuxTransport) {
    pair(context.clone(), context, Some(gate), true)
}

fn pair(
    client_context: hellas_wire::TransportContext,
    server_context: hellas_wire::TransportContext,
    gate: Option<Arc<CarrierGate>>,
    strict_send: bool,
) -> (MuxTransport, MuxTransport) {
    let (to_server, server_inbox) = mpsc::unbounded_channel();
    let (to_client, client_inbox) = mpsc::unbounded_channel();
    let client = MuxTransport::spawn::<8, _, _>(
        MuxRole::Client,
        DefaultClock,
        MuxConfig::default(),
        Pipe {
            out: to_server,
            inbox: client_inbox,
            gate: None,
            strict_send,
        },
        client_context,
    );
    let server = MuxTransport::spawn::<8, _, _>(
        MuxRole::Server,
        DefaultClock,
        MuxConfig::default(),
        Pipe {
            out: to_client,
            inbox: server_inbox,
            gate,
            strict_send,
        },
        server_context,
    );
    (client, server)
}
