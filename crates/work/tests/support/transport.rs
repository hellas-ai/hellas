use bytes::Bytes;
use hellas_wire::DefaultClock;
use hellas_wire::mux::{MessagePipe, MuxConfig, MuxTransport, Role as MuxRole};
use tokio::sync::mpsc;

const EXPORTER: [u8; 32] = [0x5e; 32];

struct Pipe {
    out: mpsc::UnboundedSender<Bytes>,
    inbox: mpsc::UnboundedReceiver<Bytes>,
}

impl MessagePipe for Pipe {
    type SendError = std::io::Error;
    type RecvError = std::io::Error;

    async fn send_message(&mut self, bytes: Bytes) -> Result<(), Self::SendError> {
        let _ = self.out.send(bytes);
        Ok(())
    }

    async fn recv_message(&mut self) -> Result<Option<Bytes>, Self::RecvError> {
        Ok(self.inbox.recv().await)
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
    let (to_server, server_inbox) = mpsc::unbounded_channel();
    let (to_client, client_inbox) = mpsc::unbounded_channel();
    let client = MuxTransport::spawn::<8, _, _>(
        MuxRole::Client,
        DefaultClock,
        MuxConfig::default(),
        Pipe {
            out: to_server,
            inbox: client_inbox,
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
        },
        server_context,
    );
    (client, server)
}
