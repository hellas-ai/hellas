use super::support::{Fixture, Handler};
use bytes::Bytes;
use hellas_rpc::services::content::ContentServer;
use hellas_wire::{
    Dispatcher, StreamTransport, TransportContext,
    clock::DefaultClock,
    mux::{MessagePipe, MuxConfig, MuxTransport, Role},
};
use std::sync::Arc;
struct Pipe(
    tokio::sync::mpsc::UnboundedSender<Bytes>,
    tokio::sync::mpsc::UnboundedReceiver<Bytes>,
);
impl MessagePipe for Pipe {
    type SendError = std::io::Error;
    type RecvError = std::io::Error;
    async fn send_message(&mut self, bytes: Bytes) -> Result<(), Self::SendError> {
        self.0.send(bytes).map_err(std::io::Error::other)
    }
    async fn recv_message(&mut self) -> Result<Option<Bytes>, Self::RecvError> {
        Ok(self.1.recv().await)
    }
}
pub fn mux(fixture: Arc<Fixture>) -> MuxTransport {
    let (a_tx, a_rx) = tokio::sync::mpsc::unbounded_channel();
    let (b_tx, b_rx) = tokio::sync::mpsc::unbounded_channel();
    let client = MuxTransport::spawn::<8, _, _>(
        Role::Client,
        DefaultClock,
        MuxConfig::default(),
        Pipe(a_tx, b_rx),
        TransportContext::default(),
    );
    let server = MuxTransport::spawn::<8, _, _>(
        Role::Server,
        DefaultClock,
        MuxConfig::default(),
        Pipe(b_tx, a_rx),
        TransportContext::default(),
    );
    tokio::spawn(async move {
        while let Ok(Some(inbound)) = server.accept().await {
            let handler = Handler(fixture.clone());
            tokio::spawn(async move {
                let _ = <ContentServer<Handler> as Dispatcher<MuxTransport>>::dispatch(
                    &ContentServer(handler),
                    inbound,
                )
                .await;
            });
        }
    });
    client
}
