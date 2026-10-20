//! Current authority checked at the carrier write, including after backpressure.
use std::{
    io,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

/// Host implementation must check current rights and invoke `write` while holding
/// its authority writer. Release that writer before returning, including Pending.
/// Register wakes for revocation/expiry as well as forwarding the carrier's wakes.
/// No lease or guard escapes this callback; buffered bytes confer no permission.
pub trait WriteAuthorization: Send {
    fn poll_write(
        &mut self,
        cx: &mut Context<'_>,
        write: &mut dyn FnMut(&mut Context<'_>) -> Poll<io::Result<usize>>,
    ) -> Poll<io::Result<usize>>;
}

#[cfg(all(test, any(feature = "mux", feature = "iroh")))]
pub(crate) mod tests;

/// A stream's immutable authority callback, shared with its carrier driver.
#[derive(Clone)]
pub struct WriteAuthority(Arc<Mutex<Box<dyn WriteAuthorization>>>);
impl WriteAuthority {
    pub fn new(authority: impl WriteAuthorization + 'static) -> Self {
        Self(Arc::new(Mutex::new(Box::new(authority))))
    }
    pub fn poll_write(
        &self,
        cx: &mut Context<'_>,
        write: &mut dyn FnMut(&mut Context<'_>) -> Poll<io::Result<usize>>,
    ) -> Poll<io::Result<usize>> {
        match self.0.lock() {
            Ok(mut authority) => authority.poll_write(cx, write),
            Err(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "write authority failed",
            ))),
        }
    }
    /// Registers authority wakes even while a mux is waiting for peer credit.
    #[cfg(feature = "mux")]
    pub(crate) fn poll_check(&self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        self.poll_write(cx, &mut |_| Poll::Ready(Ok(0)))
    }

    /// The carrier owns only bytes accepted by poll_write. Every subsequent
    /// bounded attempt rechecks authority, without holding it across a wait.
    #[cfg(all(not(target_family = "wasm"), any(feature = "mux", feature = "iroh")))]
    pub(crate) async fn write_all<W: tokio::io::AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
        mut bytes: &[u8],
    ) -> io::Result<()> {
        while !bytes.is_empty() {
            let bounded = &bytes[..bytes.len().min(64 * 1024)];
            let written = futures::future::poll_fn(|cx| {
                self.poll_write(cx, &mut |cx| {
                    std::pin::Pin::new(&mut *writer).poll_write(cx, bounded)
                })
            })
            .await?;
            if written == 0 || written > bounded.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "carrier made no valid write progress",
                ));
            }
            bytes = &bytes[written..];
        }
        Ok(())
    }
}
