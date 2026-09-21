//! Generic RPC helpers used by codegen-emitted client trait impls.
//!
//! The codegen produces typed client traits like `ExecuteClient<T>` with one
//! async method per RPC. Each method body delegates to one of the helpers
//! below, parameterised by a `MethodMarker` so prost type info is at the
//! type level — no string method names at call sites.

use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use prost::Message;

use hellas_wire::TransportError;
use hellas_wire::metadata::{Metadata, Trailer};
use hellas_wire::status::{WireCode, WireStatus};
use hellas_wire::transport::{
    MethodMarker, RecvHalf, SendHalf, Stream as WireStream, StreamTransport,
};

use crate::observe::{LEVEL, TARGET, Timing};
use crate::telemetry::CallSpan;

/// Unary call: send one request, receive one response.
pub async fn unary<T, M>(
    transport: &T,
    request: M::Request,
    headers: Metadata,
) -> Result<M::Response, WireStatus>
where
    T: StreamTransport + Sync,
    M: MethodMarker,
    M::Request: Message,
    M::Response: Message + Default,
    T::Error: std::error::Error + Send + Sync + 'static,
{
    unary_with_trailer::<T, M>(transport, request, headers)
        .await
        .map(|wt| wt.response)
}

/// Unary call returning both the response and the terminal trailer
/// metadata. Server-side handlers populate the trailer via
/// `WithTrailer<R>`; this surfaces those bytes to the client so it
/// can read `x-hellas-commitment-bin` / OTel response context.
pub async fn unary_with_trailer<T, M>(
    transport: &T,
    request: M::Request,
    headers: Metadata,
) -> Result<WithTrailer<M::Response>, WireStatus>
where
    T: StreamTransport + Sync,
    M: MethodMarker,
    M::Request: Message,
    M::Response: Message + Default,
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let span = crate::telemetry::client_span::<M>();
    let call = CallSpan::new(span.clone());
    let result: Result<_, WireStatus> = tracing::Instrument::instrument(
        async move {
            let mut headers = headers;
            crate::telemetry::inject_current(&mut headers);
            let stream = transport
                .open(M::METHOD_ID, headers)
                .await
                .map_err(transport_to_status)?;
            let (mut send, recv) = WireStream::split(stream);
            let mut recv = Box::pin(recv);

            let mut buf = BytesMut::with_capacity(request.encoded_len());
            request
                .encode(&mut buf)
                .map_err(|e| WireStatus::internal(format!("prost encode: {e}")))?;
            send.send_body(buf.freeze())
                .await
                .map_err(|e| WireStatus::internal(format!("send: {e}")))?;
            send.close_send(None)
                .await
                .map_err(|e| WireStatus::internal(format!("close_send: {e}")))?;

            // Unary protocol shape: exactly one body chunk, then EOF, then a
            // terminal trailer. Anything else is a server-side bug and must
            // surface as Internal rather than be silently swallowed.
            let chunk = match recv.next().await {
                Some(Ok(b)) => b,
                Some(Err(e)) => return Err(WireStatus::internal(format!("recv: {e}"))),
                None => {
                    // No body — must be a terminal-trailer-only error response.
                    // Drain to populate the trailer and surface it.
                    while recv.next().await.is_some() {}
                    return Err(match recv.trailer() {
                        Some(t) if t.status != WireCode::Ok => trailer_to_status(t),
                        Some(_) => {
                            WireStatus::internal("unary handler returned no body but Ok trailer")
                        }
                        None => {
                            WireStatus::internal("unary handler returned no body and no trailer")
                        }
                    });
                }
            };
            // We got the body; next() must be None next. An extra body is a
            // handler-protocol bug, not noise to swallow.
            match recv.next().await {
                None => {}
                Some(Ok(_)) => {
                    return Err(WireStatus::internal(
                        "unary handler emitted more than one body",
                    ));
                }
                Some(Err(e)) => return Err(WireStatus::internal(format!("recv after body: {e}"))),
            }
            let trailer = recv
                .trailer()
                .ok_or_else(|| WireStatus::internal("unary call ended without terminal trailer"))?;
            if trailer.status != WireCode::Ok {
                return Err(trailer_to_status(trailer));
            }
            let response = M::Response::decode(&chunk[..])
                .map_err(|e| WireStatus::internal(format!("prost decode: {e}")))?;
            Ok(WithTrailer::with_metadata(
                response,
                trailer.metadata.clone(),
            ))
        },
        span,
    )
    .await;
    if let Err(error) = &result {
        call.finish(error.code);
    }
    if result.is_ok() {
        call.finish(WireCode::Ok);
    }
    result
}

fn trailer_to_status(t: &Trailer) -> WireStatus {
    WireStatus {
        code: t.status,
        message: t.message.clone(),
        details: Bytes::new(),
        metadata: t.metadata.clone(),
    }
}

/// Server-streaming call: send one request, receive a stream of responses
/// + a terminal trailer.
///
/// Returns a [`StreamingCall`]: the consumer iterates body chunks via the
/// `Stream` impl and MUST call [`StreamingCall::finish`] after the stream
/// EOFs to surface the terminal trailer (or error).
pub async fn server_streaming<T, M>(
    transport: &T,
    request: M::Request,
    headers: Metadata,
) -> Result<StreamingCall<M::Response>, WireStatus>
where
    T: StreamTransport + Sync,
    M: MethodMarker,
    M::Request: Message,
    M::Response: Message + Default + Send + 'static,
    T::Stream: 'static,
    <T::Stream as WireStream>::RecvHalf: Unpin + 'static,
    <T::Stream as WireStream>::SendHalf: 'static,
    <<T::Stream as WireStream>::RecvHalf as RecvHalf>::Error:
        std::error::Error + Send + Sync + 'static,
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let span = crate::telemetry::client_span::<M>();
    let call = CallSpan::new(span.clone());
    let operation = call.clone();
    let result: Result<_, WireStatus> = tracing::Instrument::instrument(
        async move {
            let mut headers = headers;
            crate::telemetry::inject_current(&mut headers);
            let stream = transport
                .open(M::METHOD_ID, headers)
                .await
                .map_err(transport_to_status)?;
            let (mut send, recv) = WireStream::split(stream);

            let mut buf = BytesMut::with_capacity(request.encoded_len());
            request
                .encode(&mut buf)
                .map_err(|e| WireStatus::internal(format!("prost encode: {e}")))?;
            send.send_body(buf.freeze())
                .await
                .map_err(|e| WireStatus::internal(format!("send: {e}")))?;
            send.close_send(None)
                .await
                .map_err(|e| WireStatus::internal(format!("close_send: {e}")))?;

            Ok(StreamingCall::new(recv, operation))
        },
        span,
    )
    .await;
    if let Err(error) = &result {
        call.finish(error.code);
    }
    result
}

/// Bidirectional streaming call: open a request/response stream and let
/// the caller drive both halves.
pub async fn bidi_streaming<T, M>(
    transport: &T,
    headers: Metadata,
) -> Result<BidiStreamingCall<M::Request, M::Response>, WireStatus>
where
    T: StreamTransport + Sync,
    M: MethodMarker,
    M::Request: Message,
    M::Response: Message + Default + Send + 'static,
    T::Stream: 'static,
    <T::Stream as WireStream>::RecvHalf: Unpin + 'static,
    <T::Stream as WireStream>::SendHalf: 'static,
    <<T::Stream as WireStream>::RecvHalf as RecvHalf>::Error:
        std::error::Error + Send + Sync + 'static,
    <<T::Stream as WireStream>::SendHalf as SendHalf>::Error:
        std::error::Error + Send + Sync + 'static,
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let span = crate::telemetry::client_span::<M>();
    let call = CallSpan::new(span.clone());
    let operation = call.clone();
    let result: Result<_, WireStatus> = tracing::Instrument::instrument(
        async move {
            let mut headers = headers;
            crate::telemetry::inject_current(&mut headers);
            let stream = transport
                .open(M::METHOD_ID, headers)
                .await
                .map_err(transport_to_status)?;
            let (send, recv) = WireStream::split(stream);
            Ok(BidiStreamingCall::new(send, recv, operation))
        },
        span,
    )
    .await;
    if let Err(error) = &result {
        call.finish(error.code);
    }
    result
}

fn transport_to_status<E: std::error::Error>(err: E) -> WireStatus {
    WireStatus::new(WireCode::Unavailable, err.to_string())
}

// -- Streaming response surface ---------------------------------------------

/// A streaming-response call: yields decoded body chunks via its
/// `Stream` impl, then surfaces the terminal trailer via [`finish`].
///
/// Owns the recv-half directly (type-erased through a private trait
/// so consumers don't need to thread the transport type all the way
/// through). The protocol invariant *"0+ bodies, then exactly one
/// terminal trailer"* maps to the API surface as *"0+ next() calls,
/// then exactly one finish() call"* — sequenced by ownership, no
/// invalid states representable.
///
/// [`finish`]: StreamingCall::finish
#[must_use = "streaming calls carry a terminal trailer; ignoring it discards the server-side status"]
pub struct StreamingCall<R> {
    inner: Pin<Box<dyn ErasedRecv + Send>>,
    eof: bool,
    call: CallSpan,
    _r: PhantomData<R>,
}

// The `Pin<Box<...>>` field is already heap-pinned; the outer struct
// only carries a `bool` and `PhantomData`, so it is safe to move the
// outer struct around.
impl<R> Unpin for StreamingCall<R> {}

/// Object-safe view onto a recv-half. Adapts the transport-specific
/// `RecvHalf::Error` to a `WireStatus` and exposes the trailer as an
/// owned `Trailer` so `finish` can move out.
trait ErasedRecv {
    fn poll_chunk(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, WireStatus>>>;
    fn take_trailer(&self) -> Option<Trailer>;
}

trait ErasedSend {
    fn send_body<'a>(
        self: Pin<&'a mut Self>,
        payload: Bytes,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), WireStatus>> + Send + 'a>>;

    fn close_send<'a>(
        self: Pin<&'a mut Self>,
        trailer: Option<Trailer>,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), WireStatus>> + Send + 'a>>;

    fn reset(self: Pin<&mut Self>, code: WireCode);
}

struct RecvAdapter<R: RecvHalf + Unpin> {
    recv: R,
}

struct SendAdapter<S: SendHalf> {
    send: S,
}

impl<S: SendHalf> Unpin for SendAdapter<S> {}

impl<R: RecvHalf + Unpin> ErasedRecv for RecvAdapter<R>
where
    R::Error: std::error::Error + Send + Sync + 'static,
{
    fn poll_chunk(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, WireStatus>>> {
        match Pin::new(&mut self.recv).poll_next(cx) {
            Poll::Ready(Some(Ok(b))) => Poll::Ready(Some(Ok(b))),
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Some(Err(WireStatus::internal(format!("recv: {e}")))))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
    fn take_trailer(&self) -> Option<Trailer> {
        self.recv.trailer().cloned()
    }
}

impl<S: SendHalf> ErasedSend for SendAdapter<S>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    fn send_body<'a>(
        self: Pin<&'a mut Self>,
        payload: Bytes,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), WireStatus>> + Send + 'a>> {
        let this = self.get_mut();
        Box::pin(async move {
            this.send
                .send_body(payload)
                .await
                .map_err(|e| WireStatus::internal(format!("send: {e}")))
        })
    }

    fn close_send<'a>(
        self: Pin<&'a mut Self>,
        trailer: Option<Trailer>,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), WireStatus>> + Send + 'a>> {
        let this = self.get_mut();
        Box::pin(async move {
            this.send
                .close_send(trailer)
                .await
                .map_err(|e| WireStatus::internal(format!("close_send: {e}")))
        })
    }

    fn reset(self: Pin<&mut Self>, code: WireCode) {
        self.get_mut().send.reset(code);
    }
}

impl<R> StreamingCall<R> {
    fn new<H>(recv: H, call: CallSpan) -> Self
    where
        H: RecvHalf + Unpin + Send + 'static,
        H::Error: std::error::Error + Send + Sync + 'static,
    {
        Self {
            inner: Box::pin(RecvAdapter { recv }),
            eof: false,
            call,
            _r: PhantomData,
        }
    }

    /// Consume the call and return the terminal trailer.
    ///
    /// Must be called after the `Stream` impl returns `None`. Returns
    /// the trailer if its `status == Ok`; otherwise returns the
    /// trailer reified as a `WireStatus` error. A missing trailer is
    /// treated as `Internal` — the server emitted an EOF with no
    /// terminal frame, which is itself a protocol bug.
    pub fn finish(self) -> Result<Trailer, WireStatus> {
        assert!(
            self.eof,
            "StreamingCall::finish() called before the Stream returned None"
        );
        let _entered = self.call.span().enter();
        let result = match self.inner.take_trailer() {
            Some(t) if t.status == WireCode::Ok => Ok(t),
            Some(t) => Err(trailer_to_status(&t)),
            None => Err(WireStatus::internal(
                "stream ended without terminal trailer",
            )),
        };
        self.call.finish(
            result
                .as_ref()
                .map_or_else(|error| error.code, |_| WireCode::Ok),
        );
        result
    }
}

impl<R: Message + Default> futures_core::Stream for StreamingCall<R> {
    type Item = Result<R, WireStatus>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.eof {
            return Poll::Ready(None);
        }
        let span = self.call.span().clone();
        let _entered = span.enter();
        match self.inner.as_mut().poll_chunk(cx) {
            Poll::Ready(Some(Ok(bytes))) => match R::decode(&bytes[..]) {
                Ok(msg) => Poll::Ready(Some(Ok(msg))),
                Err(e) => {
                    self.call.finish(WireCode::Internal);
                    Poll::Ready(Some(Err(WireStatus::internal(format!(
                        "prost decode: {e}"
                    )))))
                }
            },
            Poll::Ready(Some(Err(s))) => {
                self.call.finish(s.code);
                Poll::Ready(Some(Err(s)))
            }
            Poll::Ready(None) => {
                self.eof = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Send half of a client request stream.
#[must_use = "request streams must be closed to let the server finish the RPC"]
pub struct StreamingSink<Q> {
    inner: Pin<Box<dyn ErasedSend + Send>>,
    closed: bool,
    call: CallSpan,
    _q: PhantomData<Q>,
}

impl<Q> Unpin for StreamingSink<Q> {}

impl<Q> StreamingSink<Q> {
    fn new<S>(send: S, call: CallSpan) -> Self
    where
        S: SendHalf + 'static,
        S::Error: std::error::Error + Send + Sync + 'static,
    {
        Self {
            inner: Box::pin(SendAdapter { send }),
            closed: false,
            call,
            _q: PhantomData,
        }
    }

    pub fn reset(&mut self, code: WireCode) {
        self.call.finish(code);
        self.closed = true;
        self.inner.as_mut().reset(code);
    }
}

impl<Q: Message> StreamingSink<Q> {
    pub async fn send(&mut self, request: Q) -> Result<(), WireStatus> {
        if self.closed {
            return Err(WireStatus::new(
                WireCode::FailedPrecondition,
                "request stream is already closed",
            ));
        }
        let mut buf = BytesMut::with_capacity(request.encoded_len());
        request
            .encode(&mut buf)
            .map_err(|e| WireStatus::internal(format!("prost encode: {e}")))?;
        tracing::Instrument::instrument(
            self.inner.as_mut().send_body(buf.freeze()),
            self.call.span().clone(),
        )
        .await
        .inspect_err(|error| self.call.finish(error.code))
    }

    pub async fn close(&mut self) -> Result<(), WireStatus> {
        if self.closed {
            return Ok(());
        }
        tracing::Instrument::instrument(
            self.inner.as_mut().close_send(None),
            self.call.span().clone(),
        )
        .await
        .inspect_err(|error| self.call.finish(error.code))?;
        self.closed = true;
        Ok(())
    }
}

impl<Q> Drop for StreamingSink<Q> {
    fn drop(&mut self) {
        if !self.closed {
            self.call.finish(WireCode::Cancelled);
            self.inner.as_mut().reset(WireCode::Cancelled);
        }
    }
}

/// Bidirectional streaming call. Use [`split`] when send and receive need
/// to be driven concurrently.
///
/// [`split`]: BidiStreamingCall::split
#[must_use = "streaming calls carry a terminal trailer; ignoring it discards the server-side status"]
pub struct BidiStreamingCall<Q, R> {
    sink: StreamingSink<Q>,
    responses: StreamingCall<R>,
}

impl<Q, R> Unpin for BidiStreamingCall<Q, R> {}

impl<Q, R> BidiStreamingCall<Q, R> {
    fn new<S, H>(send: S, recv: H, call: CallSpan) -> Self
    where
        S: SendHalf + 'static,
        S::Error: std::error::Error + Send + Sync + 'static,
        H: RecvHalf + Unpin + Send + 'static,
        H::Error: std::error::Error + Send + Sync + 'static,
    {
        Self {
            sink: StreamingSink::new(send, call.clone()),
            responses: StreamingCall::new(recv, call),
        }
    }

    pub fn split(self) -> (StreamingSink<Q>, StreamingCall<R>) {
        (self.sink, self.responses)
    }

    pub fn finish(self) -> Result<Trailer, WireStatus> {
        self.responses.finish()
    }
}

impl<Q: Message, R> BidiStreamingCall<Q, R> {
    pub async fn send(&mut self, request: Q) -> Result<(), WireStatus> {
        self.sink.send(request).await
    }

    pub async fn close(&mut self) -> Result<(), WireStatus> {
        self.sink.close().await
    }
}

impl<Q, R: Message + Default> futures_core::Stream for BidiStreamingCall<Q, R> {
    type Item = Result<R, WireStatus>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().responses).poll_next(cx)
    }
}

/// A successful unary response plus any trailer metadata the handler
/// wants to emit (commitments, OTel span context, ...).
#[derive(Debug)]
pub struct WithTrailer<R> {
    pub response: R,
    pub metadata: hellas_wire::Metadata,
}

impl<R> WithTrailer<R> {
    pub fn new(response: R) -> Self {
        Self {
            response,
            metadata: hellas_wire::Metadata::new(),
        }
    }

    pub fn with_metadata(response: R, metadata: hellas_wire::Metadata) -> Self {
        Self { response, metadata }
    }
}

impl<R> From<R> for WithTrailer<R> {
    fn from(response: R) -> Self {
        Self::new(response)
    }
}

/// Node-scoped concurrency bounds for close responses.
///
/// The outer permits are acquired by method routing before a request body is
/// received. Bodies admitted there wait behind the smaller worker semaphore,
/// so signature verification can never create more than four workers.
#[derive(Debug)]
pub struct WorkResponseRoute {
    permits: PermitPool,
    workers: PermitPool,
}

/// Node-scoped waiting bound for general submissions.
#[derive(Debug)]
pub struct GeneralSubmitRoute {
    permits: PermitPool,
}

impl Default for GeneralSubmitRoute {
    fn default() -> Self {
        Self {
            permits: PermitPool::new(48),
        }
    }
}

impl Default for WorkResponseRoute {
    fn default() -> Self {
        Self {
            permits: PermitPool::new(16),
            workers: PermitPool::new(4),
        }
    }
}

#[derive(Debug)]
struct PermitPool {
    available: std::sync::atomic::AtomicUsize,
    waiters: std::sync::Mutex<Vec<std::task::Waker>>,
}

impl PermitPool {
    const fn new(available: usize) -> Self {
        Self {
            available: std::sync::atomic::AtomicUsize::new(available),
            waiters: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn try_acquire(&self) -> Option<PoolPermit<'_>> {
        self.available
            .fetch_update(
                std::sync::atomic::Ordering::Acquire,
                std::sync::atomic::Ordering::Relaxed,
                |available| available.checked_sub(1),
            )
            .ok()
            .map(|_| PoolPermit { pool: self })
    }

    fn acquire(&self) -> AcquirePermit<'_> {
        AcquirePermit { pool: self }
    }
}

struct PoolPermit<'a> {
    pool: &'a PermitPool,
}

impl Drop for PoolPermit<'_> {
    fn drop(&mut self) {
        self.pool
            .available
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        let waiters = core::mem::take(
            &mut *self
                .pool
                .waiters
                .lock()
                .expect("work response permit waiters mutex poisoned"),
        );
        for waiter in waiters {
            waiter.wake();
        }
    }
}

struct AcquirePermit<'a> {
    pool: &'a PermitPool,
}

impl<'a> std::future::Future for AcquirePermit<'a> {
    type Output = PoolPermit<'a>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        if let Some(permit) = self.pool.try_acquire() {
            return std::task::Poll::Ready(permit);
        }
        let mut waiters = self
            .pool
            .waiters
            .lock()
            .expect("work response permit waiters mutex poisoned");
        if let Some(permit) = self.pool.try_acquire() {
            return std::task::Poll::Ready(permit);
        }
        if !waiters
            .iter()
            .any(|waiter| waiter.will_wake(context.waker()))
        {
            waiters.push(context.waker().clone());
        }
        std::task::Poll::Pending
    }
}

/// Server-side helper: decode a single prost message off the recv stream,
/// emit a single response, then close with an Ok trailer (optionally
/// carrying provenance metadata via `WithTrailer`).
pub async fn dispatch_unary<T, M, F, Fut, RespOrTrailer>(
    inbound: hellas_wire::transport::Inbound<T::Stream>,
    handler: F,
) -> Result<(), TransportError>
where
    T: StreamTransport,
    M: MethodMarker,
    M::Request: Message + Default,
    M::Response: Message,
    F: FnOnce(M::Request) -> Fut + Send,
    Fut: std::future::Future<Output = Result<RespOrTrailer, WireStatus>> + Send,
    RespOrTrailer: Into<WithTrailer<M::Response>>,
{
    dispatch_unary_with_context_and_limit::<T, M, _, _, _>(inbound, None, |request, _context| {
        handler(request)
    })
    .await
}

/// Server-side unary dispatch with a raw request-body limit checked before
/// prost decoding.
pub async fn dispatch_unary_bounded<T, M, F, Fut, RespOrTrailer>(
    inbound: hellas_wire::transport::Inbound<T::Stream>,
    max_request_bytes: usize,
    handler: F,
) -> Result<(), TransportError>
where
    T: StreamTransport,
    M: MethodMarker,
    M::Request: Message + Default,
    M::Response: Message,
    F: FnOnce(M::Request) -> Fut + Send,
    Fut: std::future::Future<Output = Result<RespOrTrailer, WireStatus>> + Send,
    RespOrTrailer: Into<WithTrailer<M::Response>>,
{
    dispatch_unary_with_context_and_limit::<T, M, _, _, _>(
        inbound,
        Some(max_request_bytes),
        |request, _context| handler(request),
    )
    .await
}

/// General submission route with its own 48 waiting permits and transport
/// context. Its permit pool is disjoint from `SubmitWorkResponse`.
pub async fn dispatch_general_submit_bounded<T, M, F, Fut, RespOrTrailer>(
    inbound: hellas_wire::transport::Inbound<T::Stream>,
    route: &GeneralSubmitRoute,
    max_request_bytes: usize,
    handler: F,
) -> Result<(), TransportError>
where
    T: StreamTransport,
    M: MethodMarker,
    M::Request: Message + Default,
    M::Response: Message,
    F: FnOnce(M::Request, hellas_wire::TransportContext) -> Fut + Send,
    Fut: std::future::Future<Output = Result<RespOrTrailer, WireStatus>> + Send,
    RespOrTrailer: Into<WithTrailer<M::Response>>,
{
    let Some(_permit) = route.permits.try_acquire() else {
        let call = CallSpan::new(crate::telemetry::server_span::<M>(&inbound.headers));
        let (mut send, _recv) = WireStream::split(inbound.stream);
        let result = send
            .close_send(Some(
                WireStatus::new(
                    WireCode::ResourceExhausted,
                    "general submission route is full",
                )
                .into(),
            ))
            .await
            .map_err(|error| TransportError::Io(format!("close-with-status: {error}")));
        call.finish(if result.is_ok() {
            WireCode::ResourceExhausted
        } else {
            WireCode::Internal
        });
        return result;
    };
    // `general_worker_ms`: everything this route does once it holds one
    // of its 48 permits — receive the body, check the raw cap, decode,
    // and run the handler. A submission refused for want of a permit is
    // not a worker that ran, so it emits nothing.
    let worked = Timing::start();
    let outcome = dispatch_unary_with_context_and_limit::<T, M, _, _, _>(
        inbound,
        Some(max_request_bytes),
        handler,
    )
    .await;
    if let Some(ms) = worked.ms() {
        tracing::event!(
            name: "general_worker_ms",
            target: TARGET,
            LEVEL,
            method = M::NAME,
            ms,
        );
    }
    outcome
}

/// The dedicated work-response route: reserve one of sixteen request slots
/// before reading bytes, reject raw overflow before decoding, then enter one
/// of four bounded validation workers.
pub async fn dispatch_work_response_bounded<T, M, F, Fut, RespOrTrailer>(
    inbound: hellas_wire::transport::Inbound<T::Stream>,
    route: &WorkResponseRoute,
    max_request_bytes: usize,
    handler: F,
) -> Result<(), TransportError>
where
    T: StreamTransport,
    M: MethodMarker,
    M::Request: Message + Default,
    M::Response: Message,
    F: FnOnce(M::Request) -> Fut + Send,
    Fut: std::future::Future<Output = Result<RespOrTrailer, WireStatus>> + Send,
    RespOrTrailer: Into<WithTrailer<M::Response>>,
{
    let span = crate::telemetry::server_span::<M>(&inbound.headers);
    let call = CallSpan::new(span.clone());
    let operation = call.clone();
    let result = tracing::Instrument::instrument(
        async move {
            let Some(_permit) = route.permits.try_acquire() else {
                let (mut send, _recv) = WireStream::split(inbound.stream);
                send.close_send(Some(
                    WireStatus::new(WireCode::ResourceExhausted, "work response route is full")
                        .into(),
                ))
                .await
                .map_err(|error| TransportError::Io(format!("close-with-status: {error}")))?;
                operation.finish(WireCode::ResourceExhausted);
                return Ok(());
            };

            let (mut send, recv) = WireStream::split(inbound.stream);
            let mut recv = Box::pin(recv);
            let req_bytes = match recv.next().await {
                Some(Ok(bytes)) => bytes,
                Some(Err(error)) => return Err(TransportError::Io(format!("recv: {error}"))),
                None => return Err(TransportError::Protocol("empty unary request".into())),
            };
            if let Some(status) = raw_request_limit_status(req_bytes.len(), Some(max_request_bytes))
            {
                let code = status.code;
                send.close_send(Some(status.into()))
                    .await
                    .map_err(|error| TransportError::Io(format!("close-with-status: {error}")))?;
                operation.finish(code);
                return Ok(());
            }
            finish_unary_request(recv.as_mut().get_mut()).await?;

            // `response_worker_ms`: the wait for one of the four workers, plus
            // the decode and the handler that worker then runs. The queueing is
            // deliberately inside it — under the load §4 measures at, waiting
            // for a worker *is* most of what a response costs — and the encode
            // and send after it are deliberately outside, being transport
            // rather than worker.
            let worked = Timing::start();
            let _worker = route.workers.acquire().await;
            let request = M::Request::decode(&req_bytes[..])
                .map_err(|error| TransportError::Protocol(format!("prost decode: {error}")))?;
            let handled = handler(request).await;
            if let Some(ms) = worked.ms() {
                tracing::event!(
                    name: "response_worker_ms",
                    target: TARGET,
                    LEVEL,
                    method = M::NAME,
                    bytes = req_bytes.len(),
                    ms,
                );
            }
            write_unary_response(&mut send, handled.map(Into::into), &operation).await
        },
        span,
    )
    .await;
    call.finish(if result.is_ok() {
        WireCode::Ok
    } else {
        WireCode::Internal
    });
    result
}

/// Context-aware unary dispatch. This is used by connection-bound protocols
/// such as confidential open; the exporter remains transport-provided and is
/// never decoded from request bytes.
pub async fn dispatch_unary_with_context<T, M, F, Fut, RespOrTrailer>(
    inbound: hellas_wire::transport::Inbound<T::Stream>,
    handler: F,
) -> Result<(), TransportError>
where
    T: StreamTransport,
    M: MethodMarker,
    M::Request: Message + Default,
    M::Response: Message,
    F: FnOnce(M::Request, hellas_wire::TransportContext) -> Fut + Send,
    Fut: std::future::Future<Output = Result<RespOrTrailer, WireStatus>> + Send,
    RespOrTrailer: Into<WithTrailer<M::Response>>,
{
    dispatch_unary_with_context_and_limit::<T, M, _, _, _>(inbound, None, handler).await
}

fn raw_request_limit_status(len: usize, max: Option<usize>) -> Option<WireStatus> {
    let max = max?;
    (len > max).then(|| {
        WireStatus::new(
            WireCode::InvalidArgument,
            format!("raw unary request exceeds {max} bytes"),
        )
    })
}

/// Every response writer records a terminal status only after its trailer
/// was sent. The caller records transport errors and cancellation.
async fn write_trailer<S: SendHalf>(
    send: &mut S,
    trailer: Trailer,
    call: &CallSpan,
) -> Result<(), TransportError> {
    let code = trailer.status;
    send.close_send(Some(trailer))
        .await
        .map_err(|error| TransportError::Io(format!("close: {error}")))?;
    call.finish(code);
    Ok(())
}

async fn write_unary_response<S: SendHalf, R: Message>(
    send: &mut S,
    result: Result<WithTrailer<R>, WireStatus>,
    call: &CallSpan,
) -> Result<(), TransportError> {
    let trailer = match result {
        Ok(WithTrailer { response, metadata }) => {
            let mut buf = BytesMut::with_capacity(response.encoded_len());
            response
                .encode(&mut buf)
                .map_err(|error| TransportError::Protocol(format!("prost encode: {error}")))?;
            send.send_body(buf.freeze())
                .await
                .map_err(|error| TransportError::Io(format!("send: {error}")))?;
            Trailer {
                metadata,
                ..Trailer::ok()
            }
        }
        Err(status) => status.into(),
    };
    write_trailer(send, trailer, call).await
}

async fn write_streaming_response<S: SendHalf, R: Message>(
    send: &mut S,
    mut responses: impl futures_util::Stream<Item = Result<R, WireStatus>> + Unpin,
    call: &CallSpan,
) -> Result<(), TransportError> {
    while let Some(response) = responses.next().await {
        let response = match response {
            Ok(response) => response,
            Err(status) => return write_trailer(send, status.into(), call).await,
        };
        let mut buf = BytesMut::with_capacity(response.encoded_len());
        response
            .encode(&mut buf)
            .map_err(|error| TransportError::Protocol(format!("prost encode: {error}")))?;
        send.send_body(buf.freeze())
            .await
            .map_err(|error| TransportError::Io(format!("send: {error}")))?;
    }
    write_trailer(send, Trailer::ok(), call).await
}

async fn dispatch_unary_with_context_and_limit<T, M, F, Fut, RespOrTrailer>(
    inbound: hellas_wire::transport::Inbound<T::Stream>,
    max_request_bytes: Option<usize>,
    handler: F,
) -> Result<(), TransportError>
where
    T: StreamTransport,
    M: MethodMarker,
    M::Request: Message + Default,
    M::Response: Message,
    F: FnOnce(M::Request, hellas_wire::TransportContext) -> Fut + Send,
    Fut: std::future::Future<Output = Result<RespOrTrailer, WireStatus>> + Send,
    RespOrTrailer: Into<WithTrailer<M::Response>>,
{
    let span = crate::telemetry::server_span::<M>(&inbound.headers);
    let call = CallSpan::new(span.clone());
    let operation = call.clone();
    let result = tracing::Instrument::instrument(
        async move {
            let context = inbound.context;
            let (mut send, recv) = WireStream::split(inbound.stream);
            let mut recv = Box::pin(recv);
            let req_bytes = match recv.next().await {
                Some(Ok(b)) => b,
                Some(Err(e)) => return Err(TransportError::Io(format!("recv: {e}"))),
                None => return Err(TransportError::Protocol("empty unary request".into())),
            };
            if let Some(status) = raw_request_limit_status(req_bytes.len(), max_request_bytes) {
                let code = status.code;
                send.close_send(Some(status.into()))
                    .await
                    .map_err(|e| TransportError::Io(format!("close-with-status: {e}")))?;
                operation.finish(code);
                return Ok(());
            }
            finish_unary_request(recv.as_mut().get_mut()).await?;
            let request = M::Request::decode(&req_bytes[..])
                .map_err(|e| TransportError::Protocol(format!("prost decode: {e}")))?;

            write_unary_response(
                &mut send,
                handler(request, context).await.map(Into::into),
                &operation,
            )
            .await
        },
        span,
    )
    .await;
    call.finish(if result.is_ok() {
        WireCode::Ok
    } else {
        WireCode::Internal
    });
    result
}

/// A unary request is one Body followed by End. Keep its receive half alive
/// until End arrives: dropping it after Body can send QUIC STOP_SENDING(0)
/// while the client is still writing End, hiding an otherwise valid response.
async fn finish_unary_request<R: RecvHalf>(recv: &mut R) -> Result<(), TransportError> {
    match recv.next().await {
        Some(Ok(_)) => {
            recv.reset(WireCode::InvalidArgument);
            return Err(TransportError::Protocol(
                "unary request emitted more than one body".into(),
            ));
        }
        Some(Err(error)) => return Err(TransportError::Io(format!("request end: {error}"))),
        None => {}
    }
    match recv.trailer() {
        Some(trailer) if trailer.status == WireCode::Ok => Ok(()),
        Some(trailer) => Err(TransportError::Protocol(format!(
            "request ended with {:?}: {}",
            trailer.status, trailer.message,
        ))),
        None => Err(TransportError::Protocol(
            "unary request ended without terminal trailer".into(),
        )),
    }
}

/// Server-side helper for server-streaming methods: decode the single
/// request frame, invoke the handler, then forward each yielded
/// response back over the wire.
pub async fn dispatch_server_streaming<T, M, F, Fut, S>(
    inbound: hellas_wire::transport::Inbound<T::Stream>,
    handler: F,
) -> Result<(), TransportError>
where
    T: StreamTransport,
    M: MethodMarker,
    M::Request: Message + Default,
    M::Response: Message + Send + 'static,
    F: FnOnce(M::Request) -> Fut + Send,
    Fut: std::future::Future<Output = Result<S, WireStatus>> + Send,
    S: futures_util::Stream<Item = Result<M::Response, WireStatus>> + Send + Unpin,
{
    let span = crate::telemetry::server_span::<M>(&inbound.headers);
    let call = CallSpan::new(span.clone());
    let operation = call.clone();
    let result = tracing::Instrument::instrument(
        async move {
            let (mut send, recv) = WireStream::split(inbound.stream);
            let mut recv = Box::pin(recv);
            let req_bytes = match recv.next().await {
                Some(Ok(b)) => b,
                Some(Err(e)) => return Err(TransportError::Io(format!("recv: {e}"))),
                None => return Err(TransportError::Protocol("empty stream request".into())),
            };
            finish_unary_request(recv.as_mut().get_mut()).await?;
            let request = M::Request::decode(&req_bytes[..])
                .map_err(|e| TransportError::Protocol(format!("prost decode: {e}")))?;

            let stream = match handler(request).await {
                Ok(s) => s,
                Err(status) => {
                    return write_trailer(&mut send, status.into(), &operation).await;
                }
            };

            write_streaming_response(&mut send, stream, &operation).await
        },
        span,
    )
    .await;
    call.finish(if result.is_ok() {
        WireCode::Ok
    } else {
        WireCode::Internal
    });
    result
}

/// Server-side helper for bidirectional streaming methods.
pub async fn dispatch_bidi_streaming<T, M, F, Fut, S>(
    inbound: hellas_wire::transport::Inbound<T::Stream>,
    handler: F,
) -> Result<(), TransportError>
where
    T: StreamTransport,
    M: MethodMarker,
    M::Request: Message + Default + Send + 'static,
    M::Response: Message + Send + 'static,
    F: FnOnce(RequestStream<M::Request>) -> Fut + Send,
    Fut: std::future::Future<Output = Result<S, WireStatus>> + Send,
    S: futures_util::Stream<Item = Result<M::Response, WireStatus>> + Send + Unpin,
    <T::Stream as WireStream>::RecvHalf: Unpin + Send + 'static,
    <<T::Stream as WireStream>::RecvHalf as RecvHalf>::Error:
        std::error::Error + Send + Sync + 'static,
{
    let span = crate::telemetry::server_span::<M>(&inbound.headers);
    let call = CallSpan::new(span.clone());
    let operation = call.clone();
    let result = tracing::Instrument::instrument(
        async move {
            let (mut send, recv) = WireStream::split(inbound.stream);
            let requests = RequestStream::new(recv, operation.clone());
            let stream = match handler(requests).await {
                Ok(s) => s,
                Err(status) => {
                    return write_trailer(&mut send, status.into(), &operation).await;
                }
            };

            write_streaming_response(&mut send, stream, &operation).await
        },
        span,
    )
    .await;
    call.finish(if result.is_ok() {
        WireCode::Ok
    } else {
        WireCode::Internal
    });
    result
}

/// Decoded request stream passed to bidirectional server handlers.
pub struct RequestStream<Q> {
    call: CallSpan,
    inner: Pin<Box<dyn ErasedRecv + Send>>,
    eof: bool,
    _q: PhantomData<Q>,
}

impl<Q> Unpin for RequestStream<Q> {}

impl<Q> RequestStream<Q> {
    fn new<H>(recv: H, call: CallSpan) -> Self
    where
        H: RecvHalf + Unpin + Send + 'static,
        H::Error: std::error::Error + Send + Sync + 'static,
    {
        Self {
            call,
            inner: Box::pin(RecvAdapter { recv }),
            eof: false,
            _q: PhantomData,
        }
    }
}

impl<Q: Message + Default> futures_core::Stream for RequestStream<Q> {
    type Item = Result<Q, WireStatus>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.eof {
            return Poll::Ready(None);
        }
        match this.inner.as_mut().poll_chunk(cx) {
            Poll::Ready(Some(Ok(bytes))) => match Q::decode(&bytes[..]) {
                Ok(msg) => Poll::Ready(Some(Ok(msg))),
                Err(e) => {
                    this.call.finish(WireCode::Internal);
                    Poll::Ready(Some(Err(WireStatus::internal(format!(
                        "prost decode: {e}"
                    )))))
                }
            },
            Poll::Ready(Some(Err(s))) => {
                this.call.finish(s.code);
                Poll::Ready(Some(Err(s)))
            }
            Poll::Ready(None) => {
                this.eof = true;
                match this.inner.take_trailer() {
                    Some(t) if t.status == WireCode::Ok => Poll::Ready(None),
                    Some(t) => {
                        this.call.finish(t.status);
                        Poll::Ready(Some(Err(trailer_to_status(&t))))
                    }
                    None => {
                        this.call.finish(WireCode::Internal);
                        Poll::Ready(Some(Err(WireStatus::internal(
                            "request stream ended without terminal trailer",
                        ))))
                    }
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod streaming_call_tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, PartialEq, ::prost::Message)]
    struct U32Msg {
        #[prost(uint32, tag = "1")]
        x: u32,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    struct BytesMsg {
        #[prost(bytes = "vec", tag = "1")]
        payload: Vec<u8>,
    }

    struct MockService;

    impl hellas_wire::ServiceMarker for MockService {
        const NAME: &'static str = "test.Mock";
        const ALPN: &'static str = "/test.Mock/1.0";
        const SERVICE_ID: u32 = 1;
    }

    struct MockMethod;

    impl MethodMarker for MockMethod {
        type Service = MockService;
        type Request = BytesMsg;
        type Response = BytesMsg;
        const NAME: &'static str = "Route";
        const METHOD_ID: u32 = 2;
        const REQUEST_STREAMING: bool = false;
        const RESPONSE_STREAMING: bool = false;
    }

    /// Synthetic recv: pre-loaded chunks + optional trailer.
    struct MockRecv {
        chunks: VecDeque<Result<Bytes, WireStatus>>,
        trailer: Option<Trailer>,
    }

    impl ErasedRecv for MockRecv {
        fn poll_chunk(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Bytes, WireStatus>>> {
            Poll::Ready(self.chunks.pop_front())
        }
        fn take_trailer(&self) -> Option<Trailer> {
            self.trailer.clone()
        }
    }

    fn call(
        chunks: Vec<Result<Bytes, WireStatus>>,
        trailer: Option<Trailer>,
    ) -> StreamingCall<U32Msg> {
        StreamingCall {
            inner: Box::pin(MockRecv {
                chunks: chunks.into(),
                trailer,
            }),
            eof: false,
            call: CallSpan::new(tracing::Span::none()),
            _r: PhantomData,
        }
    }

    fn body(v: u32) -> Bytes {
        let mut b = bytes::BytesMut::new();
        prost::Message::encode(&U32Msg { x: v }, &mut b).unwrap();
        b.freeze()
    }

    #[derive(Clone, Default)]
    struct MockSendState {
        bodies: Arc<Mutex<Vec<Bytes>>>,
        close: Arc<Mutex<Option<Option<Trailer>>>>,
        reset: Arc<Mutex<Option<WireCode>>>,
        fail_send: bool,
        fail_close: bool,
    }

    struct MockSend {
        state: MockSendState,
    }

    impl SendHalf for MockSend {
        type Error = std::io::Error;

        async fn send_body(&mut self, payload: Bytes) -> Result<(), Self::Error> {
            if self.state.fail_send {
                return Err(std::io::Error::other("send failed"));
            }
            self.state.bodies.lock().unwrap().push(payload);
            Ok(())
        }

        async fn close_send(&mut self, trailer: Option<Trailer>) -> Result<(), Self::Error> {
            if self.state.fail_close {
                return Err(std::io::Error::other("close failed"));
            }
            *self.state.close.lock().unwrap() = Some(trailer);
            Ok(())
        }

        fn reset(&mut self, code: WireCode) {
            *self.state.reset.lock().unwrap() = Some(code);
        }
    }

    struct RouteRecv {
        body: Option<Bytes>,
        pending: bool,
        polled: bool,
        first_polls: Option<Arc<AtomicUsize>>,
        end: Option<tokio::sync::oneshot::Receiver<()>>,
        trailer: Trailer,
    }

    impl futures_core::Stream for RouteRecv {
        type Item = Result<Bytes, std::io::Error>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            if !self.polled {
                self.polled = true;
                if let Some(polls) = &self.first_polls {
                    polls.fetch_add(1, Ordering::SeqCst);
                }
            }
            if self.pending {
                Poll::Pending
            } else if let Some(body) = self.body.take() {
                Poll::Ready(Some(Ok(body)))
            } else {
                if let Some(end) = &mut self.end {
                    std::task::ready!(Pin::new(end).poll(cx)).unwrap();
                    self.end = None;
                }
                Poll::Ready(None)
            }
        }
    }

    impl RecvHalf for RouteRecv {
        type Error = std::io::Error;

        fn trailer(&self) -> Option<&Trailer> {
            Some(&self.trailer)
        }

        fn reset(&mut self, _code: WireCode) {}
    }

    struct MockWireStream {
        send: MockSend,
        recv: RouteRecv,
    }

    impl WireStream for MockWireStream {
        type SendError = std::io::Error;
        type RecvError = std::io::Error;
        type SendHalf = MockSend;
        type RecvHalf = RouteRecv;

        fn split(self) -> (Self::SendHalf, Self::RecvHalf) {
            (self.send, self.recv)
        }

        fn reset(&mut self, code: WireCode) {
            self.send.reset(code);
        }
    }

    struct MockTransport;

    impl StreamTransport for MockTransport {
        type Stream = MockWireStream;
        type Error = std::io::Error;

        async fn open(
            &self,
            _method_id: u32,
            _headers: Metadata,
        ) -> Result<Self::Stream, Self::Error> {
            Err(std::io::Error::other("mock transport cannot open"))
        }

        async fn accept(&self) -> Result<Option<hellas_wire::Inbound<Self::Stream>>, Self::Error> {
            Ok(None)
        }
    }

    fn route_inbound(
        body: Option<Bytes>,
        pending: bool,
        first_polls: Option<Arc<AtomicUsize>>,
    ) -> (hellas_wire::Inbound<MockWireStream>, MockSendState) {
        let state = MockSendState::default();
        (
            hellas_wire::Inbound {
                method_id: MockMethod::METHOD_ID,
                headers: Metadata::new(),
                stream: MockWireStream {
                    send: MockSend {
                        state: state.clone(),
                    },
                    recv: RouteRecv {
                        body,
                        pending,
                        polled: false,
                        first_polls,
                        end: None,
                        trailer: Trailer::ok(),
                    },
                },
                context: hellas_wire::TransportContext::default(),
            },
            state,
        )
    }

    #[cfg(feature = "otel")]
    #[tokio::test]
    async fn telemetry_records_transport_protocol_and_cancellation_failures() {
        use opentelemetry::trace::{Status, TracerProvider};
        use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
        use tracing::instrument::WithSubscriber;
        use tracing_subscriber::prelude::*;

        struct ReplyTransport(Mutex<Option<MockWireStream>>);
        impl StreamTransport for ReplyTransport {
            type Stream = MockWireStream;
            type Error = std::io::Error;
            async fn open(&self, _: u32, _: Metadata) -> Result<Self::Stream, Self::Error> {
                Ok(self.0.lock().unwrap().take().unwrap())
            }
            async fn accept(
                &self,
            ) -> Result<Option<hellas_wire::Inbound<Self::Stream>>, Self::Error> {
                Ok(None)
            }
        }
        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let dispatch = tracing::Dispatch::new(
            tracing_subscriber::registry()
                .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("rpc-failures"))),
        );
        let expected = async {
            let mut expected = Vec::new();
            // Both malformed peer responses and transport write failures are errors.
            for fail_send in [false, true] {
                let (mut inbound, _) =
                    route_inbound(Some(Bytes::from_static(&[0xff])), false, None);
                inbound.stream.send.state.fail_send = fail_send;
                let transport = ReplyTransport(Mutex::new(Some(inbound.stream)));
                let error =
                    unary::<_, MockMethod>(&transport, BytesMsg::default(), Metadata::new())
                        .await
                        .unwrap_err();
                assert_eq!(error.code, WireCode::Internal);
                expected.push("INTERNAL");
            }
            // A successful handler whose terminal write fails is not a successful RPC.
            let (mut inbound, _) = route_inbound(
                Some(BytesMsg::default().encode_to_vec().into()),
                false,
                None,
            );
            inbound.stream.send.state.fail_close = true;
            assert!(
                dispatch_unary::<MockTransport, MockMethod, _, _, BytesMsg>(
                    inbound,
                    |request| async { Ok(request) }
                )
                .await
                .is_err()
            );
            expected.push("INTERNAL");
            let (inbound, _) = route_inbound(Some(Bytes::from_static(&[0; 2])), false, None);
            dispatch_unary_bounded::<MockTransport, MockMethod, _, _, BytesMsg>(
                inbound,
                1,
                |_| async { panic!("oversized request reached handler") },
            )
            .await
            .unwrap();
            expected.push("INVALID_ARGUMENT");

            for (chunks, trailer, poll) in [
                (vec![], None, true),
                (
                    vec![Ok(Bytes::from_static(&[0xff]))],
                    Some(Trailer::ok()),
                    true,
                ),
                (vec![], Some(Trailer::ok()), false),
                (
                    vec![Err(WireStatus::new(
                        WireCode::DataLoss,
                        "private peer detail",
                    ))],
                    Some(Trailer::ok()),
                    true,
                ),
            ] {
                let mut response = call(chunks, trailer);
                response.call = CallSpan::new(crate::telemetry::client_span::<MockMethod>());
                if poll {
                    while response.next().await.is_some() {}
                    let _ = response.finish();
                } else {
                    drop(response);
                }
            }
            expected.extend(["INTERNAL", "INTERNAL", "CANCELLED", "DATA_LOSS"]);

            // The request and response halves share one terminal observation.
            // A cancelled sender cannot later become OK; dropping an already
            // successful call's sender cannot turn success into cancellation.
            for finish_first in [false, true] {
                let observer = CallSpan::new(crate::telemetry::client_span::<MockMethod>());
                let mut response = call(vec![], Some(Trailer::ok()));
                response.call = observer.clone();
                let sink = StreamingSink::<U32Msg>::new(
                    MockSend {
                        state: MockSendState::default(),
                    },
                    observer,
                );
                assert!(response.next().await.is_none());
                if finish_first {
                    response.finish().unwrap();
                    drop(sink);
                    expected.push("OK");
                } else {
                    drop(sink);
                    response.finish().unwrap();
                    expected.push("CANCELLED");
                }
            }
            let route = WorkResponseRoute::default();
            let _permits: Vec<_> = (0..16)
                .map(|_| route.permits.try_acquire().unwrap())
                .collect();
            let (inbound, _) = route_inbound(None, true, None);
            dispatch_work_response_bounded::<MockTransport, MockMethod, _, _, BytesMsg>(
                inbound,
                &route,
                1,
                |_| async { panic!("full route ran handler") },
            )
            .await
            .unwrap();
            expected.push("RESOURCE_EXHAUSTED");
            let route = GeneralSubmitRoute::default();
            let _permits: Vec<_> = (0..48)
                .map(|_| route.permits.try_acquire().unwrap())
                .collect();
            let (inbound, _) = route_inbound(None, true, None);
            dispatch_general_submit_bounded::<MockTransport, MockMethod, _, _, BytesMsg>(
                inbound,
                &route,
                1,
                |_, _| async { panic!("full route ran handler") },
            )
            .await
            .unwrap();
            expected.push("RESOURCE_EXHAUSTED");

            // Cancelling an in-flight handler before it has a request is observed.
            let (inbound, _) = route_inbound(None, true, None);
            let mut pending =
                Box::pin(dispatch_unary::<MockTransport, MockMethod, _, _, BytesMsg>(
                    inbound,
                    |request| async { Ok(request) },
                ));
            assert!(futures_util::poll!(&mut pending).is_pending());
            drop(pending);
            expected.push("CANCELLED");
            expected
        }
        .with_subscriber(dispatch)
        .await;
        provider.force_flush().unwrap();
        let spans = exporter.get_finished_spans().unwrap();
        assert_eq!(spans.len(), expected.len());
        for (span, expected) in spans.iter().zip(expected) {
            assert_eq!(
                matches!(span.status, Status::Error { .. }),
                expected != "OK",
                "{span:?}"
            );
            assert!(
                span.attributes
                    .iter()
                    .any(|kv| kv.key.as_str() == "rpc.response.status_code"
                        && kv.value == opentelemetry::Value::from(expected)),
                "{span:?}"
            );
            assert!(!format!("{span:?}").contains("private peer detail"));
        }
        provider.shutdown().unwrap();
    }

    #[tokio::test]
    async fn unary_handler_waits_for_request_end_before_responding() {
        let request = BytesMsg { payload: vec![7] };
        let (mut inbound, sent) = route_inbound(Some(request.encode_to_vec().into()), false, None);
        let (end, receive_end) = tokio::sync::oneshot::channel();
        inbound.stream.recv.end = Some(receive_end);
        let called = Arc::new(AtomicUsize::new(0));
        let handler_called = called.clone();
        let dispatch = dispatch_unary::<MockTransport, MockMethod, _, _, BytesMsg>(
            inbound,
            move |request| async move {
                handler_called.fetch_add(1, Ordering::SeqCst);
                Ok(request)
            },
        );
        tokio::pin!(dispatch);
        assert!(futures_util::poll!(&mut dispatch).is_pending());
        assert_eq!(called.load(Ordering::SeqCst), 0);
        assert!(sent.bodies.lock().unwrap().is_empty());
        end.send(()).unwrap();
        dispatch.await.unwrap();
        assert_eq!(called.load(Ordering::SeqCst), 1);
        assert_eq!(sent.bodies.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn happy_path_then_ok_trailer() {
        let mut c = call(vec![Ok(body(7)), Ok(body(13))], Some(Trailer::ok()));
        assert_eq!(c.next().await.unwrap().unwrap().x, 7);
        assert_eq!(c.next().await.unwrap().unwrap().x, 13);
        assert!(c.next().await.is_none());
        assert_eq!(c.finish().unwrap().status, WireCode::Ok);
    }

    #[tokio::test]
    async fn non_ok_trailer_surfaces_via_finish() {
        let mut c = call(
            vec![Ok(body(1))],
            Some(Trailer::from_status(WireCode::Cancelled, "abort")),
        );
        let _ = c.next().await;
        let _ = c.next().await; // drain to EOF
        let err = c.finish().unwrap_err();
        assert_eq!(err.code, WireCode::Cancelled);
        assert_eq!(err.message.as_str(), "abort");
    }

    #[tokio::test]
    async fn missing_trailer_is_internal() {
        let mut c = call(vec![Ok(body(1))], None);
        let _ = c.next().await;
        let _ = c.next().await;
        assert_eq!(c.finish().unwrap_err().code, WireCode::Internal);
    }

    #[tokio::test]
    async fn per_item_error_propagates() {
        let mut c = call(
            vec![Ok(body(1)), Err(WireStatus::new(WireCode::DataLoss, "mid"))],
            Some(Trailer::ok()),
        );
        assert_eq!(c.next().await.unwrap().unwrap().x, 1);
        assert_eq!(
            c.next().await.unwrap().unwrap_err().code,
            WireCode::DataLoss,
        );
    }

    #[tokio::test]
    #[should_panic(expected = "before the Stream returned None")]
    async fn finish_before_eof_panics() {
        let _ = call(vec![Ok(body(1))], Some(Trailer::ok())).finish();
    }

    #[tokio::test]
    async fn request_stream_decodes_body_frames() {
        let mut stream = RequestStream {
            call: CallSpan::new(tracing::Span::none()),
            inner: Box::pin(MockRecv {
                chunks: vec![Ok(body(21))].into(),
                trailer: Some(Trailer::ok()),
            }),
            eof: false,
            _q: PhantomData::<U32Msg>,
        };

        assert_eq!(stream.next().await.unwrap().unwrap().x, 21);
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn request_stream_surfaces_terminal_error() {
        let mut stream = RequestStream {
            call: CallSpan::new(tracing::Span::none()),
            inner: Box::pin(MockRecv {
                chunks: VecDeque::new(),
                trailer: Some(Trailer::from_status(WireCode::Cancelled, "client closed")),
            }),
            eof: false,
            _q: PhantomData::<U32Msg>,
        };

        let err = stream.next().await.unwrap().unwrap_err();
        assert_eq!(err.code, WireCode::Cancelled);
        assert_eq!(err.message.as_str(), "client closed");
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn streaming_sink_encodes_requests_and_closes() {
        let state = MockSendState::default();
        let mut sink = StreamingSink::<U32Msg>::new(
            MockSend {
                state: state.clone(),
            },
            CallSpan::new(tracing::Span::none()),
        );

        sink.send(U32Msg { x: 34 }).await.unwrap();
        sink.close().await.unwrap();

        let bodies = state.bodies.lock().unwrap();
        assert_eq!(bodies.len(), 1);
        assert_eq!(U32Msg::decode(&bodies[0][..]).unwrap().x, 34);
        assert!(state.close.lock().unwrap().is_some());
        assert!(state.reset.lock().unwrap().is_none());
    }

    #[test]
    fn raw_unary_limit_is_inclusive_and_rejects_before_decode() {
        assert!(raw_request_limit_status(65_540, Some(65_540)).is_none());
        let status = raw_request_limit_status(65_541, Some(65_540))
            .expect("one byte over the raw cap is rejected");
        assert_eq!(status.code(), WireCode::InvalidArgument);
        assert!(raw_request_limit_status(65_536, Some(65_536)).is_none());
        assert_eq!(
            raw_request_limit_status(65_537, Some(65_536))
                .expect("work-response overflow")
                .code(),
            WireCode::InvalidArgument,
        );
    }

    #[test]
    fn work_response_route_has_sixteen_waiters_and_four_workers() {
        let route = WorkResponseRoute::default();
        let permits: Vec<_> = (0..16)
            .map(|_| {
                route
                    .permits
                    .try_acquire()
                    .expect("reserved response permit")
            })
            .collect();
        assert!(route.permits.try_acquire().is_none());

        let workers: Vec<_> = (0..4)
            .map(|_| {
                route
                    .workers
                    .try_acquire()
                    .expect("bounded response worker")
            })
            .collect();
        assert!(route.workers.try_acquire().is_none());
        drop(workers);
        drop(permits);
        assert!(route.permits.try_acquire().is_some());
        assert!(route.workers.try_acquire().is_some());
    }

    #[tokio::test]
    async fn work_response_route_reserves_permit_before_reading_body() {
        let route = Arc::new(WorkResponseRoute::default());
        let first_polls = Arc::new(AtomicUsize::new(0));
        let mut held = Vec::new();
        for _ in 0..16 {
            let (inbound, _state) = route_inbound(None, true, Some(first_polls.clone()));
            let route = route.clone();
            held.push(tokio::spawn(async move {
                dispatch_work_response_bounded::<MockTransport, MockMethod, _, _, BytesMsg>(
                    inbound,
                    &route,
                    65_536,
                    |_| async { Ok(BytesMsg::default()) },
                )
                .await
            }));
        }
        while first_polls.load(Ordering::SeqCst) != 16 {
            tokio::task::yield_now().await;
        }

        let overflow_polls = Arc::new(AtomicUsize::new(0));
        let (overflow, state) = route_inbound(None, true, Some(overflow_polls.clone()));
        dispatch_work_response_bounded::<MockTransport, MockMethod, _, _, BytesMsg>(
            overflow,
            &route,
            65_536,
            |_| async { Ok(BytesMsg::default()) },
        )
        .await
        .expect("saturation is returned as a wire trailer");
        assert_eq!(overflow_polls.load(Ordering::SeqCst), 0);
        let trailer = state
            .close
            .lock()
            .unwrap()
            .clone()
            .flatten()
            .expect("resource-exhausted trailer");
        assert_eq!(trailer.status, WireCode::ResourceExhausted);
        for task in held {
            task.abort();
        }
    }

    #[tokio::test]
    async fn work_response_raw_cap_is_inclusive_and_precedes_decode() {
        let route = WorkResponseRoute::default();
        let calls = Arc::new(AtomicUsize::new(0));
        let request = BytesMsg {
            payload: vec![0; 65_532],
        };
        let mut encoded = BytesMut::new();
        request.encode(&mut encoded).unwrap();
        assert_eq!(encoded.len(), 65_536);
        let (inbound, state) = route_inbound(Some(encoded.freeze()), false, None);
        let called = calls.clone();
        dispatch_work_response_bounded::<MockTransport, MockMethod, _, _, BytesMsg>(
            inbound,
            &route,
            65_536,
            move |_| async move {
                called.fetch_add(1, Ordering::SeqCst);
                Ok(BytesMsg::default())
            },
        )
        .await
        .expect("the exact boundary is accepted");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            state
                .close
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .as_ref()
                .unwrap()
                .status,
            WireCode::Ok,
        );

        let (overflow, state) = route_inbound(Some(Bytes::from(vec![0xff; 65_537])), false, None);
        dispatch_work_response_bounded::<MockTransport, MockMethod, _, _, BytesMsg>(
            overflow,
            &route,
            65_536,
            |_| async { Ok(BytesMsg::default()) },
        )
        .await
        .expect("raw overflow is a wire rejection, not a decode error");
        assert_eq!(
            state
                .close
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .as_ref()
                .unwrap()
                .status,
            WireCode::InvalidArgument,
        );
    }

    #[tokio::test]
    async fn work_response_route_runs_only_four_handlers() {
        let route = Arc::new(WorkResponseRoute::default());
        let entered = Arc::new(AtomicUsize::new(0));
        let notify = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let request = BytesMsg { payload: vec![7] };
        let mut encoded = BytesMut::new();
        request.encode(&mut encoded).unwrap();
        let encoded = encoded.freeze();
        let mut tasks = Vec::new();
        for _ in 0..5 {
            let (inbound, _state) = route_inbound(Some(encoded.clone()), false, None);
            let route = route.clone();
            let entered = entered.clone();
            let notify = notify.clone();
            let release = release.clone();
            tasks.push(tokio::spawn(async move {
                dispatch_work_response_bounded::<MockTransport, MockMethod, _, _, BytesMsg>(
                    inbound,
                    &route,
                    65_536,
                    move |_| async move {
                        entered.fetch_add(1, Ordering::SeqCst);
                        notify.notify_waiters();
                        release.acquire().await.unwrap().forget();
                        Ok(BytesMsg::default())
                    },
                )
                .await
            }));
        }
        while entered.load(Ordering::SeqCst) < 4 {
            notify.notified().await;
        }
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        assert_eq!(entered.load(Ordering::SeqCst), 4);
        release.add_permits(5);
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        assert_eq!(entered.load(Ordering::SeqCst), 5);
    }

    /// Each dispatch through either bounded route is its own worker
    /// sample, and a request refused for want of a permit is none.
    ///
    /// §4 adds `response_worker_ms` and `general_worker_ms` to a
    /// validator's RPC, and maximises the sum over six validators. The
    /// maximum is the reader's arithmetic: one node emits one sample per
    /// request it actually worked on, and a request that never reached a
    /// worker is not a worker that was slow.
    #[tokio::test]
    async fn each_bounded_route_samples_the_work_it_did_and_not_the_work_it_refused() {
        use crate::observe::Samples;
        use tracing::instrument::WithSubscriber as _;

        let samples = std::sync::Arc::new(Samples::new());
        let request = BytesMsg {
            payload: vec![7; 32],
        };
        let mut encoded = BytesMut::new();
        request.encode(&mut encoded).unwrap();
        let encoded = encoded.freeze();

        let response_route = WorkResponseRoute::default();
        let (inbound, _state) = route_inbound(Some(encoded.clone()), false, None);
        dispatch_work_response_bounded::<MockTransport, MockMethod, _, _, BytesMsg>(
            inbound,
            &response_route,
            65_536,
            |_| async { Ok(BytesMsg::default()) },
        )
        .with_subscriber(samples.clone())
        .await
        .expect("the response is dispatched");

        let general_route = GeneralSubmitRoute::default();
        let (inbound, _state) = route_inbound(Some(encoded.clone()), false, None);
        dispatch_general_submit_bounded::<MockTransport, MockMethod, _, _, BytesMsg>(
            inbound,
            &general_route,
            65_536,
            |_, _| async { Ok(BytesMsg::default()) },
        )
        .with_subscriber(samples.clone())
        .await
        .expect("the general submission is dispatched");

        let workers = samples.of("response_worker_ms");
        assert_eq!(workers.len(), 1, "one response, one worker sample");
        assert_eq!(workers[0].field("method"), Some("Route"));
        assert_eq!(
            workers[0].field("bytes"),
            Some(encoded.len().to_string().as_str()),
            "the sample says how much work it was a sample of",
        );
        let general = samples.of("general_worker_ms");
        assert_eq!(general.len(), 1, "one submission, one worker sample");
        assert_eq!(general[0].field("method"), Some("Route"));

        // A route with no permit refuses before it reads a body, and a
        // refusal is not a duration.
        let full_response = WorkResponseRoute {
            permits: PermitPool::new(0),
            workers: PermitPool::new(4),
        };
        let (inbound, _state) = route_inbound(Some(encoded.clone()), false, None);
        dispatch_work_response_bounded::<MockTransport, MockMethod, _, _, BytesMsg>(
            inbound,
            &full_response,
            65_536,
            |_| async { Ok(BytesMsg::default()) },
        )
        .with_subscriber(samples.clone())
        .await
        .expect("saturation is a wire trailer");
        let full_general = GeneralSubmitRoute {
            permits: PermitPool::new(0),
        };
        let (inbound, _state) = route_inbound(Some(encoded), false, None);
        dispatch_general_submit_bounded::<MockTransport, MockMethod, _, _, BytesMsg>(
            inbound,
            &full_general,
            65_536,
            |_, _| async { Ok(BytesMsg::default()) },
        )
        .with_subscriber(samples.clone())
        .await
        .expect("saturation is a wire trailer");

        assert_eq!(
            samples.of("response_worker_ms").len(),
            1,
            "a response that never reached a worker is not sampled",
        );
        assert_eq!(
            samples.of("general_worker_ms").len(),
            1,
            "a submission that never got a permit is not sampled",
        );
    }
}
