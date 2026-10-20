//! One bounded exchange before ordinary RPC framing. Lengths are checked before
//! reading any body byte. Owned authentication buffers clear themselves on drop.
use hellas_auth::{Digest, authority::*};
use hellas_rpc::authentication::{
    MAX_AUTHENTICATION_MESSAGE_BYTES, decode_challenge, decode_response, encode_challenge,
    encode_response,
};
use hellas_wire::{WireCode, WireStatus};
use hellas_work::{
    node::{NodeCoordinator, SessionKey},
    work_store::grant::NodeStoreError,
};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;
use zeroize::Zeroizing;

const VERSION: u8 = 1;

#[derive(Clone, Copy)]
pub(super) enum Framing {
    /// A dedicated QUIC stream must finish before ordinary RPC streams begin.
    Substream,
    /// Mux frames follow the authentication acknowledgement on this byte stream.
    ByteStream,
}

pub(super) async fn accept<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    node: &NodeCoordinator,
    binding: Digest,
    recv: &mut R,
    send: &mut W,
    framing: Framing,
) -> Result<(AuthenticatedSession, Instant), WireStatus> {
    if recv.read_u8().await.map_err(|_| denied())? != VERSION {
        return Err(denied());
    }
    let started = Instant::now();
    let pending = node
        .begin_authentication(binding)
        .await
        .map_err(node_error)?;
    let issued_at = pending.challenge().issued_at;
    send_message(
        send,
        &encode_challenge(pending.challenge()).map_err(|_| unavailable())?,
    )
    .await?;
    let bytes = read_message(recv).await?;
    // Exactly one response. Returning or cancellation consumes the challenge;
    // a byte stream transitions directly to mux framing after the acknowledgement.
    if matches!(framing, Framing::Substream) {
        eof(recv).await?;
    }
    let (secret, proof) = decode_response(&bytes).map_err(|_| denied())?;
    let session = node
        .complete_authentication(pending, binding, &secret, &proof)
        .await
        .map_err(node_error)?;
    let lifetime = session
        .expires()
        .0
        .checked_sub(issued_at.0)
        .ok_or_else(denied)?;
    let deadline = started
        .checked_add(Duration::from_millis(lifetime))
        .ok_or_else(denied)?;
    Ok((session, deadline))
}

/// Confirm only after the host has reserved the authenticated session's capacity.
pub(super) async fn acknowledge<W: AsyncWrite + Unpin>(
    send: &mut W,
    framing: Framing,
) -> Result<(), WireStatus> {
    send.write_all(&[VERSION]).await.map_err(|_| denied())?;
    if matches!(framing, Framing::Substream) {
        send.shutdown().await.map_err(|_| denied())?;
    } else {
        send.flush().await.map_err(|_| denied())?;
    }
    Ok(())
}

pub(super) async fn connect<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    authority: AuthorityId,
    binding: Digest,
    credential: &CredentialSecret,
    key: SessionKey<'_>,
    recv: &mut R,
    send: &mut W,
    framing: Framing,
) -> Result<(Instant, SessionChallenge), WireStatus> {
    // The host starts its session clock after this byte arrives, so the
    // returned instant never outlasts the session the host enforces.
    let started = Instant::now();
    // QUIC does not expose an opened stream until its first byte is sent.
    send.write_all(&[VERSION]).await.map_err(|_| denied())?;
    send.flush().await.map_err(|_| denied())?;
    let bytes = read_message(recv).await?;
    let challenge = decode_challenge(&bytes).map_err(|_| denied())?;
    let proof = key
        .prove(&challenge, authority, binding, credential.id())
        .map_err(|_| denied())?;
    let lifetime = challenge
        .session_expires
        .0
        .checked_sub(challenge.issued_at.0)
        .ok_or_else(denied)?;
    let response = encode_response(credential, &proof).map_err(|_| denied())?;
    send_message(send, &response).await?;
    if matches!(framing, Framing::Substream) {
        send.shutdown().await.map_err(|_| denied())?;
    } else {
        send.flush().await.map_err(|_| denied())?;
    }
    if recv.read_u8().await.map_err(|_| denied())? != VERSION {
        return Err(denied());
    }
    if matches!(framing, Framing::Substream) {
        eof(recv).await?;
    }
    let deadline = started
        .checked_add(Duration::from_millis(lifetime))
        .ok_or_else(denied)?;
    Ok((deadline, challenge))
}

async fn send_message<W: AsyncWrite + Unpin>(send: &mut W, bytes: &[u8]) -> Result<(), WireStatus> {
    if bytes.len() > MAX_AUTHENTICATION_MESSAGE_BYTES {
        return Err(denied());
    }
    let length = u16::try_from(bytes.len()).map_err(|_| denied())?;
    send.write_u16(length).await.map_err(|_| denied())?;
    send.write_all(bytes).await.map_err(|_| denied())?;
    send.flush().await.map_err(|_| denied())
}

async fn read_message<R: AsyncRead + Unpin>(
    recv: &mut R,
) -> Result<Zeroizing<Vec<u8>>, WireStatus> {
    let length = usize::from(recv.read_u16().await.map_err(|_| denied())?);
    if length == 0 || length > MAX_AUTHENTICATION_MESSAGE_BYTES {
        return Err(denied());
    }
    let mut bytes = Zeroizing::new(vec![0; length]);
    recv.read_exact(bytes.as_mut_slice())
        .await
        .map_err(|_| denied())?;
    Ok(bytes)
}

async fn eof<R: AsyncRead + Unpin>(recv: &mut R) -> Result<(), WireStatus> {
    let mut byte = Zeroizing::new([0]);
    if recv.read(&mut *byte).await.map_err(|_| denied())? != 0 {
        return Err(denied());
    }
    Ok(())
}

fn denied() -> WireStatus {
    WireStatus::new(
        WireCode::PermissionDenied,
        "application authentication failed",
    )
}
fn unavailable() -> WireStatus {
    WireStatus::new(WireCode::Unavailable, "node authority is unavailable")
}
fn node_error(error: NodeStoreError) -> WireStatus {
    match error {
        NodeStoreError::Authority(_) => denied(),
        _ => unavailable(),
    }
}
