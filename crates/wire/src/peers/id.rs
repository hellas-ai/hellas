use std::fmt;

/// Stable peer identity used by Hellas RPC.
///
/// For Iroh this is the endpoint public key. Other transports should bind their
/// local notion of identity to the same 32-byte key through a handshake or static
/// configuration.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId([u8; 32]);

impl PeerId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for PeerId {
    fn from(bytes: [u8; 32]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl AsRef<[u8; 32]> for PeerId {
    fn as_ref(&self) -> &[u8; 32] {
        self.as_bytes()
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({self})")
    }
}

impl fmt::Display for PeerId {
    /// Default: short hex (`9f3c1d77…4ab8c2e1`) — fits in logs without
    /// dominating. Use the alternate `{:#}` form for the full 64-char hex.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            for byte in &self.0 {
                write!(f, "{byte:02x}")?;
            }
            return Ok(());
        }
        for byte in &self.0[..4] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "…")?;
        for byte in &self.0[28..] {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
