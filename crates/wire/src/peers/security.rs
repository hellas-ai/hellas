/// What the transport proves about bytes received from a peer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TransportSecurity {
    /// The transport cryptographically binds the channel to the peer identity.
    Authenticated,
    /// Local OS credentials or ACLs identify the process on the other end.
    LocalCredential,
    /// The channel is encrypted, but identity binding is application-level.
    ChannelEncrypted,
    /// The channel makes no useful identity or confidentiality guarantee.
    #[default]
    Untrusted,
}

impl TransportSecurity {
    pub const fn strength(self) -> u8 {
        match self {
            Self::Untrusted => 0,
            Self::ChannelEncrypted => 1,
            Self::LocalCredential => 2,
            Self::Authenticated => 3,
        }
    }

    pub const fn strongest(self, other: Self) -> Self {
        if self.strength() >= other.strength() {
            self
        } else {
            other
        }
    }
}

/// Policy-facing authentication view derived from transport facts.
///
/// Conceptually ordered most-to-least authoritative:
/// `Authenticated > Local > Untrusted`. The ordering is exposed only
/// through `allows_at_least` — no `Ord`/`PartialOrd` is derived, so
/// variant declaration order is not load-bearing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AuthLevel {
    #[default]
    Untrusted,
    Local,
    Authenticated,
}

impl AuthLevel {
    pub const fn from_transport(security: TransportSecurity) -> Self {
        match security {
            TransportSecurity::Authenticated => Self::Authenticated,
            TransportSecurity::LocalCredential => Self::Local,
            TransportSecurity::ChannelEncrypted | TransportSecurity::Untrusted => Self::Untrusted,
        }
    }

    /// Numeric authority rank used internally by the policy predicates.
    const fn rank(self) -> u8 {
        match self {
            Self::Untrusted => 0,
            Self::Local => 1,
            Self::Authenticated => 2,
        }
    }

    /// True when `self`'s authority is at least as strong as `threshold`'s.
    pub const fn allows_at_least(self, threshold: Self) -> bool {
        self.rank() >= threshold.rank()
    }
}
