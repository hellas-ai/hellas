use super::*;

impl SetupRecord {
    /// Whether recording this step is what lets a signature leave.
    ///
    /// The two revisions, and only those: everything else here is a
    /// marker about transactions already signed, or a note of what a
    /// finalized block said.
    pub(super) const fn exports_signature(&self) -> bool {
        matches!(
            self,
            Self::Bundle { .. } | Self::ArmedBundle { .. } | Self::Offer { .. }
        )
    }

    /// Whether this step takes on an obligation rather than discharging
    /// one.
    ///
    /// The offer and the two revisions are where a handshake
    /// commits itself, so they are what stops when the journal cannot
    /// rotate. Everything below them follows a revision this endpoint
    /// has already exported — the submissions it authorised, the history
    /// that resolves them, and the end it reaches — and a journal that
    /// refused those would be one that stopped an obligation it had
    /// already taken.
    pub(super) const fn is_new_work(&self) -> bool {
        matches!(
            self,
            Self::Bundle { .. } | Self::ArmedBundle { .. } | Self::Offer { .. }
        )
    }

    /// Returns this record's canonical bytes.
    pub fn encode(&self) -> Result<Vec<u8>, SetupStateError> {
        let mut out = Vec::new();
        match self {
            Self::Offer { peer, offer } => {
                out.push(tag::OFFER);
                out.extend_from_slice(peer);
                out.extend_from_slice(&offer.encode().map_err(|_| SetupStateError::Malformed)?);
            }
            Self::Bundle { bundle } => {
                out.push(tag::BUNDLE);
                // Last field, and the whole of the rest: the journal
                // frame already carries this record's length, and a
                // second length here could disagree with it.
                out.extend_from_slice(bundle);
            }
            Self::ArmedBundle {
                bundle,
                close_descriptor,
            } => {
                out.push(tag::ARMED_BUNDLE);
                put_u64(&mut out, u64::try_from(bundle.len()).unwrap_or(u64::MAX));
                out.extend_from_slice(bundle);
                out.extend_from_slice(&close_descriptor.encode()?);
            }
            Self::Observed(observed) => {
                out.push(tag::OBSERVED);
                put_u64(&mut out, observed.height);
                out.extend_from_slice(&[
                    u8::from(observed.bond_live),
                    u8::from(observed.payment_live),
                ]);
            }
            Self::BondTimeoutSubmitted => out.push(tag::BOND_TIMEOUT_SUBMITTED),
            Self::BondSubmitted => out.push(tag::BOND_SUBMITTED),
            Self::PaymentSubmitted => out.push(tag::PAYMENT_SUBMITTED),
            Self::Complete {
                payment_edge,
                origin_height,
                origin_payload,
            } => {
                out.push(tag::COMPLETE);
                out.extend_from_slice(&payment_edge.to_bytes());
                put_u64(&mut out, *origin_height);
                out.extend_from_slice(origin_payload);
            }
            Self::Ended { outcome } => {
                out.push(tag::ENDED);
                out.push(end_to_code(*outcome));
            }
        }
        Ok(out)
    }

    /// Reads one record from exactly its canonical bytes.
    ///
    /// # Errors
    ///
    /// [`SetupStateError::Malformed`] for an unknown tag, a truncated
    /// body, or a trailing byte.
    pub fn decode(bytes: &[u8]) -> Result<Self, SetupStateError> {
        let mut cursor = Cursor::new(bytes);
        let record = match cursor.byte().ok_or(SetupStateError::Malformed)? {
            tag::OFFER => Self::Offer {
                peer: cursor.array().ok_or(SetupStateError::Malformed)?,
                offer: Box::new(
                    crate::model::offer::SignedPaidOffer::decode(cursor.rest())
                        .map_err(|_| SetupStateError::Malformed)?,
                ),
            },
            tag::BUNDLE => Self::Bundle {
                bundle: cursor.rest().to_vec(),
            },
            tag::ARMED_BUNDLE => {
                let bundle_len = usize::try_from(cursor.u64().ok_or(SetupStateError::Malformed)?)
                    .map_err(|_| SetupStateError::Malformed)?;
                let bundle = cursor
                    .take(bundle_len)
                    .ok_or(SetupStateError::Malformed)?
                    .to_vec();
                let close_descriptor = CloseDescriptor::decode(cursor.rest())
                    .map_err(|_| SetupStateError::Malformed)?;
                Self::ArmedBundle {
                    bundle,
                    close_descriptor: Box::new(close_descriptor),
                }
            }
            tag::OBSERVED => Self::Observed(SetupObservation {
                height: cursor.u64().ok_or(SetupStateError::Malformed)?,
                bond_live: take_bool(&mut cursor, SetupStateError::Malformed)?,
                payment_live: take_bool(&mut cursor, SetupStateError::Malformed)?,
            }),
            tag::BOND_TIMEOUT_SUBMITTED => Self::BondTimeoutSubmitted,
            tag::BOND_SUBMITTED => Self::BondSubmitted,
            tag::PAYMENT_SUBMITTED => Self::PaymentSubmitted,
            tag::COMPLETE => Self::Complete {
                payment_edge: EdgeId::from_bytes(
                    cursor.array::<32>().ok_or(SetupStateError::Malformed)?,
                ),
                origin_height: cursor.u64().ok_or(SetupStateError::Malformed)?,
                origin_payload: cursor.array::<32>().ok_or(SetupStateError::Malformed)?,
            },
            tag::ENDED => Self::Ended {
                outcome: end_from_code(cursor.byte().ok_or(SetupStateError::Malformed)?)
                    .ok_or(SetupStateError::Malformed)?,
            },
            _ => return Err(SetupStateError::Malformed),
        };
        if cursor.is_empty() {
            Ok(record)
        } else {
            Err(SetupStateError::Malformed)
        }
    }
}

fn put_origin(out: &mut Vec<u8>, origin: &SetupOrigin) {
    out.extend_from_slice(&origin.payment_edge.to_bytes());
    put_u64(out, origin.height);
    out.extend_from_slice(&origin.payload);
}
fn take_origin(cursor: &mut Cursor<'_>) -> Result<SetupOrigin, SetupStateError> {
    Ok(SetupOrigin {
        payment_edge: EdgeId::from_bytes(cursor.array::<32>().ok_or(SetupStateError::Malformed)?),
        height: cursor.u64().ok_or(SetupStateError::Malformed)?,
        payload: cursor.array::<32>().ok_or(SetupStateError::Malformed)?,
    })
}

pub(super) const fn role_code(role: Role) -> u8 {
    match role {
        Role::Client => 1,
        Role::Provider => 2,
    }
}

pub(super) const fn role_from_code(code: u8) -> Result<Role, SetupStateError> {
    match code {
        1 => Ok(Role::Client),
        2 => Ok(Role::Provider),
        _ => Err(SetupStateError::Malformed),
    }
}

/// Whether a close descriptor is the one its setup bundle produces.
///
/// One spelling, asked when the descriptor is first armed beside its
/// revision and again when a checkpoint carrying the pair is opened. A
/// descriptor that described some other channel would be an endpoint
/// recovering a close for a channel it does not have.
pub(super) fn describes_bundle(
    bundle: &WorkChannelSetupBundleV2,
    close_descriptor: &CloseDescriptor,
) -> Result<(), SetupStateError> {
    let Some(payment_edge) = bundle.payment_edge() else {
        return Err(SetupStateError::DescriptorMismatch);
    };
    if close_descriptor.channel().network() != bundle.network()
        || close_descriptor.channel().payment_edge() != payment_edge
        || bundle.payment_terms() != Some(close_descriptor.channel().payment_terms())
        || close_descriptor.bond_edge() != bundle.bond_edge()
    {
        return Err(SetupStateError::DescriptorMismatch);
    }
    Ok(())
}

impl SetupState {
    /// Encodes the signed handshake, what reads have shown and the
    /// outcomes. Its size is independent of chain length.
    pub fn checkpoint(&self) -> Result<Vec<u8>, SetupStateError> {
        let Self {
            offer,
            network,
            bond_edge,
            role,
            bundle,
            bundle_bytes,
            close_descriptor,
            unresolved_bond_open,
            unresolved_payment_open,
            observed_height,
            bond_finalized,
            payment_finalized,
            bond_timeout_submitted,
            origin,
            end,
        } = self;

        let mut out = Vec::new();
        put_bytes(&mut out, network.as_str().as_bytes());
        out.extend_from_slice(&bond_edge.to_bytes());
        out.push(role_code(*role));
        // The value and its bytes are one field written once: the
        // presence byte is the decoded revision's, and the body is the
        // bytes it was decoded from.
        put_option(&mut out, bundle.as_ref(), |out, _| {
            put_bytes(out, bundle_bytes);
        });
        let close_bytes = close_descriptor.as_ref().map(|d| d.encode()).transpose()?;
        put_option(&mut out, close_bytes.as_ref(), |out, bytes| {
            put_bytes(out, bytes);
        });
        out.push(u8::from(*unresolved_bond_open));
        out.push(u8::from(*unresolved_payment_open));
        put_option(&mut out, observed_height.as_ref(), |out, height| {
            put_u64(out, *height);
        });
        out.push(u8::from(*bond_finalized));
        out.push(u8::from(*payment_finalized));
        out.push(u8::from(*bond_timeout_submitted));
        put_option(&mut out, origin.as_ref(), put_origin);
        put_option(&mut out, end.as_ref(), |out, end| {
            out.push(end_to_code(*end));
        });
        match offer {
            Some((peer, offer)) => {
                out.push(1);
                out.extend_from_slice(peer);
                put_bytes(
                    &mut out,
                    &offer.encode().map_err(|_| SetupStateError::Malformed)?,
                );
            }
            None => out.push(0),
        }
        Ok(out)
    }

    /// Reads a checkpoint back into the state it was written from.
    ///
    /// Decoding only. What makes those bytes a state this endpoint may
    /// hold is [`Self::revalidate`] and the signature check beside it,
    /// and [`SetupStore::open`] runs both — this is separate because
    /// discovery has a journal to name and no verifier to name it with.
    ///
    /// # Errors
    ///
    /// [`SetupStateError::Malformed`] for a truncated body, an unknown
    /// code, or a trailing byte, and
    /// [`SetupStateError::Bundle`]/[`SetupStateError::Descriptor`] when
    /// a nested body does not decode.
    pub(super) fn decode_checkpoint(bytes: &[u8]) -> Result<Self, SetupStateError> {
        let mut cursor = Cursor::new(bytes);
        let network = std::str::from_utf8(take_bytes(&mut cursor, SetupStateError::Malformed)?)
            .ok()
            .and_then(NetworkId::new)
            .ok_or(SetupStateError::Malformed)?;
        let bond_edge = EdgeId::from_bytes(cursor.array::<32>().ok_or(SetupStateError::Malformed)?);
        let role = role_from_code(cursor.byte().ok_or(SetupStateError::Malformed)?)?;
        let bundle_bytes = take_option(&mut cursor, SetupStateError::Malformed, |cursor| {
            Ok(take_bytes(cursor, SetupStateError::Malformed)?.to_vec())
        })?;
        let bundle = bundle_bytes
            .as_deref()
            .map(WorkChannelSetupBundleV2::decode)
            .transpose()?;
        let close_descriptor = take_option(&mut cursor, SetupStateError::Malformed, |cursor| {
            Ok(CloseDescriptor::decode(take_bytes(
                cursor,
                SetupStateError::Malformed,
            )?)?)
        })?;
        let unresolved_bond_open = take_bool(&mut cursor, SetupStateError::Malformed)?;
        let unresolved_payment_open = take_bool(&mut cursor, SetupStateError::Malformed)?;
        let observed_height = take_option(&mut cursor, SetupStateError::Malformed, |cursor| {
            cursor.u64().ok_or(SetupStateError::Malformed)
        })?;
        let state = Self {
            network,
            bond_edge,
            role,
            bundle,
            bundle_bytes: bundle_bytes.unwrap_or_default(),
            close_descriptor,
            unresolved_bond_open,
            unresolved_payment_open,
            observed_height,
            bond_finalized: take_bool(&mut cursor, SetupStateError::Malformed)?,
            payment_finalized: take_bool(&mut cursor, SetupStateError::Malformed)?,
            bond_timeout_submitted: take_bool(&mut cursor, SetupStateError::Malformed)?,
            origin: take_option(&mut cursor, SetupStateError::Malformed, take_origin)?,
            end: take_option(&mut cursor, SetupStateError::Malformed, |cursor| {
                end_from_code(cursor.byte().ok_or(SetupStateError::Malformed)?)
                    .ok_or(SetupStateError::Malformed)
            })?,
            offer: take_option(&mut cursor, SetupStateError::Malformed, |cursor| {
                let peer = cursor.array().ok_or(SetupStateError::Malformed)?;
                let offer = crate::model::offer::SignedPaidOffer::decode(take_bytes(
                    cursor,
                    SetupStateError::Malformed,
                )?)
                .map_err(|_| SetupStateError::Malformed)?;
                Ok((peer, offer))
            })?,
        };
        if cursor.is_empty() {
            Ok(state)
        } else {
            Err(SetupStateError::Malformed)
        }
    }
}
