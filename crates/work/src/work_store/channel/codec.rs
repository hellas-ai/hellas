use super::*;

impl ChannelRecord {
    /// What this step must leave room for in one checkpoint, when
    /// recording it is what lets a signature leave.
    ///
    /// `None` for the records that carry no signature and no
    /// variable-width body: a cursor advance, a running marker, a
    /// plaintext release, a match, and the two a finalized block
    /// dictates. Those cannot move the width of a checkpoint by anything
    /// this endpoint chooses.
    pub(super) const fn checkpoint_tail(&self) -> Option<usize> {
        match self {
            Self::JobProposed { .. } => Some(JOB_TAIL_BYTES),
            Self::JobAccepted { .. }
            | Self::JobResult { .. }
            | Self::JobTerminated { .. }
            | Self::ClosePrepared { .. }
            | Self::CloseResponded { .. } => Some(0),
            _ => None,
        }
    }

    /// Whether this step takes on an obligation rather than discharging
    /// one.
    ///
    /// The proposal, and only the proposal. Everything after it follows
    /// a signature already exported — the co-signature the client is
    /// waiting on, the result it bought, the payment, the close, the
    /// answer, and every block the cursor must cross to know about
    /// them — and a journal that refused those would be one that stopped
    /// a duty it had already taken on.
    pub(super) const fn is_new_work(&self) -> bool {
        matches!(self, Self::JobProposed { .. })
    }

    /// Returns this record's canonical bytes.
    ///
    /// Each nested body is its own canonical encoding — the private
    /// record's, or the kernel's — so the journal holds exactly the
    /// bytes whose digests the signatures beside them cover.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.encode_for_storage(false)
    }

    pub(super) fn encode_for_storage(&self, metadata_only: bool) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::CursorAdvanced {
                height,
                parent,
                payload,
            } => {
                out.push(tag::CURSOR);
                put_u64(&mut out, *height);
                out.extend_from_slice(parent);
                out.extend_from_slice(payload);
            }
            Self::JobProposed {
                authorization,
                client_signature,
                prepared_input,
            } => {
                out.push(tag::PROPOSED);
                out.extend_from_slice(&authorization.encode());
                out.extend_from_slice(client_signature.as_bytes());
                // Last field, and the whole of the rest: the journal
                // frame already carries this record's length, and a
                // second length here could disagree with it.
                if !metadata_only {
                    out.extend_from_slice(prepared_input);
                }
            }
            Self::JobAccepted {
                work_id,
                provider_signature,
            } => {
                out.push(tag::ACCEPTED);
                out.extend_from_slice(work_id.as_bytes());
                out.extend_from_slice(provider_signature.as_bytes());
            }
            Self::JobRunning { work_id } => {
                out.push(tag::RUNNING);
                out.extend_from_slice(work_id.as_bytes());
            }
            Self::JobResult {
                work_id,
                result,
                provider_signature,
                transcript,
            } => {
                out.push(tag::RESULT);
                out.extend_from_slice(work_id.as_bytes());
                out.extend_from_slice(&result.encode());
                out.extend_from_slice(provider_signature.as_bytes());
                // Last field, and the whole of the rest, for the reason
                // `JobProposed`'s bundle is: the journal frame already
                // carries this record's length.
                if !metadata_only {
                    out.extend_from_slice(transcript);
                }
            }
            Self::PlaintextReleased { work_id } => {
                out.push(tag::PLAINTEXT);
                out.extend_from_slice(work_id.as_bytes());
            }
            Self::ResultMatched { work_id } => {
                out.push(tag::MATCHED);
                out.extend_from_slice(work_id.as_bytes());
            }
            Self::JobTerminated { work_id, outcome } => {
                out.push(tag::TERMINATED);
                out.extend_from_slice(work_id.as_bytes());
                put_outcome(&mut out, outcome);
            }
            Self::ClosePrepared { start } => {
                out.push(tag::CLOSE_PREPARED);
                // Last field, and the whole of the rest, for the reason
                // `JobProposed`'s bundle is: a start is variable-width,
                // and the journal frame already carries this record's
                // length.
                out.extend_from_slice(&encode_kernel(start.as_ref()));
            }
            Self::CloseOpened {
                start_id,
                opener,
                response_deadline,
                claimed,
            } => {
                out.push(tag::CLOSE_OPENED);
                out.extend_from_slice(&start_id.to_bytes());
                out.push(party_code(*opener));
                put_u64(&mut out, *response_deadline);
                put_u64(&mut out, *claimed);
            }
            Self::CloseResponded {
                start_id,
                response_digest,
            } => {
                out.push(tag::CLOSE_RESPONDED);
                out.extend_from_slice(&start_id.to_bytes());
                out.extend_from_slice(response_digest.as_bytes());
            }
            Self::CloseSettled {
                height,
                payload,
                provider_payout,
            } => {
                out.push(tag::CLOSE_SETTLED);
                put_u64(&mut out, *height);
                out.extend_from_slice(payload);
                put_u64(&mut out, *provider_payout);
            }
        }
        out
    }

    /// Reads one record from exactly its canonical bytes.
    ///
    /// # Errors
    ///
    /// [`ChannelStateError::Malformed`] for an unknown tag, a nested
    /// body that does not decode, a truncated record, or a trailing
    /// byte.
    pub fn decode(bytes: &[u8]) -> Result<Self, ChannelStateError> {
        let mut cursor = Cursor::new(bytes);
        let record = match cursor.byte().ok_or(ChannelStateError::Malformed)? {
            tag::CURSOR => Self::CursorAdvanced {
                height: cursor.u64().ok_or(ChannelStateError::Malformed)?,
                parent: cursor.array::<32>().ok_or(ChannelStateError::Malformed)?,
                payload: cursor.array::<32>().ok_or(ChannelStateError::Malformed)?,
            },
            tag::PROPOSED => Self::JobProposed {
                authorization: private_record(&mut cursor)?,
                client_signature: signature(&mut cursor)?,
                prepared_input: cursor.rest().to_vec(),
            },
            tag::ACCEPTED => Self::JobAccepted {
                work_id: digest(&mut cursor)?,
                provider_signature: signature(&mut cursor)?,
            },
            tag::RUNNING => Self::JobRunning {
                work_id: digest(&mut cursor)?,
            },
            tag::RESULT => Self::JobResult {
                work_id: digest(&mut cursor)?,
                result: private_record(&mut cursor)?,
                provider_signature: signature(&mut cursor)?,
                transcript: cursor.rest().to_vec(),
            },
            tag::PLAINTEXT => Self::PlaintextReleased {
                work_id: digest(&mut cursor)?,
            },
            tag::MATCHED => Self::ResultMatched {
                work_id: digest(&mut cursor)?,
            },
            tag::TERMINATED => Self::JobTerminated {
                work_id: digest(&mut cursor)?,
                outcome: take_outcome(&mut cursor)?,
            },
            tag::CLOSE_PREPARED => Self::ClosePrepared {
                start: Box::new(decode_kernel(cursor.rest())?),
            },
            tag::CLOSE_OPENED => Self::CloseOpened {
                start_id: StartId::from_bytes(
                    cursor
                        .array::<{ StartId::LENGTH }>()
                        .ok_or(ChannelStateError::Malformed)?,
                ),
                opener: party(cursor.byte().ok_or(ChannelStateError::Malformed)?)?,
                response_deadline: cursor.u64().ok_or(ChannelStateError::Malformed)?,
                claimed: cursor.u64().ok_or(ChannelStateError::Malformed)?,
            },
            tag::CLOSE_RESPONDED => Self::CloseResponded {
                start_id: StartId::from_bytes(
                    cursor
                        .array::<{ StartId::LENGTH }>()
                        .ok_or(ChannelStateError::Malformed)?,
                ),
                response_digest: PayloadHash::from_bytes(
                    cursor
                        .array::<{ PayloadHash::LENGTH }>()
                        .ok_or(ChannelStateError::Malformed)?,
                ),
            },
            tag::CLOSE_SETTLED => Self::CloseSettled {
                height: cursor.u64().ok_or(ChannelStateError::Malformed)?,
                payload: cursor.array::<32>().ok_or(ChannelStateError::Malformed)?,
                provider_payout: cursor.u64().ok_or(ChannelStateError::Malformed)?,
            },
            _ => return Err(ChannelStateError::Malformed),
        };
        if cursor.is_empty() {
            Ok(record)
        } else {
            Err(ChannelStateError::Malformed)
        }
    }
}

/// Writes how a job ended.
///
/// One spelling, because a terminal is written twice: once as the record
/// that ends the job and once inside the checkpoint that carries the
/// ended job across a rotation. A second encoder for the second place
/// would be a second answer to what a certified job is.
pub(super) fn put_outcome(out: &mut Vec<u8>, outcome: &TerminalOutcome) {
    match outcome {
        TerminalOutcome::Certified {
            certificate,
            binding,
            binding_signature,
            certificate_signature,
        } => {
            out.push(outcome_code::CERTIFIED);
            out.extend_from_slice(&encode_kernel(certificate));
            out.extend_from_slice(&binding.encode());
            out.extend_from_slice(binding_signature.as_bytes());
            out.extend_from_slice(certificate_signature.as_bytes());
        }
        TerminalOutcome::Refuted {
            result_digest,
            reproduction_digest,
        } => {
            out.push(outcome_code::REFUTED);
            out.extend_from_slice(result_digest.as_bytes());
            out.extend_from_slice(reproduction_digest.as_bytes());
        }
        TerminalOutcome::Expired {
            deadline,
            height,
            payload,
        } => {
            out.push(outcome_code::EXPIRED);
            put_u64(out, *deadline);
            put_u64(out, *height);
            out.extend_from_slice(payload);
        }
        TerminalOutcome::Failed { code } => {
            out.push(outcome_code::FAILED);
            out.extend_from_slice(&code.to_be_bytes());
        }
        TerminalOutcome::Indeterminate => out.push(outcome_code::INDETERMINATE),
    }
}

/// Reads back exactly what [`put_outcome`] wrote.
pub(super) fn take_outcome(cursor: &mut Cursor<'_>) -> Result<TerminalOutcome, ChannelStateError> {
    Ok(match cursor.byte().ok_or(ChannelStateError::Malformed)? {
        outcome_code::CERTIFIED => TerminalOutcome::Certified {
            certificate: certificate(cursor)?,
            binding: Box::new(private_record(cursor)?),
            binding_signature: signature(cursor)?,
            certificate_signature: signature(cursor)?,
        },
        outcome_code::REFUTED => TerminalOutcome::Refuted {
            result_digest: digest(cursor)?,
            reproduction_digest: digest(cursor)?,
        },
        outcome_code::EXPIRED => TerminalOutcome::Expired {
            deadline: cursor.u64().ok_or(ChannelStateError::Malformed)?,
            height: cursor.u64().ok_or(ChannelStateError::Malformed)?,
            payload: cursor.array::<32>().ok_or(ChannelStateError::Malformed)?,
        },
        outcome_code::FAILED => TerminalOutcome::Failed {
            code: u32::from_be_bytes(cursor.array::<4>().ok_or(ChannelStateError::Malformed)?),
        },
        outcome_code::INDETERMINATE => TerminalOutcome::Indeterminate,
        _ => return Err(ChannelStateError::Malformed),
    })
}

pub(super) fn private_record<R: hellas_rpc::protocol::work::PrivateRecord>(
    cursor: &mut Cursor<'_>,
) -> Result<R, ChannelStateError> {
    let bytes = cursor
        .take(R::ENCODED_SIZE)
        .ok_or(ChannelStateError::Malformed)?;
    Ok(R::decode(bytes)?)
}

/// The one byte a party is written as.
pub(super) const fn party_code(party: Party) -> u8 {
    match party {
        Party::Maker => 0,
        Party::Taker => 1,
    }
}

pub(super) fn party(code: u8) -> Result<Party, ChannelStateError> {
    match code {
        0 => Ok(Party::Maker),
        1 => Ok(Party::Taker),
        _ => Err(ChannelStateError::Malformed),
    }
}

pub(super) const fn role_code(role: Role) -> u8 {
    match role {
        Role::Client => 1,
        Role::Provider => 2,
    }
}

pub(super) const fn role_from_code(code: u8) -> Result<Role, ChannelStateError> {
    match code {
        1 => Ok(Role::Client),
        2 => Ok(Role::Provider),
        _ => Err(ChannelStateError::Malformed),
    }
}

pub(super) fn signature(cursor: &mut Cursor<'_>) -> Result<Sig, ChannelStateError> {
    let bytes = cursor
        .array::<{ Sig::LENGTH }>()
        .ok_or(ChannelStateError::Malformed)?;
    Ok(Sig::from_bytes(bytes))
}

pub(super) fn digest(cursor: &mut Cursor<'_>) -> Result<Digest, ChannelStateError> {
    Ok(Digest::from_bytes(
        cursor.array::<32>().ok_or(ChannelStateError::Malformed)?,
    ))
}

pub(super) fn certificate(cursor: &mut Cursor<'_>) -> Result<EarnedCertificate, ChannelStateError> {
    let bytes = cursor
        .take(EarnedCertificate::ENCODED_SIZE)
        .ok_or(ChannelStateError::Malformed)?;
    let (certificate, consumed) =
        EarnedCertificate::decode(bytes).map_err(|_| ChannelStateError::Malformed)?;
    if consumed == bytes.len() {
        Ok(certificate)
    } else {
        Err(ChannelStateError::Malformed)
    }
}

/// Returns the kernel's own canonical encoding of a kernel value.
///
/// The journal holds these bytes and the wire carries them, and both
/// take them from here: the signature beside a certificate is over the
/// digest of this encoding, so a second speller of it would be a second
/// definition of what was signed.
pub(crate) fn encode_kernel<E: Encode>(value: &E) -> Vec<u8> {
    let mut buf = vec![0_u8; value.encoded_size()];
    let written = value.write_to(&mut buf);
    buf.truncate(written);
    buf
}

pub(super) fn decode_kernel<D: Decode>(bytes: &[u8]) -> Result<D, ChannelStateError> {
    D::decode_exact(bytes).map_err(|_| ChannelStateError::Malformed)
}

impl ChannelState {
    /// Returns this state's canonical bytes: the whole of what a
    /// successor generation replays from.
    ///
    /// Not a summary, and the destructuring below is what keeps it from
    /// becoming one. Every field of this struct is named here and named
    /// again in [`Self::decode_checkpoint`]'s literal, so a field added
    /// to [`ChannelState`] and forgotten here does not compile: the
    /// pattern is refused for the field it does not mention, and the
    /// literal for the field it cannot fill. The same holds one level
    /// down, for [`JobState`] and for [`JobTerminal`].
    ///
    /// The channel and the settlement are written as what pins them
    /// rather than as a second copy of themselves: the channel id is a
    /// commitment to the network, both edges and both terms bodies, and
    /// the opener supplies the value. A checkpoint whose id or
    /// settlement is not the opener's is refused, so what the two hold
    /// is one channel and not two that happen to agree.
    #[must_use]
    pub fn checkpoint(&self) -> Vec<u8> {
        self.checkpoint_for_storage(false)
    }

    pub(super) fn checkpoint_for_storage(&self, metadata_only: bool) -> Vec<u8> {
        let Self {
            channel,
            settlement,
            role,
            ledger,
            jobs,
            terminals,
            proposal_nonce_high_water,
            cursor,
            indeterminate,
            close_prepared,
            close_opened,
            close_responded,
            close_settled,
        } = self;

        let mut out = Vec::new();
        out.extend_from_slice(channel.id().as_bytes());
        put_u64(&mut out, settlement.freeze_total());
        put_u64(&mut out, settlement.adjudicated_total());
        put_u64(&mut out, settlement.capacity());
        put_u64(&mut out, settlement.omission_bond());
        out.push(role_code(*role));
        put_u64(&mut out, ledger.credited_cumulative());
        put_u64(&mut out, jobs.len() as u64);
        for job in jobs.values() {
            let JobState {
                authorization,
                work_id,
                prepared_input,
                client_signature,
                provider_signature,
                phase,
                result,
                transcript,
            } = job;
            out.extend_from_slice(&authorization.encode());
            out.extend_from_slice(work_id.as_bytes());
            out.extend_from_slice(client_signature.as_bytes());
            put_option(&mut out, provider_signature.as_ref(), |out, signature| {
                out.extend_from_slice(signature.as_bytes());
            });
            out.push(phase.code());
            put_option(&mut out, result.as_ref(), |out, (result, signature)| {
                out.extend_from_slice(&result.encode());
                out.extend_from_slice(signature.as_bytes());
            });
            put_bytes(&mut out, if metadata_only { &[] } else { prepared_input });
            put_bytes(&mut out, if metadata_only { &[] } else { transcript });
        }
        put_u64(&mut out, terminals.len() as u64);
        for terminal in terminals.values() {
            let JobTerminal {
                work_id,
                phase,
                outcome,
            } = terminal;
            out.extend_from_slice(work_id.as_bytes());
            out.push(phase.code());
            put_outcome(&mut out, outcome);
        }
        put_u64(&mut out, *proposal_nonce_high_water);
        put_u64(&mut out, cursor.0);
        out.extend_from_slice(&cursor.1);
        put_u64(&mut out, indeterminate.len() as u64);
        for work_id in indeterminate.keys() {
            out.extend_from_slice(work_id.as_bytes());
        }
        put_option(&mut out, close_prepared.as_ref(), |out, start| {
            put_bytes(out, &encode_kernel(start));
        });
        put_option(&mut out, close_opened.as_ref(), |out, contest| {
            out.extend_from_slice(&contest.start_id.to_bytes());
            out.push(party_code(contest.opener));
            put_u64(out, contest.response_deadline);
            put_u64(out, contest.claimed);
        });
        put_option(&mut out, close_responded.as_ref(), |out, answer| {
            out.extend_from_slice(&answer.start_id.to_bytes());
            out.extend_from_slice(answer.response_digest.as_bytes());
        });
        put_option(&mut out, close_settled.as_ref(), |out, settlement| {
            put_u64(out, settlement.height);
            out.extend_from_slice(&settlement.payload);
            put_u64(out, settlement.provider_payout);
        });
        out
    }

    /// Reads a checkpoint back into the state it was written from.
    ///
    /// The channel and the settlement are the opener's, and the two
    /// values the checkpoint pins them by are checked against them
    /// first: a successor holding another channel's state is refused
    /// rather than adopted under this channel's keys.
    pub(super) fn decode_checkpoint(
        bytes: &[u8],
        channel: PaidChannel,
        settlement: WorkPaymentSettlement,
        role: Role,
    ) -> Result<Self, ChannelStateError> {
        let mut cursor = Cursor::new(bytes);
        if digest(&mut cursor)?.as_bytes() != channel.id().as_bytes() {
            return Err(ChannelStateError::WrongChannel {
                field: "checkpoint channel_id",
            });
        }
        for (field, held) in [
            ("freeze_total", settlement.freeze_total()),
            ("adjudicated_total", settlement.adjudicated_total()),
            ("capacity", settlement.capacity()),
            ("omission_bond", settlement.omission_bond()),
        ] {
            if cursor.u64().ok_or(ChannelStateError::Malformed)? != held {
                return Err(ChannelStateError::WrongChannel { field });
            }
        }
        if role_from_code(cursor.byte().ok_or(ChannelStateError::Malformed)?)? != role {
            return Err(ChannelStateError::WrongRole {
                step: "replaying a checkpoint",
                expected: match role {
                    Role::Client => "client",
                    Role::Provider => "provider",
                },
            });
        }
        let credited = cursor.u64().ok_or(ChannelStateError::Malformed)?;
        let jobs_len = cursor.u64().ok_or(ChannelStateError::Malformed)?;
        let mut jobs = BTreeMap::new();
        for _ in 0..jobs_len {
            let authorization = private_record(&mut cursor)?;
            let work_id = digest(&mut cursor)?;
            let client_signature = signature(&mut cursor)?;
            let provider_signature =
                take_option(&mut cursor, ChannelStateError::Malformed, signature)?;
            let phase = JobPhase::from_code(cursor.byte().ok_or(ChannelStateError::Malformed)?)?;
            let result = take_option(&mut cursor, ChannelStateError::Malformed, |cursor| {
                Ok((private_record(cursor)?, signature(cursor)?))
            })?;
            let job = JobState {
                authorization,
                work_id,
                client_signature,
                provider_signature,
                phase,
                result,
                prepared_input: take_bytes(&mut cursor, ChannelStateError::Malformed)?.to_vec(),
                transcript: take_bytes(&mut cursor, ChannelStateError::Malformed)?.to_vec(),
            };
            if jobs.insert(work_id, job).is_some() {
                return Err(ChannelStateError::Malformed);
            }
        }
        let terminals_len = cursor.u64().ok_or(ChannelStateError::Malformed)?;
        let mut terminals = BTreeMap::new();
        for _ in 0..terminals_len {
            let terminal = JobTerminal {
                work_id: digest(&mut cursor)?,
                phase: JobPhase::from_code(cursor.byte().ok_or(ChannelStateError::Malformed)?)?,
                outcome: take_outcome(&mut cursor)?,
            };
            if terminals.insert(terminal.work_id, terminal).is_some() {
                return Err(ChannelStateError::Malformed);
            }
        }
        let proposal_nonce_high_water = cursor.u64().ok_or(ChannelStateError::Malformed)?;
        let state = Self {
            channel,
            settlement,
            role,
            ledger: CreditLedger::from_credited_cumulative(credited),
            jobs,
            terminals,
            proposal_nonce_high_water,
            cursor: (
                cursor.u64().ok_or(ChannelStateError::Malformed)?,
                cursor.array::<32>().ok_or(ChannelStateError::Malformed)?,
            ),
            indeterminate: {
                let count = cursor.u64().ok_or(ChannelStateError::Malformed)?;
                let mut held = BTreeMap::new();
                for _ in 0..count {
                    let work_id = digest(&mut cursor)?;
                    if held.insert(work_id, ()).is_some() {
                        return Err(ChannelStateError::Malformed);
                    }
                }
                held
            },
            close_prepared: take_option(&mut cursor, ChannelStateError::Malformed, |cursor| {
                decode_kernel(take_bytes(cursor, ChannelStateError::Malformed)?)
            })?,
            close_opened: take_option(&mut cursor, ChannelStateError::Malformed, |cursor| {
                Ok(OpenContest {
                    start_id: StartId::from_bytes(
                        cursor
                            .array::<{ StartId::LENGTH }>()
                            .ok_or(ChannelStateError::Malformed)?,
                    ),
                    opener: party(cursor.byte().ok_or(ChannelStateError::Malformed)?)?,
                    response_deadline: cursor.u64().ok_or(ChannelStateError::Malformed)?,
                    claimed: cursor.u64().ok_or(ChannelStateError::Malformed)?,
                })
            })?,
            close_responded: take_option(&mut cursor, ChannelStateError::Malformed, |cursor| {
                Ok(RespondedContest {
                    start_id: StartId::from_bytes(
                        cursor
                            .array::<{ StartId::LENGTH }>()
                            .ok_or(ChannelStateError::Malformed)?,
                    ),
                    response_digest: PayloadHash::from_bytes(
                        cursor
                            .array::<{ PayloadHash::LENGTH }>()
                            .ok_or(ChannelStateError::Malformed)?,
                    ),
                })
            })?,
            close_settled: take_option(&mut cursor, ChannelStateError::Malformed, |cursor| {
                Ok(CloseSettlement {
                    height: cursor.u64().ok_or(ChannelStateError::Malformed)?,
                    payload: cursor.array::<32>().ok_or(ChannelStateError::Malformed)?,
                    provider_payout: cursor.u64().ok_or(ChannelStateError::Malformed)?,
                })
            })?,
        };
        if cursor.is_empty() {
            Ok(state)
        } else {
            Err(ChannelStateError::Malformed)
        }
    }
}
