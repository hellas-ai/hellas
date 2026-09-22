//! Canonical kernel-to-public projections; no persistence or state lookup occurs here.
use super::types::*;
use hellas_kernel::{self as kernel, Decode, Encode, TermsProfile};

/// Verify each evidence block once and retain its decoded transactions for the
/// projection checks. Discovery and current objects remain indexer-reported.
pub fn verify_metadata(
    metadata: &EdgeIndexMetadata,
    verifier: &crate::proof_verify::ProofVerifier,
    trust: &hellas_genesis::TrustDocument,
) -> Result<Vec<crate::proof_verify::VerifiedBlock>, ProjectionError> {
    metadata
        .validate()
        .map_err(|e| ProjectionError::Malformed(e.into()))?;
    if metadata.genesis_sha256 != trust.genesis_sha256
        || metadata.network_id != trust.network_id
        || metadata.trust_sha256 != verifier.trust_sha256()
    {
        return Err(ProjectionError::Binding);
    }
    let snapshot = required(&metadata.snapshot)?;
    std::iter::once(required(&snapshot.block_proof)?)
        .chain(&metadata.evidence)
        .map(|proof| {
            verifier
                .verify(
                    proof.clone(),
                    crate::proof_verify::ProofQuery::Block(crate::FinalizedBlockQuery::Payload(
                        digest(&proof.payload)?,
                    )),
                )
                .map_err(|e| ProjectionError::Malformed(e.to_string()))
        })
        .collect()
}
fn required<T>(value: &Option<T>) -> Result<&T, ProjectionError> {
    value.as_ref().ok_or(ProjectionError::Binding)
}
fn check_ref(
    reference: &TransactionRef,
    metadata: &EdgeIndexMetadata,
) -> Result<(), ProjectionError> {
    validate_id(&reference.payload).map_err(|e| ProjectionError::Malformed(e.into()))?;
    validate_id(&reference.transaction_digest).map_err(|e| ProjectionError::Malformed(e.into()))?;
    if reference.height > required(&metadata.snapshot)?.height {
        return Err(ProjectionError::Binding);
    }
    Ok(())
}
fn check_summary(
    summary: &EdgeSummary,
    metadata: &EdgeIndexMetadata,
) -> Result<(), ProjectionError> {
    for id in [&summary.edge_id, &summary.terms_hash]
        .into_iter()
        .chain(summary.bond_edge_id.iter())
        .chain(summary.payment_edge_id.iter())
    {
        validate_id(id).map_err(|e| ProjectionError::Malformed(e.into()))?;
    }
    let opened = required(&summary.opened)?;
    if summary.maker.len() != kernel::Key::LENGTH
        || summary.taker.len() != kernel::Key::LENGTH
        || !matches!(
            summary.kind.as_str(),
            "basic" | "work-payment" | "work-stake-bond"
        )
        || !matches!(
            (summary.lifecycle.as_str(), &summary.closed),
            ("open", None) | ("closed", Some(_))
        )
    {
        return Err(ProjectionError::Binding);
    }
    check_ref(opened, metadata)?;
    if let Some(closed) = &summary.closed {
        check_ref(closed, metadata)?;
        if (closed.height, closed.transaction_index) <= (opened.height, opened.transaction_index) {
            return Err(ProjectionError::Binding);
        }
    }
    Ok(())
}
pub fn check_list(response: &ListEdgesResponse) -> Result<(), ProjectionError> {
    let metadata = required(&response.envelope)?;
    let data = required(&response.data)?;
    if data.items.len() > 64 || !data.items.windows(2).all(|v| v[0].edge_id < v[1].edge_id) {
        return Err(ProjectionError::Binding);
    }
    for summary in &data.items {
        check_summary(summary, metadata)?;
    }
    Ok(())
}
/// Checks reported event bytes and ordering; linked evidence must be fetched separately
/// before calling any individual event consensus-included.
pub fn check_events(
    response: &ListEdgeEventsResponse,
    expected_edge_id: &str,
) -> Result<(), ProjectionError> {
    use commonware_codec::{DecodeExt as _, Encode as _};
    let metadata = required(&response.envelope)?;
    let snapshot = required(&metadata.snapshot)?;
    let data = required(&response.data)?;
    validate_id(expected_edge_id).map_err(|e| ProjectionError::Malformed(e.into()))?;
    if data.items.len() > 64 {
        return Err(ProjectionError::Binding);
    }
    let mut previous = None;
    for event in &data.items {
        let transaction = required(&event.transaction)?;
        check_ref(transaction, metadata)?;
        let position = (transaction.height, transaction.transaction_index);
        if previous.is_some_and(|p| p >= position) {
            return Err(ProjectionError::Binding);
        }
        previous = Some(position);
        if transaction.height > snapshot.height {
            return Err(ProjectionError::Binding);
        }
        validate_id(&transaction.payload).map_err(|e| ProjectionError::Malformed(e.into()))?;
        let tx = crate::domain::Transaction::decode(event.canonical_transaction.as_slice())
            .map_err(|e| ProjectionError::Malformed(e.to_string()))?;
        if tx.encode().as_ref() != event.canonical_transaction
            || crate::proof_verify::transaction_digest(&tx)
                != digest(&transaction.transaction_digest)?
        {
            return Err(ProjectionError::Binding);
        }
        let (id, kind) = match tx {
            crate::domain::Transaction::Kernel(kernel::Tx::Open { funding, terms, .. }) => {
                (kernel::Tx::edge_id_of(&funding, &terms), "open")
            }
            crate::domain::Transaction::Kernel(kernel::Tx::Close { input, .. }) => (input, "close"),
            crate::domain::Transaction::Kernel(kernel::Tx::Move { action }) => (
                match action {
                    kernel::Move::StartPaymentClose(start) => start.payment_edge(),
                    kernel::Move::RespondPaymentClose(response) => response.payment_edge(),
                },
                "move",
            ),
            _ => return Err(ProjectionError::Binding),
        };
        if hex::encode(id.as_bytes()) != expected_edge_id || event.kind != kind {
            return Err(ProjectionError::Binding);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn payment_terms() -> kernel::Terms {
        kernel::Terms::work_payment(kernel::WorkPaymentTerms {
            bond_edge: kernel::EdgeId::from_bytes([3; 32]),
            bond_terms: kernel::WorkStakeBondTerms {
                parties: kernel::Parties::new(
                    kernel::Key::from_bytes([1; kernel::Key::LENGTH]),
                    kernel::Key::from_bytes([2; kernel::Key::LENGTH]),
                ),
                timeout: kernel::BlockHeight::new(100),
                timeout_outputs: kernel::List::take(
                    [kernel::Payout::default(); kernel::MAX_EDGE_OUTPUTS],
                    0,
                ),
                max_job_price: u64::MAX,
            },
            private_policy_commitment: [4; 32],
            omit_response_blocks: 64,
            start_validity_blocks: 8,
            omission_bond: 5,
        })
    }
    #[test]
    fn payment_projection_retains_embedded_bond_and_exact_admission_boundary() {
        let terms = payment_terms();
        let public = public_terms(&terms).unwrap();
        let Some(TermsKind::WorkPayment(payment)) = public.terms else {
            panic!("work payment")
        };
        assert_eq!(payment.admission_horizon, 100);
        assert_eq!(payment.maker, vec![2; kernel::Key::LENGTH]);
        assert_eq!(payment.taker, vec![1; kernel::Key::LENGTH]);
        let bond: kernel::Terms = decode_canonical(&payment.canonical_bond_terms).unwrap();
        assert_eq!(hex::encode(bond.hash().as_bytes()), payment.bond_terms_hash);
        assert_eq!(payment.allowed_close_kinds, ["freeze", "adjudicated"]);
        assert_eq!(admission_at(99, &terms), "before_horizon");
        assert_eq!(admission_at(100, &terms), "ended");
        assert_eq!(admission_at(101, &terms), "ended");
    }
    #[test]
    fn basic_protocol_is_decoded_without_reclassifying_unsupported_terms() {
        let terms = kernel::Terms::basic(
            kernel::ProtocolCode::new(7),
            kernel::Parties::new(
                kernel::Key::from_bytes([1; kernel::Key::LENGTH]),
                kernel::Key::from_bytes([2; kernel::Key::LENGTH]),
            ),
            kernel::BlockHeight::new(8),
            kernel::List::take([kernel::Payout::default(); kernel::MAX_EDGE_OUTPUTS], 0),
        );
        let public = public_terms(&terms).unwrap();
        assert!(matches!(
            public.terms,
            Some(TermsKind::Basic(BasicTerms { protocol: 7, .. }))
        ));
        let mut bytes = canonical_bytes(&terms);
        bytes[2] = 255;
        assert!(decode_canonical::<kernel::Terms>(&bytes).is_err());
    }
    #[test]
    fn summary_checks_kernel_id_and_preserves_party_order() {
        let terms = payment_terms();
        let funding = kernel::Funding::new(
            kernel::List::take(
                [kernel::CoinId::from_bytes([5; 32]); kernel::MAX_PARTY_INPUTS],
                1,
            ),
            kernel::List::take(
                [kernel::CoinId::from_bytes([6; 32]); kernel::MAX_PARTY_INPUTS],
                0,
            ),
        );
        let edge_id = hex::encode(kernel::Tx::edge_id_of(&funding, &terms).as_bytes());
        let opened = TransactionRef {
            height: 4,
            payload: "ab".repeat(32),
            transaction_digest: "cd".repeat(32),
            transaction_index: 0,
        };
        let summary = summary_from_open(
            &edge_id,
            &opened,
            None,
            &funding,
            &terms,
            None,
            &"ef".repeat(32),
        )
        .unwrap();
        assert_eq!(summary.kind, "work-payment");
        assert_eq!(summary.lifecycle, "open");
        assert_eq!(summary.maker, vec![2; kernel::Key::LENGTH]);
        assert_eq!(summary.bond_edge_id, Some("03".repeat(32)));
        assert!(
            summary_from_open(
                &"00".repeat(32),
                &opened,
                None,
                &funding,
                &terms,
                None,
                &"ef".repeat(32)
            )
            .is_err()
        );
    }
    #[test]
    fn missing_registry_slots_are_not_a_missing_parser_answer() {
        let terms = payment_terms();
        let bond = kernel::EdgeId::from_bytes([3; 32]);
        let payment = kernel::EdgeId::from_bytes([4; 32]);
        assert!(matches!(
            lease_projection([None, None], bond, payment, &terms).answer,
            Some(LeaseState::Absent(_))
        ));
        assert!(matches!(
            pending_projection(None, payment).answer,
            Some(PendingState::Absent(_))
        ));
    }
}

fn digest(value: &str) -> Result<crate::domain::Digest, ProjectionError> {
    validate_id(value).map_err(|e| ProjectionError::Malformed(e.into()))?;
    let bytes: [u8; 32] = hex::decode(value)
        .map_err(|e| ProjectionError::Malformed(e.to_string()))?
        .try_into()
        .map_err(|_| ProjectionError::Binding)?;
    Ok(crate::domain::Digest::from(bytes))
}
fn referenced_transaction<'a>(
    reference: &TransactionRef,
    blocks: &'a [crate::proof_verify::VerifiedBlock],
) -> Result<&'a crate::domain::Transaction, ProjectionError> {
    let block = blocks
        .iter()
        .find(|b| b.bundle().payload == reference.payload)
        .ok_or(ProjectionError::Binding)?;
    if reference.height != block.view().height() {
        return Err(ProjectionError::Binding);
    }
    let tx = block
        .view()
        .txs()
        .get(reference.transaction_index as usize)
        .ok_or(ProjectionError::Binding)?;
    if crate::proof_verify::transaction_digest(tx) != digest(&reference.transaction_digest)? {
        return Err(ProjectionError::Binding);
    }
    Ok(tx)
}
/// Checks public projections against their canonical evidence. Does not verify consensus
/// signatures, current-state membership, global discovery, or completeness.
pub fn check_detail(
    detail: &EdgeDetail,
    envelope: &EdgeIndexMetadata,
    blocks: &[crate::proof_verify::VerifiedBlock],
) -> Result<(), ProjectionError> {
    let summary = required(&detail.summary)?;
    check_summary(summary, envelope)?;
    let snapshot = required(&envelope.snapshot)?;
    let related = required(&detail.related)?;
    let object = required(&detail.object_at_snapshot)?;
    let opening = required(&detail.opening)?;
    let transaction = required(&opening.transaction)?;
    if Some(transaction) != summary.opened.as_ref()
        || transaction.height > snapshot.height
        || detail.closing.as_ref().is_some_and(|c| {
            c.transaction
                .as_ref()
                .is_none_or(|t| t.height > snapshot.height)
        })
    {
        return Err(ProjectionError::Binding);
    }
    let tx = referenced_transaction(transaction, blocks)?;
    let crate::domain::Transaction::Kernel(kernel::Tx::Open { funding, terms, .. }) = tx else {
        return Err(ProjectionError::Binding);
    };
    let expected_opening = opening_projection(transaction.clone(), funding, terms)?;
    if &expected_opening != opening {
        return Err(ProjectionError::Binding);
    }
    let edge_id = hex::encode(kernel::Tx::edge_id_of(funding, terms).as_bytes());
    // A bond's opening cannot name a payment created later. Authenticate any
    // claimed reverse association with that payment's own certified opening.
    // Absence remains a discovery claim, not a proof that no payment exists.
    if let Some(payment_id) = &related.payment_edge_id {
        validate_id(payment_id).map_err(|e| ProjectionError::Malformed(e.into()))?;
        if !matches!(terms.profile(), TermsProfile::WorkStakeBond(_))
            || !blocks.iter().any(|block| {
                let height = block.view().height();
                height <= snapshot.height
                    && block.view().txs().iter().enumerate().any(|(index, tx)| {
                        if (height, index)
                            <= (transaction.height, transaction.transaction_index as usize)
                        {
                            return false;
                        }
                        let crate::domain::Transaction::Kernel(kernel::Tx::Open {
                            funding,
                            terms,
                            ..
                        }) = tx
                        else {
                            return false;
                        };
                        let TermsProfile::WorkPayment(payment) = terms.profile() else {
                            return false;
                        };
                        hex::encode(kernel::Tx::edge_id_of(funding, terms).as_bytes())
                            == *payment_id
                            && hex::encode(payment.bond_edge.as_bytes()) == edge_id
                            && canonical_bytes(&kernel::Terms::work_stake_bond(
                                payment.bond_terms.clone(),
                            )) == opening.canonical_terms
                    })
            })
        {
            return Err(ProjectionError::Binding);
        }
    }
    let expected = summary_from_open(
        &edge_id,
        transaction,
        summary.closed.as_ref(),
        funding,
        terms,
        related.payment_edge_id.as_deref(),
        &snapshot.payload,
    )?;
    if summary != &expected || related.bond_edge_id != expected.bond_edge_id {
        return Err(ProjectionError::Binding);
    }
    match (&detail.closing, &summary.closed) {
        (None, None) if summary.lifecycle == "open" => {}
        (Some(closing), Some(reference)) if summary.lifecycle == "closed" => {
            if closing.transaction.as_ref() != Some(reference)
                || (reference.height, reference.transaction_index)
                    <= (transaction.height, transaction.transaction_index)
            {
                return Err(ProjectionError::Binding);
            }
            let close = referenced_transaction(reference, blocks)?;
            match close {
                crate::domain::Transaction::Kernel(kernel::Tx::Close { input, .. })
                    if hex::encode(input.as_bytes()) == edge_id => {}
                _ => return Err(ProjectionError::Binding),
            }
        }
        _ => return Err(ProjectionError::Binding),
    }
    match &object.answer {
        Some(ObjectState::Present(present)) => {
            if present.provenance != "indexer-reported" || summary.lifecycle != "open" {
                return Err(ProjectionError::Binding);
            }
            let edge: kernel::Edge = decode_canonical(&present.canonical)?;
            if Some(edge_projection(&edge)) != present.decoded
                || edge.parties() != terms.parties()
                || edge.terms() != terms.hash()
                || edge.timeout() != terms.timeout()
                || edge.allowed_closes() != terms.allowed_closes()
            {
                return Err(ProjectionError::Binding);
            }
        }
        Some(ObjectState::Absent(absent))
            if absent.provenance == "indexer-reported" && summary.lifecycle == "closed" => {}
        _ => return Err(ProjectionError::Binding),
    }
    Ok(())
}
fn edge_id(value: &str) -> Result<kernel::EdgeId, ProjectionError> {
    validate_id(value).map_err(|e| ProjectionError::Malformed(e.into()))?;
    Ok(kernel::EdgeId::from_bytes(
        hex::decode(value)
            .map_err(|e| ProjectionError::Malformed(e.to_string()))?
            .try_into()
            .map_err(|_| ProjectionError::Binding)?,
    ))
}
/// Checks ordered raw objects and parser answers from a single claimed snapshot.
pub fn check_work_channel(
    detail: &WorkChannelDetail,
    network: kernel::NetworkId,
    envelope: &EdgeIndexMetadata,
    blocks: &[crate::proof_verify::VerifiedBlock],
) -> Result<(), ProjectionError> {
    let height = required(&envelope.snapshot)?.height;
    let payment_detail = required(&detail.payment)?;
    let bond_detail = required(&detail.bond)?;
    check_detail(payment_detail, envelope, blocks)?;
    check_detail(bond_detail, envelope, blocks)?;
    let payment_summary = required(&payment_detail.summary)?;
    let bond_summary = required(&bond_detail.summary)?;
    let payment_opening = required(&payment_detail.opening)?;
    let bond_opening = required(&bond_detail.opening)?;
    let pending_slot = required(&detail.pending_slot)?;
    let payment_id = edge_id(&payment_summary.edge_id)?;
    let bond_id = edge_id(&bond_summary.edge_id)?;
    let terms: kernel::Terms = decode_canonical(&payment_opening.canonical_terms)?;
    let TermsProfile::WorkPayment(payment) = terms.profile() else {
        return Err(ProjectionError::Binding);
    };
    if payment.bond_edge != bond_id
        || bond_summary.payment_edge_id.as_deref() != Some(payment_summary.edge_id.as_str())
        || canonical_bytes(&kernel::Terms::work_stake_bond(payment.bond_terms.clone()))
            != bond_opening.canonical_terms
        || detail.admission != admission_at(height, &terms)
    {
        return Err(ProjectionError::Binding);
    }
    if detail.bond_state
        != if bond_summary.lifecycle == "open" {
            "live"
        } else {
            "consumed"
        }
    {
        return Err(ProjectionError::Binding);
    }
    let slots = kernel::bond_lease_slots(network, bond_id);
    if detail.lease_slots.len() != slots.len() {
        return Err(ProjectionError::Binding);
    }
    let mut chunks = [None; kernel::BOND_LEASE_CHUNKS as usize];
    for ((slot, expected), chunk) in detail.lease_slots.iter().zip(slots).zip(chunks.iter_mut()) {
        if slot.object_id != hex::encode(expected.as_bytes()) {
            return Err(ProjectionError::Binding);
        }
        *chunk = slot
            .chunk
            .as_ref()
            .map(|b| decode_canonical::<kernel::RegistryChunk>(b))
            .transpose()?;
    }
    if detail.lease.as_ref() != Some(&lease_projection(chunks, bond_id, payment_id, &terms)) {
        return Err(ProjectionError::Binding);
    }
    if pending_slot.object_id
        != hex::encode(kernel::pending_payment_close_slot(network, payment_id).as_bytes())
    {
        return Err(ProjectionError::Binding);
    }
    let pending = pending_slot
        .chunk
        .as_ref()
        .map(|b| decode_canonical::<kernel::RegistryChunk>(b))
        .transpose()?;
    if detail.pending.as_ref() != Some(&pending_projection(pending, payment_id)) {
        return Err(ProjectionError::Binding);
    }
    if detail.funding_query.len() > kernel::MAX_EDGE_INPUTS * 2
        || !detail.funding_query.windows(2).all(|v| v[0] < v[1])
        || !detail.live_funding.windows(2).all(|v| v[0] < v[1])
    {
        return Err(ProjectionError::Binding);
    }
    for id in &detail.funding_query {
        validate_id(id).map_err(|e| ProjectionError::Malformed(e.into()))?;
    }
    if detail
        .live_funding
        .iter()
        .any(|id| detail.funding_query.binary_search(id).is_err())
    {
        return Err(ProjectionError::Binding);
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum ProjectionError {
    #[error("malformed canonical data: {0}")]
    Malformed(String),
    #[error("unsupported terms projection")]
    Unsupported,
    #[error("edge ID does not match its retained opening")]
    Binding,
}
pub(crate) fn canonical_bytes<T: Encode>(value: &T) -> Vec<u8> {
    let mut bytes = vec![0; value.encoded_size()];
    value.write_to(&mut bytes);
    bytes
}
pub(crate) fn decode_canonical<T: Decode + Encode>(bytes: &[u8]) -> Result<T, ProjectionError> {
    let (value, consumed) =
        T::decode(bytes).map_err(|e| ProjectionError::Malformed(format!("{e:?}")))?;
    if consumed != bytes.len() || canonical_bytes(&value) != bytes {
        return Err(ProjectionError::Malformed(
            "noncanonical or trailing bytes".into(),
        ));
    }
    Ok(value)
}
pub(crate) fn close_kinds(kinds: kernel::CloseKindSet) -> Vec<String> {
    kernel::CloseKind::ALL
        .into_iter()
        .filter(|kind| kinds.contains(*kind))
        .map(|kind| {
            match kind {
                kernel::CloseKind::Mutual => "mutual",
                kernel::CloseKind::Timeout => "timeout",
                kernel::CloseKind::Freeze => "freeze",
                kernel::CloseKind::Adjudicated => "adjudicated",
            }
            .to_owned()
        })
        .collect()
}
pub(crate) fn edge_projection(edge: &kernel::Edge) -> EdgeProjection {
    let fees = edge.close_fees();
    EdgeProjection {
        value: edge.value(),
        reserve: edge.reserve(),
        close_fees: Some(CloseFees {
            base: fees.base(),
            slot: fees.slot(),
            proof: fees.proof(),
            lifetime: fees.lifetime(),
        }),
        timeout: edge.timeout().get(),
        maker: edge.parties().maker().as_bytes().to_vec(),
        taker: edge.parties().taker().as_bytes().to_vec(),
        terms_hash: hex::encode(edge.terms().as_bytes()),
        allowed_close_kinds: close_kinds(edge.allowed_closes()),
    }
}
#[cfg(feature = "indexer-api")]
pub(crate) fn object_answer(edge: Option<&kernel::Edge>) -> ObjectAnswer {
    ObjectAnswer {
        answer: Some(match edge {
            Some(edge) => ObjectState::Present(PresentEdge {
                canonical: canonical_bytes(edge),
                decoded: Some(edge_projection(edge)),
                provenance: "indexer-reported".into(),
            }),
            None => ObjectState::Absent(AbsentObject {
                provenance: "indexer-reported".into(),
            }),
        }),
    }
}
fn payouts(values: &[kernel::Payout]) -> Vec<PublicPayout> {
    values
        .iter()
        .map(|v| PublicPayout {
            owner: v.owner().as_bytes().to_vec(),
            value: v.value(),
        })
        .collect()
}
fn bond_terms(bond: &kernel::WorkStakeBondTerms) -> WorkStakeBondTerms {
    WorkStakeBondTerms {
        maker: bond.parties.maker().as_bytes().to_vec(),
        taker: bond.parties.taker().as_bytes().to_vec(),
        timeout: bond.timeout.get(),
        timeout_payouts: payouts(bond.timeout_outputs.as_slice()),
        max_job_price: bond.max_job_price,
    }
}
pub(crate) fn public_terms(terms: &kernel::Terms) -> Result<PublicTerms, ProjectionError> {
    let projection = match terms.profile() {
        TermsProfile::Basic => {
            let protocol = terms.basic_protocol().ok_or(ProjectionError::Unsupported)?;
            TermsKind::Basic(BasicTerms {
                protocol: u32::from(protocol.get()),
                maker: terms.parties().maker().as_bytes().to_vec(),
                taker: terms.parties().taker().as_bytes().to_vec(),
                timeout: terms.timeout().get(),
                timeout_payouts: payouts(
                    terms
                        .timeout_outputs()
                        .ok_or(ProjectionError::Unsupported)?
                        .as_slice(),
                ),
            })
        }
        TermsProfile::WorkStakeBond(bond) => TermsKind::WorkStakeBond(bond_terms(bond)),
        TermsProfile::WorkPayment(payment) => TermsKind::WorkPayment(WorkPaymentTerms {
            bond_edge_id: hex::encode(payment.bond_edge.as_bytes()),
            canonical_bond_terms: canonical_bytes(&kernel::Terms::work_stake_bond(
                payment.bond_terms.clone(),
            )),
            bond_terms: Some(bond_terms(&payment.bond_terms)),
            bond_terms_hash: hex::encode(payment.bond_terms_hash().as_bytes()),
            maker: payment.parties().maker().as_bytes().to_vec(),
            taker: payment.parties().taker().as_bytes().to_vec(),
            admission_horizon: payment.admission_horizon().get(),
            private_policy_commitment: hex::encode(payment.private_policy_commitment),
            omission_bond: payment.omission_bond,
            omit_response_blocks: payment.omit_response_blocks,
            start_validity_blocks: payment.start_validity_blocks,
            allowed_close_kinds: close_kinds(terms.allowed_closes()),
        }),
    };
    Ok(PublicTerms {
        terms: Some(projection),
    })
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn summary_from_open(
    edge_id: &str,
    opened: &TransactionRef,
    closed: Option<&TransactionRef>,
    funding: &kernel::Funding,
    terms: &kernel::Terms,
    payment_edge_id: Option<&str>,
    payload: &str,
) -> Result<EdgeSummary, ProjectionError> {
    for id in [
        edge_id,
        payload,
        &opened.payload,
        &opened.transaction_digest,
    ] {
        validate_id(id).map_err(|e| ProjectionError::Malformed(e.into()))?;
    }
    if hex::encode(kernel::Tx::edge_id_of(funding, terms).as_bytes()) != edge_id {
        return Err(ProjectionError::Binding);
    }
    let (kind, bond_edge_id) = match terms.profile() {
        TermsProfile::Basic => ("basic", None),
        TermsProfile::WorkStakeBond(_) => ("work-stake-bond", None),
        TermsProfile::WorkPayment(payment) => (
            "work-payment",
            Some(hex::encode(payment.bond_edge.as_bytes())),
        ),
    };
    let maker = terms.parties().maker().as_bytes().to_vec();
    let taker = terms.parties().taker().as_bytes().to_vec();
    Ok(EdgeSummary {
        edge_id: edge_id.into(),
        kind: kind.into(),
        maker: maker.clone(),
        taker: taker.clone(),
        opened: Some(opened.clone()),
        closed: closed.cloned(),
        lifecycle: if closed.is_some() { "closed" } else { "open" }.into(),
        terms_hash: hex::encode(terms.hash().as_bytes()),
        bond_edge_id,
        payment_edge_id: payment_edge_id.map(str::to_owned),
    })
}
pub(crate) fn opening_projection(
    transaction: TransactionRef,
    funding: &kernel::Funding,
    terms: &kernel::Terms,
) -> Result<Opening, ProjectionError> {
    Ok(Opening {
        transaction: Some(transaction),
        funding_maker: funding
            .maker()
            .as_slice()
            .iter()
            .map(|id| hex::encode(id.as_bytes()))
            .collect(),
        funding_taker: funding
            .taker()
            .as_slice()
            .iter()
            .map(|id| hex::encode(id.as_bytes()))
            .collect(),
        canonical_terms: canonical_bytes(terms),
        terms: Some(public_terms(terms)?),
    })
}
/// The shared lease contract admits only strictly before the horizon.
pub(crate) fn admission_at(height: u64, terms: &kernel::Terms) -> &'static str {
    match terms.profile() {
        TermsProfile::WorkPayment(payment) if height < payment.admission_horizon().get() => {
            "before_horizon"
        }
        TermsProfile::WorkPayment(_) => "ended",
        _ => "not_applicable",
    }
}
pub(crate) fn lease_projection(
    slots: [Option<kernel::RegistryChunk>; kernel::BOND_LEASE_CHUNKS as usize],
    bond_edge: kernel::EdgeId,
    payment_edge: kernel::EdgeId,
    payment_terms: &kernel::Terms,
) -> LeaseAnswer {
    let state = match kernel::parse_bond_lease(slots, bond_edge) {
        kernel::LeaseSlots::Absent => LeaseState::Absent(ParserAbsent {}),
        kernel::LeaseSlots::Faulty(fault) => LeaseState::Invalid(ParserInvalid {
            reason: format!("{fault:?}"),
        }),
        kernel::LeaseSlots::Present(lease) => {
            let bound = match payment_terms.profile() {
                TermsProfile::WorkPayment(payment) => {
                    lease.payment_edge() == payment_edge
                        && payment.bond_edge == bond_edge
                        && lease.payment_terms_hash() == payment_terms.hash()
                        && lease.private_policy_commitment() == payment.private_policy_commitment
                        && lease.admission_horizon() == payment.admission_horizon().get()
                }
                _ => false,
            };
            if !bound {
                LeaseState::Invalid(ParserInvalid {
                    reason: "lease belongs to another channel or terms".into(),
                })
            } else {
                LeaseState::Present(LeaseProjection {
                    bond_edge_id: hex::encode(lease.bond_edge().as_bytes()),
                    payment_edge_id: hex::encode(lease.payment_edge().as_bytes()),
                    payment_terms_hash: hex::encode(lease.payment_terms_hash().as_bytes()),
                    private_policy_commitment: hex::encode(lease.private_policy_commitment()),
                    admission_horizon: lease.admission_horizon(),
                })
            }
        }
    };
    LeaseAnswer {
        answer: Some(state),
    }
}
pub(crate) fn pending_projection(
    chunk: Option<kernel::RegistryChunk>,
    payment_edge: kernel::EdgeId,
) -> PendingAnswer {
    let state = match kernel::parse_pending_close(chunk, payment_edge) {
        kernel::PendingSlot::Absent => PendingState::Absent(ParserAbsent {}),
        kernel::PendingSlot::Faulty(fault) => PendingState::Invalid(ParserInvalid {
            reason: format!("{fault:?}"),
        }),
        kernel::PendingSlot::Present(pending) => PendingState::Present(PendingProjection {
            payment_edge_id: hex::encode(pending.payment_edge().as_bytes()),
            opener_role: match pending.opener_role() {
                kernel::Party::Maker => "maker",
                kernel::Party::Taker => "taker",
            }
            .into(),
            start_id: hex::encode(pending.start_id().to_bytes()),
            response_deadline: pending.response_deadline(),
            start_cumulative: pending.start_cumulative(),
            final_cumulative: pending.final_cumulative(),
            responded: pending.responded(),
            penalty_due: pending.penalty_due(),
            penalty_amount: pending.penalty_amount(),
        }),
    };
    PendingAnswer {
        answer: Some(state),
    }
}
