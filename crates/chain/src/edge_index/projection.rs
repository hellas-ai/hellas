//! Canonical kernel-to-public projections; no persistence or state lookup occurs here.
use super::types::*;
use hellas_kernel::{self as kernel, Decode, Encode, TermsProfile};

/// Evidence-checking facade shared by native and Wasm consumers. The returned values
/// remain reported EdgeIndex models, never authenticated light-client object types.
pub struct EdgeIndexClient {
    verifier: crate::verified_explorer::ExplorerVerifier,
    genesis_sha256: String,
    network: kernel::NetworkId,
}
impl EdgeIndexClient {
    /// Checks reported event bytes and ordering; linked evidence must be fetched separately
    /// before calling any individual event consensus-included.
    pub fn check_events(
        &self,
        response: &ListEdgeEventsResponse,
        expected_edge_id: &str,
    ) -> Result<(), ProjectionError> {
        use commonware_codec::{DecodeExt as _, Encode as _};
        self.check_envelope(&response.envelope)?;
        validate_id(expected_edge_id).map_err(|e| ProjectionError::Malformed(e.into()))?;
        if response.data.items.len() > 64
            || !response.data.items.windows(2).all(|v| {
                (v[0].transaction.height, v[0].transaction.transaction_index)
                    < (v[1].transaction.height, v[1].transaction.transaction_index)
            })
        {
            return Err(ProjectionError::Binding);
        }
        for event in &response.data.items {
            if event.transaction.height > response.envelope.snapshot.height {
                return Err(ProjectionError::Binding);
            }
            validate_id(&event.transaction.payload)
                .map_err(|e| ProjectionError::Malformed(e.into()))?;
            let tx = crate::domain::Transaction::decode(event.canonical_transaction.as_slice())
                .map_err(|e| ProjectionError::Malformed(e.to_string()))?;
            if tx.encode().as_ref() != event.canonical_transaction
                || crate::verified_explorer::transaction_digest(&tx)
                    != digest(&event.transaction.transaction_digest)?
            {
                return Err(ProjectionError::Binding);
            }
            let (id, kind) = match tx {
                crate::domain::Transaction::Kernel(kernel::Tx::Open { funding, terms, .. }) => {
                    (kernel::Tx::edge_id_of(&funding, &terms), "open")
                }
                crate::domain::Transaction::Kernel(kernel::Tx::Close { input, .. }) => {
                    (input, "close")
                }
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

    pub fn with_genesis(
        trust: hellas_genesis::TrustDocument,
        genesis_json: &[u8],
    ) -> Result<Self, ProjectionError> {
        let network = kernel::NetworkId::new(&trust.network_id).ok_or(ProjectionError::Binding)?;
        let genesis_sha256 = trust.genesis_sha256.clone();
        let verifier =
            crate::verified_explorer::ExplorerVerifier::with_genesis(trust, genesis_json)
                .map_err(|e| ProjectionError::Malformed(e.to_string()))?;
        Ok(Self {
            verifier,
            genesis_sha256,
            network,
        })
    }
    pub fn check_envelope(&self, envelope: &EdgeIndexMetadata) -> Result<(), ProjectionError> {
        envelope
            .validate()
            .map_err(|e| ProjectionError::Malformed(e.into()))?;
        if envelope.genesis_sha256 != self.genesis_sha256
            || envelope.network_id != self.network.as_str()
        {
            return Err(ProjectionError::Binding);
        }
        for proof in std::iter::once(&envelope.snapshot.block_proof).chain(&envelope.evidence) {
            self.check_proof(proof)?;
        }
        Ok(())
    }
    fn check_proof(
        &self,
        proof: &crate::verified_explorer::ProofBundle,
    ) -> Result<(), ProjectionError> {
        self.verifier
            .verify(
                proof.clone(),
                crate::verified_explorer::ExplorerQuery::Block(
                    crate::FinalizedBlockQuery::Payload(digest(&proof.payload)?),
                ),
            )
            .map_err(|e| ProjectionError::Malformed(e.to_string()))?;
        Ok(())
    }
    pub fn check_edge(&self, response: &GetEdgeDetailResponse) -> Result<(), ProjectionError> {
        self.check_envelope(&response.envelope)?;
        check_detail(&response.data, &response.envelope)
    }
    pub fn check_channel(
        &self,
        response: &GetWorkChannelDetailResponse,
    ) -> Result<(), ProjectionError> {
        self.check_envelope(&response.envelope)?;
        check_work_channel(&response.data, self.network, &response.envelope)
    }
    pub fn check_list(&self, response: &ListEdgesResponse) -> Result<(), ProjectionError> {
        self.check_envelope(&response.envelope)?;
        if response.data.items.len() > 64
            || !response
                .data
                .items
                .windows(2)
                .all(|v| v[0].edge_id < v[1].edge_id)
        {
            return Err(ProjectionError::Binding);
        }
        for summary in &response.data.items {
            for id in [
                &summary.edge_id,
                &summary.terms_hash,
                &summary.opened.payload,
                &summary.opened.transaction_digest,
            ] {
                validate_id(id).map_err(|e| ProjectionError::Malformed(e.into()))?;
            }
            if summary.opened.height > response.envelope.snapshot.height
                || summary.maker.len() != kernel::Key::LENGTH
                || summary.taker.len() != kernel::Key::LENGTH
                || !matches!(
                    summary.kind.as_str(),
                    "basic" | "work-payment" | "work-stake-bond"
                )
                || !matches!(
                    (&summary.closed, summary.lifecycle.as_str()),
                    (Some(_), "closed") | (None, "open")
                )
            {
                return Err(ProjectionError::Binding);
            }
            if summary
                .closed
                .as_ref()
                .is_some_and(|c| c.height > response.envelope.snapshot.height)
            {
                return Err(ProjectionError::Binding);
            }
        }
        Ok(())
    }
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
            summary
                .links
                .edge
                .ends_with(&format!("?payload={}", "ef".repeat(32)))
        );
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
fn referenced_transaction(
    reference: &TransactionRef,
    proof: &crate::verified_explorer::ProofBundle,
) -> Result<crate::domain::Transaction, ProjectionError> {
    if reference.height != proof.height || reference.payload != proof.payload {
        return Err(ProjectionError::Binding);
    }
    let block = crate::FinalizedBlock {
        snapshot: crate::LatestBlock {
            height: proof.height,
            payload: digest(&proof.payload)?,
            state_root: digest(&proof.state_root)?,
            finalization: proof.finalization.clone(),
        },
        block: proof.canonical_block.clone(),
    };
    let view = crate::FinalizedBlockView::decode(&block)
        .map_err(|e| ProjectionError::Malformed(e.to_string()))?;
    let tx = view
        .txs()
        .get(reference.transaction_index as usize)
        .ok_or(ProjectionError::Binding)?;
    if crate::verified_explorer::transaction_digest(tx) != digest(&reference.transaction_digest)? {
        return Err(ProjectionError::Binding);
    }
    Ok(tx.clone())
}
/// Checks public projections against their canonical evidence. Does not verify consensus
/// signatures, current-state membership, global discovery, or completeness.
pub fn check_detail(
    detail: &EdgeDetail,
    envelope: &EdgeIndexMetadata,
) -> Result<(), ProjectionError> {
    let opening = &detail.opening;
    if opening.transaction != detail.summary.opened
        || opening.transaction.height > envelope.snapshot.height
        || detail
            .closing
            .as_ref()
            .is_some_and(|c| c.transaction.height > envelope.snapshot.height)
    {
        return Err(ProjectionError::Binding);
    }
    let tx = referenced_transaction(
        &opening.transaction,
        envelope
            .proof(&opening.transaction.payload)
            .map_err(|_| ProjectionError::Binding)?,
    )?;
    let crate::domain::Transaction::Kernel(kernel::Tx::Open { funding, terms, .. }) = tx else {
        return Err(ProjectionError::Binding);
    };
    let expected_opening = opening_projection(opening.transaction.clone(), &funding, &terms)?;
    if &expected_opening != opening {
        return Err(ProjectionError::Binding);
    }
    let edge_id = hex::encode(kernel::Tx::edge_id_of(&funding, &terms).as_bytes());
    if detail.summary.edge_id != edge_id
        || detail.summary.terms_hash != hex::encode(terms.hash().as_bytes())
        || detail.summary.maker != terms.parties().maker().as_bytes()
        || detail.summary.taker != terms.parties().taker().as_bytes()
    {
        return Err(ProjectionError::Binding);
    }
    let (kind, bond) = match terms.profile() {
        TermsProfile::Basic => ("basic", None),
        TermsProfile::WorkStakeBond(_) => ("work-stake-bond", None),
        TermsProfile::WorkPayment(payment) => (
            "work-payment",
            Some(hex::encode(payment.bond_edge.as_bytes())),
        ),
    };
    if detail.summary.kind != kind
        || detail.summary.bond_edge_id != bond
        || detail.related.bond_edge_id != bond
        || detail.related.payment_edge_id != detail.summary.payment_edge_id
    {
        return Err(ProjectionError::Binding);
    }
    if let Some(id) = &detail.related.payment_edge_id {
        validate_id(id).map_err(|e| ProjectionError::Malformed(e.into()))?;
    }
    match (&detail.closing, &detail.summary.closed) {
        (None, None) if detail.summary.lifecycle == "open" => {}
        (Some(closing), Some(reference)) if detail.summary.lifecycle == "closed" => {
            if &closing.transaction != reference
                || (reference.height, reference.transaction_index)
                    <= (
                        opening.transaction.height,
                        opening.transaction.transaction_index,
                    )
            {
                return Err(ProjectionError::Binding);
            }
            let close = referenced_transaction(
                reference,
                envelope
                    .proof(&reference.payload)
                    .map_err(|_| ProjectionError::Binding)?,
            )?;
            match close {
                crate::domain::Transaction::Kernel(kernel::Tx::Close { input, .. })
                    if hex::encode(input.as_bytes()) == edge_id => {}
                _ => return Err(ProjectionError::Binding),
            }
        }
        _ => return Err(ProjectionError::Binding),
    }
    match &detail.object_at_snapshot.answer {
        Some(ObjectState::Present(present)) => {
            if present.provenance != "indexer-reported" || detail.summary.lifecycle != "open" {
                return Err(ProjectionError::Binding);
            }
            let edge: kernel::Edge = decode_canonical(&present.canonical)?;
            if edge_projection(&edge) != present.decoded
                || edge.parties() != terms.parties()
                || edge.terms() != terms.hash()
                || edge.timeout() != terms.timeout()
                || edge.allowed_closes() != terms.allowed_closes()
            {
                return Err(ProjectionError::Binding);
            }
        }
        Some(ObjectState::Absent(absent))
            if absent.provenance == "indexer-reported" && detail.summary.lifecycle == "closed" => {}
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
) -> Result<(), ProjectionError> {
    let height = envelope.snapshot.height;
    check_detail(&detail.payment, envelope)?;
    check_detail(&detail.bond, envelope)?;
    let payment_id = edge_id(&detail.payment.summary.edge_id)?;
    let bond_id = edge_id(&detail.bond.summary.edge_id)?;
    let terms: kernel::Terms = decode_canonical(&detail.payment.opening.canonical_terms)?;
    let TermsProfile::WorkPayment(payment) = terms.profile() else {
        return Err(ProjectionError::Binding);
    };
    if payment.bond_edge != bond_id
        || canonical_bytes(&kernel::Terms::work_stake_bond(payment.bond_terms.clone()))
            != detail.bond.opening.canonical_terms
        || detail.admission != admission_at(height, &terms)
    {
        return Err(ProjectionError::Binding);
    }
    if detail.bond_state
        != if detail.bond.summary.lifecycle == "open" {
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
    if detail.lease != lease_projection(chunks, bond_id, payment_id, &terms) {
        return Err(ProjectionError::Binding);
    }
    if detail.pending_slot.object_id
        != hex::encode(kernel::pending_payment_close_slot(network, payment_id).as_bytes())
    {
        return Err(ProjectionError::Binding);
    }
    let pending = detail
        .pending_slot
        .chunk
        .as_ref()
        .map(|b| decode_canonical::<kernel::RegistryChunk>(b))
        .transpose()?;
    if detail.pending != pending_projection(pending, payment_id) {
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
    for edge in [&detail.payment, &detail.bond] {
        if edge.summary.opened.height > height
            || edge
                .summary
                .closed
                .as_ref()
                .is_some_and(|c| c.height > height)
        {
            return Err(ProjectionError::Binding);
        }
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
pub fn canonical_bytes<T: Encode>(value: &T) -> Vec<u8> {
    let mut bytes = vec![0; value.encoded_size()];
    value.write_to(&mut bytes);
    bytes
}
pub fn decode_canonical<T: Decode + Encode>(bytes: &[u8]) -> Result<T, ProjectionError> {
    let (value, consumed) =
        T::decode(bytes).map_err(|e| ProjectionError::Malformed(format!("{e:?}")))?;
    if consumed != bytes.len() || canonical_bytes(&value) != bytes {
        return Err(ProjectionError::Malformed(
            "noncanonical or trailing bytes".into(),
        ));
    }
    Ok(value)
}
pub fn close_kinds(kinds: kernel::CloseKindSet) -> Vec<String> {
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
pub fn edge_projection(edge: &kernel::Edge) -> EdgeProjection {
    let fees = edge.close_fees();
    EdgeProjection {
        value: edge.value(),
        reserve: edge.reserve(),
        close_fees: CloseFees {
            base: fees.base(),
            slot: fees.slot(),
            proof: fees.proof(),
            lifetime: fees.lifetime(),
        },
        timeout: edge.timeout().get(),
        maker: edge.parties().maker().as_bytes().to_vec(),
        taker: edge.parties().taker().as_bytes().to_vec(),
        terms_hash: hex::encode(edge.terms().as_bytes()),
        allowed_close_kinds: close_kinds(edge.allowed_closes()),
    }
}
pub fn object_answer(edge: Option<&kernel::Edge>) -> ObjectAnswer {
    ObjectAnswer {
        answer: Some(match edge {
            Some(edge) => ObjectState::Present(PresentEdge {
                canonical: canonical_bytes(edge),
                decoded: edge_projection(edge),
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
pub fn public_terms(terms: &kernel::Terms) -> Result<PublicTerms, ProjectionError> {
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
            bond_terms: bond_terms(&payment.bond_terms),
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
pub fn summary_from_open(
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
    let channel_id = if kind == "work-payment" {
        Some(edge_id)
    } else {
        payment_edge_id
    };
    Ok(EdgeSummary {
        edge_id: edge_id.into(),
        kind: kind.into(),
        maker: maker.clone(),
        taker: taker.clone(),
        opened: opened.clone(),
        closed: closed.cloned(),
        lifecycle: if closed.is_some() { "closed" } else { "open" }.into(),
        terms_hash: hex::encode(terms.hash().as_bytes()),
        bond_edge_id,
        payment_edge_id: payment_edge_id.map(str::to_owned),
        links: EdgeLinks {
            edge: format!("/edges/{edge_id}?payload={payload}"),
            channel: channel_id.map(|id| format!("/channels/{id}?payload={payload}")),
            maker: format!(
                "/addresses/{}?payload={payload}",
                bs58::encode(maker).into_string()
            ),
            taker: format!(
                "/addresses/{}?payload={payload}",
                bs58::encode(taker).into_string()
            ),
            opening_transaction: format!("/transactions/{}", opened.transaction_digest),
            opening_block: format!("/blocks/{}", opened.payload),
            evidence: format!("/api/v1/edges/{edge_id}/evidence?payload={payload}"),
        },
    })
}
pub fn opening_projection(
    transaction: TransactionRef,
    funding: &kernel::Funding,
    terms: &kernel::Terms,
) -> Result<Opening, ProjectionError> {
    Ok(Opening {
        transaction,
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
        terms: public_terms(terms)?,
    })
}
/// The shared lease contract admits only strictly before the horizon.
pub fn admission_at(height: u64, terms: &kernel::Terms) -> &'static str {
    match terms.profile() {
        TermsProfile::WorkPayment(payment) if height < payment.admission_horizon().get() => {
            "before_horizon"
        }
        TermsProfile::WorkPayment(_) => "ended",
        _ => "not_applicable",
    }
}
pub fn lease_projection(
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
pub fn pending_projection(
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
