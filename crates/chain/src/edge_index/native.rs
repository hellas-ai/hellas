use super::query::{Cursor, Filters};
use super::{
    projection::*,
    store::{Identity, IndexStore, ReadSnapshot, SnapshotError, StoredEdge},
    types::*,
};
use crate::domain::{Object, Transaction};
use base64ct::{Base64UrlUnpadded, Encoding};
use commonware_codec::DecodeExt as _;
use hellas_kernel::{TermsProfile, Tx};
use serde::Serialize;
use std::{
    path::Path,
    time::{Duration, Instant},
};

#[derive(Debug, thiserror::Error)]
#[error("{code}: {message}")]
pub struct EdgeIndexError {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
    pub snapshot: Option<Box<EdgeIndexMetadata>>,
}
impl EdgeIndexError {
    fn bad(message: impl ToString) -> Self {
        Self {
            status: 400,
            code: "invalid_request",
            message: message.to_string(),
            snapshot: None,
        }
    }
    fn unavailable(message: impl ToString) -> Self {
        Self {
            status: 503,
            code: "index_not_ready",
            message: message.to_string(),
            snapshot: None,
        }
    }
}
type Result<T> = std::result::Result<T, EdgeIndexError>;
fn storage(error: impl std::fmt::Display) -> EdgeIndexError {
    EdgeIndexError::unavailable(error)
}
#[derive(Clone)]
pub struct EdgeIndex {
    pub(super) store: IndexStore,
    pub(super) permits: std::sync::Arc<tokio::sync::Semaphore>,
}
impl EdgeIndex {
    pub fn open(
        path: &Path,
        network_id: String,
        genesis_sha256: String,
        trust_sha256: String,
    ) -> Result<Self> {
        validate_id(&genesis_sha256).map_err(EdgeIndexError::bad)?;
        validate_id(&trust_sha256).map_err(EdgeIndexError::bad)?;
        Ok(Self {
            store: IndexStore::open(
                path,
                Identity {
                    network_id,
                    genesis_sha256,
                    trust_sha256,
                    schema_version: SCHEMA_VERSION,
                },
            )
            .map_err(storage)?,
            permits: std::sync::Arc::new(tokio::sync::Semaphore::new(16)),
        })
    }
    pub(crate) fn transaction_height(&self, digest: &str) -> Result<Option<u64>> {
        self.store.transaction_height(digest).map_err(storage)
    }
    fn scope(&self) -> String {
        let i = &self.store.identity;
        super::query::cursor_scope(&i.network_id, &i.genesis_sha256, &i.trust_sha256)
    }
    fn cursor(&self, raw: &str) -> Result<Cursor> {
        let identity = &self.store.identity;
        let value = super::query::decode_cursor(
            raw,
            &identity.network_id,
            &identity.genesis_sha256,
            &identity.trust_sha256,
        )
        .map_err(EdgeIndexError::bad)?;
        Ok(value)
    }
    fn encode_cursor(&self, value: Cursor) -> Result<String> {
        let bytes = serde_json::to_vec(&value).map_err(storage)?;
        if bytes.len() > 512 {
            return Err(EdgeIndexError::unavailable(
                "cursor exceeds supported bound",
            ));
        }
        Ok(Base64UrlUnpadded::encode_string(&bytes))
    }
    fn snapshot(&self, payload: Option<&str>) -> Result<ReadSnapshot> {
        if let Some(payload) = payload {
            validate_id(payload).map_err(EdgeIndexError::bad)?;
        }
        self.store.read(payload).map_err(|error| {
            if let Some(kind) = error.downcast_ref::<SnapshotError>() {
                let (status, code) = match kind {
                    SnapshotError::Expired => (410, "snapshot_expired"),
                    SnapshotError::Unavailable => (409, "snapshot_unavailable"),
                    SnapshotError::NotReady => (503, "index_not_ready"),
                };
                EdgeIndexError {
                    status,
                    code,
                    message: error.to_string(),
                    snapshot: self
                        .store
                        .read(None)
                        .ok()
                        .map(|read| Box::new(self.metadata(&read))),
                }
            } else {
                storage(error)
            }
        })
    }
    fn metadata(&self, read: &ReadSnapshot) -> EdgeIndexMetadata {
        EdgeIndexMetadata {
            schema_version: SCHEMA_VERSION,
            network_id: self.store.identity.network_id.clone(),
            genesis_sha256: self.store.identity.genesis_sha256.clone(),
            trust_sha256: self.store.identity.trust_sha256.clone(),
            snapshot: Snapshot {
                height: read.proof.height,
                payload: read.proof.payload.clone(),
                state_root: read.proof.state_root.clone(),
                block_proof: read.proof.clone(),
            },
            index: IndexCoverage {
                schema_version: SCHEMA_VERSION,
                indexed_from_height: 0,
                indexed_through_height: read.proof.height,
                indexed_through_payload: read.proof.payload.clone(),
                complete_through_snapshot: true,
                observed_head: Some(ObservedHead {
                    height: read.indexed_through.height,
                    payload: read.indexed_through.payload.clone(),
                }),
                observed_at_ms: read.proof.observed_at_ms,
                retained_from_height: read.retained_from_height,
            },
            provenance: Provenance::reported(),
        }
    }
    pub fn list_edges(&self, mut request: ListEdgesRequest) -> Result<ListEdgesResponse> {
        request = super::query::normalize_list_request(
            request,
            &self.store.identity.network_id,
            &self.store.identity.genesis_sha256,
            &self.store.identity.trust_sha256,
        )
        .map_err(EdgeIndexError::bad)?;
        let cursor = request
            .cursor
            .as_deref()
            .map(|value| self.cursor(value))
            .transpose()?;
        request.validate().map_err(EdgeIndexError::bad)?;
        let read = self.snapshot(request.payload.as_deref())?;
        let filters = Filters {
            s: request.state.unwrap_or_else(|| "open".into()),
            k: request.kind,
            p: request
                .party
                .as_ref()
                .map(|v| bs58::encode(v).into_string()),
            r: request.role.unwrap_or_else(|| "any".into()),
        };
        let limit = validate_limit(request.limit).map_err(EdgeIndexError::bad)? as usize;
        let prefix = if let Some(party) = &filters.p {
            format!(
                "{}/{party}/",
                match filters.r.as_str() {
                    "maker" => "m",
                    "taker" => "t",
                    _ => "p",
                }
            )
        } else if let Some(kind) = &filters.k {
            format!("k/{kind}/")
        } else {
            "a/".into()
        };
        let mut items = Vec::new();
        let started = Instant::now();
        let prefix = format!("{}/{prefix}", filters.s);
        read.scan_edges(&prefix, cursor.as_ref().map(|v| v.a.as_str()), |edge| {
            if started.elapsed() > Duration::from_millis(250) {
                return Err("query deadline exceeded".into());
            }
            let summary = self
                .summary(&read, &edge)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            if filters.s != "all" && filters.s != summary.lifecycle
                || filters.k.as_ref().is_some_and(|kind| kind != &summary.kind)
            {
                return Ok(true);
            }
            items.push(summary);
            Ok(items.len() <= limit)
        })
        .map_err(storage)?;
        let next_cursor = if items.len() > limit {
            items.pop();
            Some(self.encode_cursor(Cursor {
                v: SCHEMA_VERSION,
                s: self.scope(),
                p: read.proof.payload.clone(),
                f: filters,
                a: items.last().expect("nonempty page").edge_id.clone(),
                e: None,
                h: None,
                t: None,
            })?)
        } else {
            None
        };
        bounded(ListEdgesResponse {
            envelope: self.metadata(&read),
            data: ListEdgesPage { items, next_cursor },
        })
    }
    fn summary(&self, read: &ReadSnapshot, edge: &StoredEdge) -> Result<EdgeSummary> {
        let tx = Transaction::decode(edge.canonical_open.as_slice()).map_err(storage)?;
        let Transaction::Kernel(Tx::Open { funding, terms, .. }) = tx else {
            return Err(EdgeIndexError::unavailable("stored opening is not Open"));
        };
        summary_from_open(
            &edge.edge_id,
            &edge.opened,
            edge.closed.as_ref(),
            &funding,
            &terms,
            edge.payment_edge_id.as_deref(),
            &read.proof.payload,
        )
        .map_err(storage)
    }
    fn detail(&self, read: &ReadSnapshot, id: &str) -> Result<EdgeDetail> {
        let edge = read
            .edge(id)
            .map_err(storage)?
            .ok_or_else(|| EdgeIndexError {
                status: 404,
                code: "edge_not_found",
                message: "edge is absent from indexed history at this snapshot".into(),
                snapshot: Some(Box::new(self.metadata(read))),
            })?;
        let summary = self.summary(read, &edge)?;
        let tx = Transaction::decode(edge.canonical_open.as_slice()).map_err(storage)?;
        let Transaction::Kernel(Tx::Open { funding, terms, .. }) = tx else {
            return Err(EdgeIndexError::unavailable("stored opening is not Open"));
        };
        let object = read
            .object(&hex::decode(id).map_err(EdgeIndexError::bad)?)
            .map_err(storage)?;
        let object = match object {
            Some(Object::Edge(edge)) => Some(edge),
            None => None,
            _ => return Err(EdgeIndexError::unavailable("wrong object kind at edge id")),
        };
        if object.is_some() != edge.closed.is_none() {
            return Err(EdgeIndexError::unavailable(
                "edge history/object state mismatch",
            ));
        }
        let closing = edge
            .closed
            .as_ref()
            .map(|closed| {
                Ok(Closing {
                    transaction: closed.clone(),
                    proof: read.proof(closed.height).map_err(storage)?,
                })
            })
            .transpose()?;
        let related = RelatedEdges {
            bond_edge_id: summary.bond_edge_id.clone(),
            payment_edge_id: summary.payment_edge_id.clone(),
        };
        Ok(EdgeDetail {
            summary,
            object_at_snapshot: object_answer(object.as_ref()),
            opening: Opening {
                transaction: edge.opened.clone(),
                proof: read.proof(edge.opened.height).map_err(storage)?,
                funding_maker: funding
                    .maker()
                    .iter()
                    .map(|id| hex::encode(id.as_bytes()))
                    .collect(),
                funding_taker: funding
                    .taker()
                    .iter()
                    .map(|id| hex::encode(id.as_bytes()))
                    .collect(),
                canonical_terms: canonical(&terms),
                terms: public_terms(&terms).map_err(storage)?,
            },
            closing,
            related,
            events: EventsLink {
                href: format!("/api/v1/edges/{id}/events?payload={}", read.proof.payload),
            },
        })
    }
    pub fn get_work_channel_detail(
        &self,
        request: GetWorkChannelDetailRequest,
    ) -> Result<GetWorkChannelDetailResponse> {
        validate_request(request.schema_version, &request.payment_edge_id)?;
        let read = self.snapshot(request.payload.as_deref())?;
        let payment = self.detail(&read, &request.payment_edge_id)?;
        let terms = decode_canonical::<hellas_kernel::Terms>(&payment.opening.canonical_terms)
            .map_err(storage)?;
        let TermsProfile::WorkPayment(work) = terms.profile() else {
            return Err(EdgeIndexError::bad("edge is not a work payment"));
        };
        let bond_id = hex::encode(work.bond_edge.as_bytes());
        let bond = self.detail(&read, &bond_id)?;
        if bond.summary.terms_hash != hex::encode(work.bond_terms_hash().as_bytes()) {
            return Err(EdgeIndexError::unavailable(
                "bond does not match payment terms",
            ));
        }
        let funding_query = match request.funding {
            Some(query) => {
                super::query::validate_funding(&query.coins).map_err(EdgeIndexError::bad)?;
                query.coins
            }
            None => payment
                .opening
                .funding_maker
                .iter()
                .chain(&payment.opening.funding_taker)
                .chain(&bond.opening.funding_maker)
                .chain(&bond.opening.funding_taker)
                .cloned()
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect(),
        };
        let mut live_funding = Vec::new();
        for id in &funding_query {
            match read
                .object(&hex::decode(id).map_err(EdgeIndexError::bad)?)
                .map_err(storage)?
            {
                Some(Object::Coin(_)) => live_funding.push(id.clone()),
                None => {}
                _ => {
                    return Err(EdgeIndexError::unavailable(
                        "wrong object kind for funding coin",
                    ));
                }
            }
        }
        let network = hellas_kernel::NetworkId::new(&self.store.identity.network_id)
            .ok_or_else(|| EdgeIndexError::unavailable("invalid network identity"))?;
        let payment_id = hellas_kernel::EdgeId::from_bytes(
            hex::decode(&request.payment_edge_id)
                .map_err(EdgeIndexError::bad)?
                .try_into()
                .map_err(|_| EdgeIndexError::bad("invalid edge id"))?,
        );
        let mut raw_slots = [None; hellas_kernel::BOND_LEASE_CHUNKS as usize];
        let mut lease_slots = Vec::new();
        for (index, id) in hellas_kernel::bond_lease_slots(network, work.bond_edge)
            .into_iter()
            .enumerate()
        {
            let object_id = crate::domain::registry_chunk_object_id(id);
            let chunk = registry_chunk(&read, object_id.as_ref())?;
            raw_slots[index] = chunk;
            lease_slots.push(RegistrySlot {
                object_id: hex::encode(object_id),
                chunk: chunk.as_ref().map(canonical_bytes),
            });
        }
        let pending_id = crate::domain::registry_chunk_object_id(
            hellas_kernel::pending_payment_close_slot(network, payment_id),
        );
        let raw_pending = registry_chunk(&read, pending_id.as_ref())?;
        let lease = lease_projection(raw_slots, work.bond_edge, payment_id, &terms);
        let pending = pending_projection(raw_pending, payment_id);
        let admission = admission_at(read.proof.height, &terms).into();
        let bond_state = if bond.summary.closed.is_some() {
            "consumed"
        } else {
            "live"
        }
        .into();
        let data = WorkChannelDetail {
            payment,
            bond,
            funding_query,
            live_funding,
            lease_slots,
            pending_slot: RegistrySlot {
                object_id: hex::encode(pending_id),
                chunk: raw_pending.as_ref().map(canonical_bytes),
            },
            lease,
            pending,
            admission,
            bond_state,
        };
        bounded(GetWorkChannelDetailResponse {
            envelope: self.metadata(&read),
            data,
        })
    }
    pub fn get_edge_detail(&self, request: GetEdgeDetailRequest) -> Result<GetEdgeDetailResponse> {
        validate_request(request.schema_version, &request.edge_id)?;
        let read = self.snapshot(request.payload.as_deref())?;
        bounded(GetEdgeDetailResponse {
            envelope: self.metadata(&read),
            data: self.detail(&read, &request.edge_id)?,
        })
    }
    pub fn list_edge_events(
        &self,
        request: ListEdgeEventsRequest,
    ) -> Result<ListEdgeEventsResponse> {
        let request = super::query::normalize_events_request(
            request,
            &self.store.identity.network_id,
            &self.store.identity.genesis_sha256,
            &self.store.identity.trust_sha256,
        )
        .map_err(EdgeIndexError::bad)?;
        validate_request(request.schema_version, &request.edge_id)?;
        let limit = validate_limit(request.limit).map_err(EdgeIndexError::bad)? as usize;
        let cursor = request
            .cursor
            .as_deref()
            .map(|value| self.cursor(value))
            .transpose()?;
        let read = self.snapshot(
            cursor
                .as_ref()
                .map(|v| v.p.as_str())
                .or(request.payload.as_deref()),
        )?;
        if cursor
            .as_ref()
            .and_then(|value| value.h)
            .is_some_and(|height| height > read.proof.height)
        {
            return Err(EdgeIndexError::bad(
                "event cursor position is after snapshot",
            ));
        }
        if read.edge(&request.edge_id).map_err(storage)?.is_none() {
            return Err(EdgeIndexError {
                status: 404,
                code: "edge_not_found",
                message: "edge not found".into(),
                snapshot: Some(Box::new(self.metadata(&read))),
            });
        }
        let mut events = read
            .events(
                &request.edge_id,
                cursor.as_ref().and_then(|v| v.h.zip(v.t)),
                limit + 1,
            )
            .map_err(storage)?;
        let next_cursor = if events.len() > limit {
            events.pop();
            let last = &events.last().unwrap().transaction;
            Some(self.encode_cursor(Cursor {
                v: SCHEMA_VERSION,
                s: self.scope(),
                p: read.proof.payload.clone(),
                f: Filters {
                    s: "all".into(),
                    k: None,
                    p: None,
                    r: "any".into(),
                },
                a: request.edge_id.clone(),
                e: Some(request.edge_id),
                h: Some(last.height),
                t: Some(last.transaction_index),
            })?)
        } else {
            None
        };
        let items = events
            .into_iter()
            .map(|event| EdgeEvent {
                kind: event.kind,
                evidence_href: format!(
                    "/api/v1/transactions/{}/proof",
                    event.transaction.transaction_digest
                ),
                transaction: event.transaction,
                canonical_transaction: event.canonical_transaction,
            })
            .collect();
        bounded(ListEdgeEventsResponse {
            envelope: self.metadata(&read),
            data: EdgeEventsPage { items, next_cursor },
        })
    }
}
fn validate_request(schema: u32, id: &str) -> Result<()> {
    if schema != SCHEMA_VERSION {
        return Err(EdgeIndexError::bad("unsupported schema version"));
    }
    validate_id(id).map_err(EdgeIndexError::bad)
}
fn canonical<T: hellas_kernel::Encode>(value: &T) -> Vec<u8> {
    let mut bytes = vec![0; value.encoded_size()];
    value.write_to(&mut bytes);
    bytes
}
fn bounded<T: Serialize + prost::Message>(value: T) -> Result<T> {
    if value.encoded_len() > MAX_RESPONSE_BYTES
        || serde_json::to_vec(&value).map_err(storage)?.len() > MAX_RESPONSE_BYTES
    {
        Err(EdgeIndexError {
            status: 413,
            code: "response_too_large",
            message: "response exceeds 8 MiB".into(),
            snapshot: None,
        })
    } else {
        Ok(value)
    }
}

fn registry_chunk(read: &ReadSnapshot, id: &[u8]) -> Result<Option<hellas_kernel::RegistryChunk>> {
    match read.object(id).map_err(storage)? {
        Some(Object::RegistryChunk(chunk)) => Ok(Some(chunk)),
        None => Ok(None),
        _ => Err(EdgeIndexError::unavailable(
            "wrong object kind at registry slot",
        )),
    }
}
