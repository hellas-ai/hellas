//! Durable finalized index. Object versions and publication metadata commit in one redb
//! transaction. A small intent bridges that transaction to QMDB's independent finalize.
use super::types::TransactionRef;
use crate::{
    domain::{Digest, Object, Transaction},
    verified_explorer::ProofBundle,
};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::{Block as _, Heightable as _};
use hellas_kernel::{TermsProfile, Tx};
use prost::Message as _;
use redb::{Database, ReadableDatabase as _, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, path::Path, sync::Arc};

pub(super) type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const STORAGE_VERSION: u32 = 2;
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("edge_metadata_v1");
const PROOFS: TableDefinition<u64, &[u8]> = TableDefinition::new("edge_block_proofs_v1");
const PAYLOADS: TableDefinition<&str, u64> = TableDefinition::new("edge_payload_heights_v1");
const EDGES: TableDefinition<&str, &[u8]> = TableDefinition::new("edge_history_v1");
const LOOKUP: TableDefinition<&str, &str> = TableDefinition::new("edge_lookup_v1");
const OBJECTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("edge_object_versions_v1");
const TRANSACTIONS: TableDefinition<&str, u64> =
    TableDefinition::new("edge_transaction_locator_v1");
const EVENTS: TableDefinition<&str, &[u8]> = TableDefinition::new("edge_events_v1");
const EXPIRE: TableDefinition<&str, &[u8]> = TableDefinition::new("edge_open_expiry_v1");

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct Identity {
    pub network_id: String,
    pub genesis_sha256: String,
    pub trust_sha256: String,
    pub schema_version: u32,
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct StoredEdge {
    pub edge_id: String,
    pub opened: TransactionRef,
    pub closed: Option<TransactionRef>,
    pub payment_edge_id: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct StoredEvent {
    pub kind: String,
    pub transaction: TransactionRef,
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Intent {
    pub proof: ProofBundle,
    pub changes: Vec<(Vec<u8>, Option<Vec<u8>>)>,
}
#[derive(Clone)]
pub(super) struct IndexStore {
    db: Arc<Database>,
    pub identity: Identity,
    pub retention: u64,
}
/// A read transaction pins every table version even while publication/pruning proceeds.
pub(super) struct ReadSnapshot {
    tx: redb::ReadTransaction,
    pub proof: ProofBundle,
    pub retained_from_height: u64,
    pub indexed_through: ProofBundle,
    block: RefCell<Option<(u64, crate::HellasBlock)>>,
}
#[derive(Debug, thiserror::Error)]
pub(super) enum SnapshotError {
    #[error("index_not_ready")]
    NotReady,
    #[error("snapshot_expired")]
    Expired,
    #[error("snapshot_unavailable")]
    Unavailable,
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(value)?)
}
fn decode<T: serde::de::DeserializeOwned>(value: &[u8]) -> Result<T> {
    Ok(serde_json::from_slice(value)?)
}
fn version_key(id: &[u8], height: u64) -> Vec<u8> {
    let mut key = id.to_vec();
    key.extend_from_slice(&height.to_be_bytes());
    key
}
impl IndexStore {
    pub fn open(path: &Path, identity: Identity) -> Result<Self> {
        std::fs::create_dir_all(path.parent().ok_or("index path has no parent")?)?;
        let retention = match std::env::var("HELLAS_EDGE_SNAPSHOT_RETENTION") {
            Ok(raw) => {
                let value = raw.parse::<u64>()?;
                if value.to_string() != raw || !(32..=1024).contains(&value) {
                    return Err(
                        "HELLAS_EDGE_SNAPSHOT_RETENTION must be canonical decimal 32..1024".into(),
                    );
                }
                value
            }
            Err(std::env::VarError::NotPresent) => 32,
            Err(error) => return Err(error.into()),
        };
        let db = Database::builder()
            .set_cache_size(64 * 1024 * 1024)
            .create(path)?;
        let write = db.begin_write()?;
        {
            let mut meta = write.open_table(META)?;
            if meta.get("identity")?.is_some()
                && meta
                    .get("storage_version")?
                    .map(|v| decode::<u32>(v.value()))
                    .transpose()?
                    != Some(STORAGE_VERSION)
            {
                return Err(
                    "edge index storage format changed; rebuild in a new storage directory".into(),
                );
            }
            meta.insert("storage_version", encode(&STORAGE_VERSION)?.as_slice())?;
            if let Some(previous) = meta.get("identity")? {
                if decode::<Identity>(previous.value())? != identity {
                    return Err("edge index identity/schema mismatch; rebuild this index from genesis in a new storage directory".into());
                }
            } else {
                meta.insert("identity", encode(&identity)?.as_slice())?;
            }
        }
        write.open_table(PROOFS)?;
        write.open_table(PAYLOADS)?;
        write.open_table(EDGES)?;
        write.open_table(LOOKUP)?;
        write.open_table(OBJECTS)?;
        write.open_table(EVENTS)?;
        write.open_table(EXPIRE)?;
        write.open_table(TRANSACTIONS)?;
        write.commit()?;
        Ok(Self {
            db: Arc::new(db),
            identity,
            retention,
        })
    }
    pub fn transaction_height(&self, digest: &str) -> Result<Option<u64>> {
        let read = self.db.begin_read()?;
        Ok(read
            .open_table(TRANSACTIONS)?
            .get(digest)?
            .map(|value| value.value()))
    }
    pub fn latest(&self) -> Result<Option<ProofBundle>> {
        let read = self.db.begin_read()?;
        let table = read.open_table(META)?;
        let height: Option<u64> = table
            .get("latest")?
            .map(|v| decode(v.value()))
            .transpose()?;
        height
            .map(|height| read_proof(&read.open_table(PROOFS)?, height))
            .transpose()
    }
    pub fn intent(&self) -> Result<Option<Intent>> {
        let read = self.db.begin_read()?;
        let table = read.open_table(META)?;
        table.get("intent")?.map(|v| decode(v.value())).transpose()
    }
    pub fn prepare(
        &self,
        proof: ProofBundle,
        changes: Vec<(Digest, Option<Object>)>,
    ) -> Result<()> {
        let intent = Intent {
            proof,
            changes: changes
                .into_iter()
                .map(|(id, object)| (id.0.to_vec(), object.map(|object| object.encode().to_vec())))
                .collect(),
        };
        let write = self.db.begin_write()?;
        write
            .open_table(META)?
            .insert("intent", encode(&intent)?.as_slice())?;
        write.commit()?;
        Ok(())
    }
    pub fn clear_intent(&self) -> Result<()> {
        let write = self.db.begin_write()?;
        write.open_table(META)?.remove("intent")?;
        write.commit()?;
        Ok(())
    }
    /// Caller has checked that the finalized QMDB root equals the intent's certified root.
    /// No rows become query-visible until this whole transaction commits.
    pub fn publish_intent(&self) -> Result<()> {
        let intent = self.intent()?.ok_or("missing replay intent")?;
        let block = crate::HellasBlock::decode(intent.proof.canonical_block.as_slice())?;
        let height = intent.proof.height;
        let write = self.db.begin_write()?;
        {
            let mut meta = write.open_table(META)?;
            let previous: Option<u64> =
                meta.get("latest")?.map(|v| decode(v.value())).transpose()?;
            let previous = previous
                .map(|height| read_proof(&write.open_table(PROOFS)?, height))
                .transpose()?;
            if let Some(previous) = previous {
                if previous.height == height && previous.payload == intent.proof.payload {
                    meta.remove("intent")?;
                    drop(meta);
                    write.commit()?;
                    return Ok(());
                }
                if previous.height.checked_add(1) != Some(height)
                    || previous.payload != hex::encode(block.parent())
                {
                    return Err("edge index finalized gap or parent conflict".into());
                }
            } else if height != 1 {
                return Err("edge index must begin at height one".into());
            }
            if block.height().get() != height {
                return Err("edge index height mismatch".into());
            }
            let previous_floor: u64 = meta
                .get("retained_from")?
                .map(|v| decode(v.value()))
                .transpose()?
                .unwrap_or(1);
            let floor = previous_floor.max(height.saturating_sub(self.retention - 1).max(1));
            let mut expiry = write.open_table(EXPIRE)?;
            let mut edges = write.open_table(EDGES)?;
            let mut lookup = write.open_table(LOOKUP)?;
            let mut events = write.open_table(EVENTS)?;
            for (index, transaction) in block.txs().iter().enumerate() {
                let transaction_digest =
                    hex::encode(crate::verified_explorer::transaction_digest(transaction));
                write
                    .open_table(TRANSACTIONS)?
                    .insert(transaction_digest.as_str(), height)?;
                let Transaction::Kernel(tx) = transaction else {
                    continue;
                };
                let reference = TransactionRef {
                    height,
                    payload: intent.proof.payload.clone(),
                    transaction_digest,
                    transaction_index: u32::try_from(index)?,
                };
                let (id, kind) = match tx {
                    Tx::Open { funding, terms, .. } => {
                        let id = hex::encode(Tx::edge_id_of(funding, terms).as_bytes());
                        if edges.get(id.as_str())?.is_some() {
                            return Err("duplicate edge open in finalized history".into());
                        }
                        let edge = StoredEdge {
                            edge_id: id.clone(),
                            opened: reference.clone(),
                            closed: None,
                            payment_edge_id: None,
                        };
                        edges.insert(id.as_str(), encode(&edge)?.as_slice())?;
                        let maker =
                            crate::domain::SettlementKey::from(terms.parties().maker()).to_string();
                        let taker =
                            crate::domain::SettlementKey::from(terms.parties().taker()).to_string();
                        let kind = match terms.profile() {
                            TermsProfile::Basic => "basic",
                            TermsProfile::WorkStakeBond(_) => "work-stake-bond",
                            TermsProfile::WorkPayment(payment) => {
                                let bond_id = hex::encode(payment.bond_edge.as_bytes());
                                let mut bond: StoredEdge = decode(
                                    edges
                                        .get(bond_id.as_str())?
                                        .ok_or("payment names unindexed bond")?
                                        .value(),
                                )?;
                                if bond.payment_edge_id.is_some() {
                                    return Err("bond already has an indexed payment".into());
                                }
                                bond.payment_edge_id = Some(id.clone());
                                edges.insert(bond_id.as_str(), encode(&bond)?.as_slice())?;
                                "work-payment"
                            }
                        };
                        for prefix in [
                            "a/".to_string(),
                            format!("k/{kind}/"),
                            format!("m/{maker}/"),
                            format!("t/{taker}/"),
                            format!("p/{maker}/"),
                            format!("p/{taker}/"),
                        ] {
                            for state in ["all", "open"] {
                                lookup.insert(
                                    format!("{state}/{prefix}{id}").as_str(),
                                    id.as_str(),
                                )?;
                            }
                        }
                        (id, "open")
                    }
                    Tx::Close { input, .. } => {
                        let id = hex::encode(input.as_bytes());
                        let mut edge: StoredEdge = decode(
                            edges
                                .get(id.as_str())?
                                .ok_or("close names unindexed edge")?
                                .value(),
                        )?;
                        if edge.closed.is_some() {
                            return Err("edge closed twice".into());
                        }
                        edge.closed = Some(reference.clone());
                        let opening_block;
                        let opening = if edge.opened.height == height {
                            &block
                        } else {
                            let proof = read_proof(&write.open_table(PROOFS)?, edge.opened.height)?;
                            opening_block =
                                crate::HellasBlock::decode(proof.canonical_block.as_slice())?;
                            &opening_block
                        };
                        let Transaction::Kernel(Tx::Open { terms, .. }) =
                            transaction_at(opening, &edge.opened)?
                        else {
                            return Err("stored opening is not Open".into());
                        };
                        let prefixes = lookup_prefixes(&terms);
                        for prefix in &prefixes {
                            lookup.insert(format!("closed/{prefix}{id}").as_str(), id.as_str())?;
                        }
                        expiry.insert(
                            format!("{height:020}/{id}").as_str(),
                            encode(&prefixes)?.as_slice(),
                        )?;
                        edges.insert(id.as_str(), encode(&edge)?.as_slice())?;
                        (id, "close")
                    }
                    Tx::Move { action } => {
                        let id = match action {
                            hellas_kernel::Move::StartPaymentClose(start) => start.payment_edge(),
                            hellas_kernel::Move::RespondPaymentClose(response) => {
                                response.payment_edge()
                            }
                        };
                        (hex::encode(id.as_bytes()), "move")
                    }
                };
                let event = StoredEvent {
                    kind: kind.into(),
                    transaction: reference,
                };
                events.insert(
                    format!("{id}/{height:020}/{index:010}").as_str(),
                    encode(&event)?.as_slice(),
                )?;
            }
            // Closed edges remain in the open lookup only while a retained pin can
            // still precede their close. Old closed history never burdens open scans.
            let expired = expiry
                .range(..format!("{floor:020}/").as_str())?
                .map(|entry| {
                    entry.map(|(key, value)| (key.value().to_string(), value.value().to_vec()))
                })
                .collect::<std::result::Result<Vec<_>, _>>()?;
            for (key, value) in expired {
                let (_, id) = key.split_once('/').ok_or("invalid expiry key")?;
                for prefix in decode::<Vec<String>>(&value)? {
                    lookup.remove(format!("open/{prefix}{id}").as_str())?;
                }
                expiry.remove(key.as_str())?;
            }
            let mut objects = write.open_table(OBJECTS)?;
            for (id, value) in &intent.changes {
                // First byte distinguishes a tombstone from a canonical object.
                let mut bytes = vec![u8::from(value.is_some())];
                if let Some(value) = value {
                    bytes.extend(value);
                }
                objects.insert(version_key(id, height).as_slice(), bytes.as_slice())?;
                // Retain one baseline at/before the oldest advertised snapshot plus
                // every newer version. Readers already holding the old transaction
                // keep its pages alive through redb MVCC.
                let old = objects
                    .range(version_key(id, 0).as_slice()..=version_key(id, floor).as_slice())?
                    .map(|entry| entry.map(|(key, _)| key.value().to_vec()))
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                for key in old.iter().take(old.len().saturating_sub(1)) {
                    objects.remove(key.as_slice())?;
                }
            }
            write
                .open_table(PROOFS)?
                .insert(height, intent.proof.encode_to_vec().as_slice())?;
            write
                .open_table(PAYLOADS)?
                .insert(intent.proof.payload.as_str(), height)?;
            meta.insert("latest", encode(&height)?.as_slice())?;
            meta.insert("retained_from", encode(&floor)?.as_slice())?;
            meta.remove("intent")?;
        }
        write.commit()?;
        Ok(())
    }
    pub fn read(&self, payload: Option<&str>) -> Result<ReadSnapshot> {
        let tx = self.db.begin_read()?;
        let latest: u64 = decode(
            tx.open_table(META)?
                .get("latest")?
                .ok_or(SnapshotError::NotReady)?
                .value(),
        )?;
        let indexed_through = read_proof(&tx.open_table(PROOFS)?, latest)?;
        let retained_from_height = decode(
            tx.open_table(META)?
                .get("retained_from")?
                .ok_or("missing retention cursor")?
                .value(),
        )?;
        let height = match payload {
            Some(payload) => tx
                .open_table(PAYLOADS)?
                .get(payload)?
                .ok_or(SnapshotError::Unavailable)?
                .value(),
            None => indexed_through.height,
        };
        if height < retained_from_height {
            return Err(SnapshotError::Expired.into());
        }
        let proof = read_proof(&tx.open_table(PROOFS)?, height)?;
        Ok(ReadSnapshot {
            tx,
            proof,
            retained_from_height,
            indexed_through,
            block: RefCell::new(None),
        })
    }
}
impl ReadSnapshot {
    pub fn edge(&self, id: &str) -> Result<Option<StoredEdge>> {
        let table = self.tx.open_table(EDGES)?;
        let mut edge: StoredEdge = match table.get(id)? {
            Some(value) => decode(value.value())?,
            None => return Ok(None),
        };
        if edge.opened.height > self.proof.height {
            return Ok(None);
        }
        if edge
            .closed
            .as_ref()
            .is_some_and(|reference| reference.height > self.proof.height)
        {
            edge.closed = None;
        }
        if let Some(payment) = &edge.payment_edge_id {
            let payment: StoredEdge = decode(
                table
                    .get(payment.as_str())?
                    .ok_or("missing indexed payment")?
                    .value(),
            )?;
            if payment.opened.height > self.proof.height {
                edge.payment_edge_id = None;
            }
        }
        Ok(Some(edge))
    }
    pub fn proof(&self, height: u64) -> Result<ProofBundle> {
        read_proof(&self.tx.open_table(PROOFS)?, height)
    }
    pub fn transaction(&self, reference: &TransactionRef) -> Result<Transaction> {
        // Adjacent events and edges commonly reference one block. Keep only one
        // decoded block so a filtered scan cannot accumulate archive-sized memory.
        let mut cached = self.block.borrow_mut();
        if cached
            .as_ref()
            .is_none_or(|(height, _)| *height != reference.height)
        {
            let proof = self.proof(reference.height)?;
            *cached = Some((
                reference.height,
                crate::HellasBlock::decode(proof.canonical_block.as_slice())?,
            ));
        }
        transaction_at(&cached.as_ref().expect("block loaded above").1, reference)
    }
    pub fn object(&self, id: &[u8]) -> Result<Option<Object>> {
        if id.len() != 32 {
            return Err("object id length".into());
        }
        let table = self.tx.open_table(OBJECTS)?;
        let low = version_key(id, 0);
        let high = version_key(id, self.proof.height);
        let mut range = table.range(low.as_slice()..=high.as_slice())?;
        let Some(value) = range.next_back() else {
            return Ok(None);
        };
        let (_, bytes) = value?;
        match bytes.value().split_first() {
            Some((0, [])) => Ok(None),
            Some((1, canonical)) => Ok(Some(Object::decode(canonical)?)),
            _ => Err("invalid stored object version".into()),
        }
    }
    /// Indexed prefix seek with a bounded visit budget; callers additionally enforce time.
    pub fn scan_edges(
        &self,
        prefix: &str,
        after: Option<&str>,
        visit: impl FnMut(StoredEdge) -> Result<bool>,
    ) -> Result<()> {
        let table = self.tx.open_table(LOOKUP)?;
        let start = format!("{prefix}{}", after.unwrap_or(""));
        let mut visit = visit;
        let mut count = 0;
        for entry in table.range(start.as_str()..)? {
            let (key, id) = entry?;
            if !key.value().starts_with(prefix) {
                break;
            }
            if after == Some(id.value()) {
                continue;
            }
            count += 1;
            if count > 100_000 {
                return Err("query budget exceeded".into());
            }
            if let Some(edge) = self.edge(id.value())?
                && !visit(edge)?
            {
                break;
            }
        }
        Ok(())
    }
    pub fn events(
        &self,
        edge: &str,
        after: Option<(u64, u32)>,
        limit: usize,
    ) -> Result<Vec<StoredEvent>> {
        let table = self.tx.open_table(EVENTS)?;
        let prefix = format!("{edge}/");
        let start = match after {
            Some((height, index)) => format!("{prefix}{height:020}/{index:010}"),
            None => prefix.clone(),
        };
        let mut result = Vec::new();
        for entry in table.range(start.as_str()..)? {
            let (key, value) = entry?;
            if !key.value().starts_with(&prefix) {
                break;
            }
            let event: StoredEvent = decode(value.value())?;
            if event.transaction.height > self.proof.height {
                break;
            }
            if after
                == Some((
                    event.transaction.height,
                    event.transaction.transaction_index,
                ))
            {
                continue;
            }
            result.push(event);
            if result.len() >= limit {
                break;
            }
        }
        Ok(result)
    }
}

fn read_proof(table: &impl ReadableTable<u64, &'static [u8]>, height: u64) -> Result<ProofBundle> {
    let value = table.get(height)?.ok_or("canonical block proof missing")?;
    Ok(<ProofBundle as prost::Message>::decode(value.value())?)
}
fn transaction_at(block: &crate::HellasBlock, reference: &TransactionRef) -> Result<Transaction> {
    use commonware_cryptography::Digestible as _;
    let transaction = block
        .txs()
        .get(reference.transaction_index as usize)
        .ok_or("transaction locator is out of range")?;
    if block.height().get() != reference.height
        || hex::encode(block.digest()) != reference.payload
        || hex::encode(crate::verified_explorer::transaction_digest(transaction))
            != reference.transaction_digest
    {
        return Err("transaction locator differs from canonical block".into());
    }
    Ok(transaction.clone())
}

fn lookup_prefixes(terms: &hellas_kernel::Terms) -> Vec<String> {
    let maker = crate::domain::SettlementKey::from(terms.parties().maker()).to_string();
    let taker = crate::domain::SettlementKey::from(terms.parties().taker()).to_string();
    let kind = match terms.profile() {
        TermsProfile::Basic => "basic",
        TermsProfile::WorkPayment(_) => "work-payment",
        TermsProfile::WorkStakeBond(_) => "work-stake-bond",
    };
    vec![
        "a/".into(),
        format!("k/{kind}/"),
        format!("m/{maker}/"),
        format!("t/{taker}/"),
        format!("p/{maker}/"),
        format!("p/{taker}/"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge_index::{EdgeIndex, ListEdgesRequest};

    #[test]
    fn native_edge_index_open_queries_do_not_scan_closed_history() {
        // Synthetic lookup stress: the certificate/root checks are covered by the
        // execution-backed replay tests. Here the adversary is a large cold history
        // prefix, and the open query must never visit any of its rows.
        let directory = tempfile::tempdir().unwrap();
        let index = EdgeIndex::open(
            &directory.path().join("index.redb"),
            "test".into(),
            "01".repeat(32),
            "02".repeat(32),
        )
        .unwrap();
        let proof = ProofBundle {
            schema_version: 1,
            network_id: "test".into(),
            trust_sha256: "02".repeat(32),
            height: 100_001,
            payload: "03".repeat(32),
            state_root: "04".repeat(32),
            ..Default::default()
        };
        let write = index.store.db.begin_write().unwrap();
        {
            let mut lookup = write.open_table(LOOKUP).unwrap();
            for id in 0..100_001_u64 {
                let id = format!("{id:064x}");
                lookup
                    .insert(format!("all/a/{id}").as_str(), id.as_str())
                    .unwrap();
                lookup
                    .insert(format!("closed/a/{id}").as_str(), id.as_str())
                    .unwrap();
            }
            let mut meta = write.open_table(META).unwrap();
            meta.insert("latest", encode(&proof.height).unwrap().as_slice())
                .unwrap();
            meta.insert("retained_from", encode(&99_970_u64).unwrap().as_slice())
                .unwrap();
            write
                .open_table(PROOFS)
                .unwrap()
                .insert(proof.height, proof.encode_to_vec().as_slice())
                .unwrap();
        }
        write.commit().unwrap();
        let page = index
            .list_edges(ListEdgesRequest {
                schema_version: super::super::SCHEMA_VERSION,
                ..Default::default()
            })
            .unwrap();
        assert!(page.data.items.is_empty());
        assert!(page.data.next_cursor.is_none());
    }
}
