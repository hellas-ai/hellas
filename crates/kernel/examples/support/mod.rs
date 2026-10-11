#![allow(dead_code)]
#![allow(clippy::redundant_pub_crate)]

use std::collections::BTreeMap;

use hellas_kernel::{
    Batch, Block, BlockHash, BlockHeight, Coin, CoinId, Context, Cost, Edge, EdgeId, EventKind,
    Fees, Genesis, InsertError, KernelResult, Key, List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS,
    NetworkId, PayloadHash, Payout, RegistryChunk, RegistryChunkId, Sig, SigVerifier, State, Store,
    Tx,
};

/// The network these examples settle on. Every authorization they build
/// commits to it, and every context they run under names it.
pub(crate) const NETWORK: NetworkId = match NetworkId::new("hellas-example-1") {
    Some(network) => network,
    None => panic!("literal is a legal network id"),
};
use secp256k1::{Message, SecretKey, ecdsa};

#[derive(Debug, Default)]
pub(crate) struct MemStore {
    coins: BTreeMap<CoinId, Coin>,
    edges: BTreeMap<EdgeId, Edge>,
    registry: BTreeMap<RegistryChunkId, RegistryChunk>,
}

impl MemStore {
    pub(crate) fn coin_count(&self) -> usize {
        self.coins.len()
    }

    pub(crate) fn edge_count(&self) -> usize {
        self.edges.len()
    }

    pub(crate) fn edge(&self, id: EdgeId) -> Option<Edge> {
        self.edges.get(&id).copied()
    }

    fn coins(&self) -> impl Iterator<Item = (CoinId, Coin)> + '_ {
        self.coins.iter().map(|(id, coin)| (*id, *coin))
    }
}

impl Store for MemStore {
    type Batch<'a>
        = MemTx<'a>
    where
        Self: 'a;

    fn begin(&mut self) -> Self::Batch<'_> {
        MemTx {
            working: Working {
                coins: self.coins.clone(),
                edges: self.edges.clone(),
                registry: self.registry.clone(),
            },
            parent: self,
        }
    }
}

#[derive(Debug, Default)]
struct Working {
    coins: BTreeMap<CoinId, Coin>,
    edges: BTreeMap<EdgeId, Edge>,
    registry: BTreeMap<RegistryChunkId, RegistryChunk>,
}

pub(crate) struct MemTx<'a> {
    working: Working,
    parent: &'a mut MemStore,
}

impl Batch for MemTx<'_> {
    fn coin(&self, id: CoinId) -> Option<Coin> {
        self.working.coins.get(&id).copied()
    }

    fn insert_coin(&mut self, id: CoinId, coin: Coin) -> KernelResult<(), InsertError> {
        if self.working.coins.contains_key(&id) {
            return Err(InsertError::Exists);
        }
        self.working.coins.insert(id, coin);
        Ok(())
    }

    fn remove_coin(&mut self, id: CoinId) -> Option<Coin> {
        self.working.coins.remove(&id)
    }

    fn edge(&self, id: EdgeId) -> Option<Edge> {
        self.working.edges.get(&id).copied()
    }

    fn insert_edge(&mut self, id: EdgeId, edge: Edge) -> KernelResult<(), InsertError> {
        if self.working.edges.contains_key(&id) {
            return Err(InsertError::Exists);
        }
        self.working.edges.insert(id, edge);
        Ok(())
    }

    fn remove_edge(&mut self, id: EdgeId) -> Option<Edge> {
        self.working.edges.remove(&id)
    }

    fn registry_chunk(&self, id: RegistryChunkId) -> Option<RegistryChunk> {
        self.working.registry.get(&id).copied()
    }

    fn insert_registry_chunk(
        &mut self,
        id: RegistryChunkId,
        chunk: RegistryChunk,
    ) -> KernelResult<(), InsertError> {
        if self.working.registry.contains_key(&id) {
            return Err(InsertError::Exists);
        }
        self.working.registry.insert(id, chunk);
        Ok(())
    }

    fn remove_registry_chunk(&mut self, id: RegistryChunkId) -> Option<RegistryChunk> {
        self.working.registry.remove(&id)
    }

    fn commit(self) {
        self.parent.coins = self.working.coins;
        self.parent.edges = self.working.edges;
        self.parent.registry = self.working.registry;
    }
}

pub(crate) fn genesis(seeds: &[Genesis]) -> State<MemStore> {
    State::genesis(MemStore::default(), seeds).expect("genesis seeds are valid")
}

pub(crate) fn apply_one<V>(
    state: &mut State<MemStore>,
    verifier: &V,
    context: Context,
    operation: Tx,
) -> EventKind
where
    V: SigVerifier + ?Sized,
{
    let block = Block::new(context, List::all([operation]));
    let diff = state
        .apply_block(verifier, &block)
        .expect("single-op block accepted");
    diff.event(0)
        .expect("single-op block emits one event")
        .kind()
        .clone()
}

pub(crate) fn secp_keypair(seed: u8) -> (SecretKey, Key) {
    let secret = SecretKey::from_secret_bytes([seed; 32]).expect("non-zero seed");
    let public = secret.public_key();
    (secret, Key::from_bytes(public.serialize()))
}

pub(crate) fn secp_sign(secret: &SecretKey, hash: PayloadHash) -> Sig {
    let message = Message::from_digest(hash.to_bytes());
    let signature = ecdsa::sign(message, secret);
    Sig::from_bytes(signature.serialize_compact())
}

pub(crate) const fn context(height: u64, hash_byte: u8, fees: Fees) -> Context {
    Context::with_fees(
        NETWORK,
        BlockHeight::new(height),
        BlockHash::from_bytes([hash_byte; BlockHash::LENGTH]),
        fees,
    )
}

pub(crate) fn context_fee(context: Context, cost: Cost) -> u64 {
    context.fee(cost).expect("fee calculation fits")
}

pub(crate) fn schedule_fee(fees: Fees, cost: Cost) -> u64 {
    fees.charge(cost).expect("fee calculation fits")
}

pub(crate) const fn lifetime_fee(context: Context, timeout: BlockHeight) -> u64 {
    let blocks = timeout
        .get()
        .checked_sub(context.block_height().get())
        .expect("timeout is in the future");
    context
        .fees()
        .lifetime()
        .checked_mul(blocks)
        .expect("lifetime fee fits")
}

pub(crate) const fn party_one(id: CoinId) -> List<CoinId, MAX_PARTY_INPUTS> {
    List::take([id; MAX_PARTY_INPUTS], 1)
}

pub(crate) const fn empty_party() -> List<CoinId, MAX_PARTY_INPUTS> {
    List::empty(CoinId::from_bytes([0; CoinId::LENGTH]))
}

pub(crate) const fn payouts2(
    maker: Key,
    maker_value: u64,
    taker: Key,
    taker_value: u64,
) -> List<Payout, MAX_EDGE_OUTPUTS> {
    let first = Payout::new(maker, maker_value);
    let second = Payout::new(taker, taker_value);
    let mut outputs = [first; MAX_EDGE_OUTPUTS];
    outputs[1] = second;
    List::take(outputs, 2)
}

pub(crate) const fn payout1(owner: Key, value: u64) -> List<Payout, MAX_EDGE_OUTPUTS> {
    List::take([Payout::new(owner, value); MAX_EDGE_OUTPUTS], 1)
}

pub(crate) const fn coin_id(tag: u8) -> CoinId {
    CoinId::from_bytes([tag; CoinId::LENGTH])
}

pub(crate) fn print_live_coins(store: &MemStore) {
    println!("  final live coins:");
    for (id, coin) in store.coins() {
        println!(
            "    {} owner={} value={}",
            short(id.as_bytes()),
            short(coin.owner().as_bytes()),
            coin.value(),
        );
    }
}

pub(crate) fn summarize(event: &EventKind) -> String {
    match event {
        EventKind::EdgeOpened { inputs, output } => {
            let inputs: Vec<String> = inputs
                .as_slice()
                .iter()
                .map(|id| short(id.as_bytes()))
                .collect();
            format!(
                "EdgeOpened(inputs=[{}], output={})",
                inputs.join(", "),
                short(output.as_bytes()),
            )
        }
        EventKind::EdgeClosed { input, outputs } => {
            let outputs: Vec<String> = outputs
                .as_slice()
                .iter()
                .map(|id| short(id.as_bytes()))
                .collect();
            format!(
                "EdgeClosed(input={}, outputs=[{}])",
                short(input.as_bytes()),
                outputs.join(", "),
            )
        }
    }
}

pub(crate) fn short(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in &bytes[..4] {
        push_hex(&mut out, *byte);
    }
    out.push_str("...");
    for byte in &bytes[bytes.len() - 2..] {
        push_hex(&mut out, *byte);
    }
    out
}

fn push_hex(out: &mut String, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(char::from(HEX[usize::from(byte >> 4)]));
    out.push(char::from(HEX[usize::from(byte & 0x0f)]));
}
