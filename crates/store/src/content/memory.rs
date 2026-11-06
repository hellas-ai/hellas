use super::{reservation::Reservation, *};
use bytes::Bytes;
use hellas_auth::authority::UnixMillis;
use hellas_rpc::{ContentId, ContentRef};
use hellas_xet::Chunk;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Arc, Mutex},
};

#[derive(Clone)]
pub struct MemoryStore {
    pub(crate) state: Arc<Mutex<State>>,
    pub(crate) pool: Reservations,
    pub(crate) changed: Arc<tokio::sync::Notify>,
    pub(crate) peers: Option<hellas_wire::iroh::Pool>,
    pub(crate) http: ureq::Agent,
}
pub(crate) struct Stored {
    pub bytes: Bytes,
    pub chunks: Vec<Chunk>,
}
struct ChargedBytes {
    bytes: Bytes,
    _charge: Arc<Reservation>,
}
impl AsRef<[u8]> for ChargedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
fn charged(bytes: Bytes, charge: Arc<Reservation>) -> Bytes {
    Bytes::from_owner(ChargedBytes {
        bytes,
        _charge: charge,
    })
}
struct Work {
    upload_limit: u64,
    job: JobId,
    closure: Closure,
    charge: Arc<Reservation>,
    staged: BTreeMap<ContentId, Arc<Stored>>,
}
pub(crate) struct State {
    objects: BTreeMap<ContentId, Arc<Stored>>,
    pins: BTreeMap<PinName, PinValue>,
    work: BTreeMap<ReservationId, Work>,
    active: BTreeSet<(ReservationId, ContentId)>,
    next_reservation: u64,
    generation: u64,
    events: VecDeque<(PinEvent, Option<PinValue>, usize)>,
    event_bytes: usize,
}
impl MemoryStore {
    pub fn new(pool: Reservations) -> Self {
        Self {
            pool,
            peers: None,
            http: ureq::Agent::new_with_defaults(),
            changed: Arc::new(tokio::sync::Notify::new()),
            state: Arc::new(Mutex::new(State {
                objects: BTreeMap::new(),
                pins: BTreeMap::new(),
                work: BTreeMap::new(),
                active: BTreeSet::new(),
                next_reservation: 0,
                generation: 0,
                events: VecDeque::new(),
                event_bytes: 0,
            })),
        }
    }
    pub fn with_peers(mut self, peers: hellas_wire::iroh::Pool) -> Self {
        self.peers = Some(peers);
        self
    }
    pub(crate) fn publish_acquired(
        &self,
        objects: Vec<(ContentRef, Bytes, Vec<Chunk>, Arc<Reservation>)>,
        target: Target,
        pin: PinTarget,
    ) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::Invalid("store lock"))?;
        if state.generation == u64::MAX {
            return Err(Error::Capacity);
        }
        let mut added = Vec::new();
        for (object, bytes, chunks, charge) in objects {
            if let std::collections::btree_map::Entry::Vacant(e) = state.objects.entry(object.id())
            {
                e.insert(Arc::new(Stored {
                    bytes: charged(bytes, charge),
                    chunks,
                }));
                added.push(object.id());
            }
        }
        if let Err(error) = state.walk(target).and_then(|_| state.load(target)) {
            for id in added {
                state.objects.remove(&id);
            }
            return Err(error);
        }
        state.change_pin(
            pin.name,
            Some(PinValue {
                target,
                policy: pin.policy,
                expires: None,
            }),
        )?;
        self.changed.notify_waiters();
        Ok(())
    }
    /// Called by the authenticated application opening, first with the root only.
    pub fn open_work(&self, job: JobId, closure: Closure, max_upload_bytes: u64) -> Result<Scope> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::Invalid("store lock"))?;
        if let Some((id, work)) = state.work.iter().find(|(_, work)| work.job == job) {
            return Ok(Scope::Work {
                job,
                closure: work.closure.clone(),
                reservation: *id,
            });
        }
        let closure = canonical_closure(closure)?;
        let scope = Scope::Work {
            job,
            closure: closure.clone(),
            reservation: 0,
        };
        let missing = state.missing(&scope, &closure)?;
        if missing > max_upload_bytes {
            return Err(Error::Capacity);
        }
        let charge = self.pool.reserve(missing)?;
        state.next_reservation = state
            .next_reservation
            .checked_add(1)
            .ok_or(Error::Capacity)?;
        let reservation = state.next_reservation;
        state.work.insert(
            reservation,
            Work {
                upload_limit: max_upload_bytes,
                job,
                closure: closure.clone(),
                charge,
                staged: BTreeMap::new(),
            },
        );
        Ok(Scope::Work {
            job,
            closure,
            reservation,
        })
    }
    /// Widen only after the application has verified and parsed the root.
    pub fn widen_work(
        &self,
        scope: &Scope,
        closure: Closure,
        max_upload_bytes: u64,
    ) -> Result<Scope> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::Invalid("store lock"))?;
        state.check(scope)?;
        let Scope::Work {
            job, reservation, ..
        } = scope
        else {
            return Err(Error::Denied);
        };
        let closure = canonical_closure(closure)?;
        let work = state.work.get(reservation).ok_or(Error::Denied)?;
        if max_upload_bytes > work.upload_limit {
            return Err(Error::Denied);
        }
        if work.closure.iter().any(|object| !closure.contains(object)) {
            return Err(Error::Invalid("closure cannot narrow"));
        }
        let new_scope = Scope::Work {
            job: *job,
            closure: closure.clone(),
            reservation: *reservation,
        };
        let missing = state.missing(&new_scope, &closure)?;
        if missing > max_upload_bytes {
            return Err(Error::Capacity);
        }
        let work = state.work.get_mut(reservation).ok_or(Error::Denied)?;
        if missing > work.charge.bytes() {
            work.charge.extend(missing - work.charge.bytes())?;
        }
        work.closure = closure;
        Ok(new_scope)
    }
    /// The host has atomically taken these bytes into live job RAM accounting.
    pub fn accept_work(&self, scope: &Scope) -> Result<()> {
        let state = self
            .state
            .lock()
            .map_err(|_| Error::Invalid("store lock"))?;
        state.check(scope)?;
        let Scope::Work { reservation, .. } = scope else {
            return Err(Error::Denied);
        };
        state
            .work
            .get(reservation)
            .ok_or(Error::Denied)?
            .charge
            .transfer();
        Ok(())
    }
    pub fn end_work(&self, scope: &Scope) -> Result<()> {
        let Scope::Work {
            job, reservation, ..
        } = scope
        else {
            return Err(Error::Denied);
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::Invalid("store lock"))?;
        if state
            .work
            .get(reservation)
            .is_some_and(|work| work.job != *job)
        {
            return Err(Error::Denied);
        }
        state.work.remove(reservation);
        self.changed.notify_waiters();
        Ok(())
    }
    pub(crate) fn check(&self, scope: &Scope) -> Result<()> {
        self.state
            .lock()
            .map_err(|_| Error::Invalid("store lock"))?
            .check(scope)
    }
    fn session(
        &self,
        state: &mut State,
        scope: &Scope,
        object: ContentRef,
        pin: Option<PinTarget>,
    ) -> Result<super::upload::LocalSession> {
        state.check(scope)?;
        let (reservation, charge) = match scope {
            Scope::Owner => {
                if pin.is_none() {
                    return Err(Error::Invalid("owner upload requires pin"));
                }
                state.next_reservation = state
                    .next_reservation
                    .checked_add(1)
                    .ok_or(Error::Capacity)?;
                (state.next_reservation, self.pool.reserve(object.bytes())?)
            }
            Scope::Work {
                reservation,
                closure,
                ..
            } => {
                if pin.is_some() || !closure.contains(&object) {
                    return Err(Error::Denied);
                }
                let missing = state.missing(scope, closure)?;
                let work = state.work.get(reservation).ok_or(Error::Denied)?;
                if missing > work.upload_limit {
                    return Err(Error::Capacity);
                }
                let held = work.charge.bytes();
                if missing > held {
                    work.charge.extend(missing - held)?;
                }
                (*reservation, work.charge.clone())
            }
            _ => return Err(Error::Denied),
        };
        if state.active.contains(&(reservation, object.id())) {
            return Err(Error::Conflict);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(usize::try_from(object.bytes()).map_err(|_| Error::Capacity)?)
            .map_err(|_| Error::Capacity)?;
        if !state.active.insert((reservation, object.id())) {
            return Err(Error::Conflict);
        }
        Ok(super::upload::LocalSession {
            store: self.clone(),
            scope: scope.clone(),
            pin,
            object,
            reservation,
            charge,
            bytes,
            finished: false,
        })
    }
    pub(crate) fn publish(
        &self,
        session: &mut super::upload::LocalSession,
        chunks: Vec<Chunk>,
    ) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::Invalid("store lock"))?;
        state.check(&session.scope)?;
        if session.pin.is_some() && state.generation == u64::MAX {
            return Err(Error::Capacity);
        }
        let bytes = Bytes::from(std::mem::take(&mut session.bytes));
        if bytes.len() as u64 != session.object.bytes() {
            return Err(Error::Invalid("incomplete object"));
        }
        let stored = Arc::new(Stored {
            bytes: charged(bytes, session.charge.clone()),
            chunks,
        });
        if let Some(pin) = &session.pin {
            PinName::new(pin.name.as_str().to_owned())?;
            state.objects.entry(session.object.id()).or_insert(stored);
            state.change_pin(
                pin.name.clone(),
                Some(PinValue {
                    target: Target::Object(session.object),
                    policy: pin.policy.clone(),
                    expires: None,
                }),
            )?;
            self.changed.notify_waiters();
        } else if let Scope::Work { reservation, .. } = session.scope {
            state
                .work
                .get_mut(&reservation)
                .ok_or(Error::Denied)?
                .staged
                .insert(session.object.id(), stored);
        } else {
            return Err(Error::Denied);
        }
        state
            .active
            .remove(&(session.reservation, session.object.id()));
        session.finished = true;
        Ok(())
    }
    pub(crate) fn abandon(&self, reservation: ReservationId, object: ContentId) {
        if let Ok(mut state) = self.state.lock() {
            state.active.remove(&(reservation, object));
        }
    }
    /// Own upper objects are available to the executor only within the live closure.
    pub fn own_bytes(&self, scope: &Scope, object: ContentRef) -> Result<Option<Bytes>> {
        let state = self
            .state
            .lock()
            .map_err(|_| Error::Invalid("store lock"))?;
        state.check(scope)?;
        let Scope::Work {
            reservation,
            closure,
            ..
        } = scope
        else {
            return Err(Error::Denied);
        };
        if !closure.contains(&object) {
            return Err(Error::Denied);
        }
        let result = state
            .work
            .get(reservation)
            .and_then(|work| work.staged.get(&object.id()));
        result
            .map(|stored| checked_bytes(stored, object))
            .transpose()
    }
}
fn canonical_closure(closure: Closure) -> Result<Closure> {
    let mut objects = BTreeMap::new();
    for object in closure {
        if objects
            .insert(object.id(), object)
            .is_some_and(|old| old != object)
        {
            return Err(Error::Invalid("inconsistent closure lengths"));
        }
    }
    Ok(objects.into_values().collect())
}
fn checked_bytes(stored: &Stored, object: ContentRef) -> Result<Bytes> {
    if stored.bytes.len() as u64 != object.bytes() {
        return Err(Error::Invalid("content length contract"));
    }
    Ok(stored.bytes.clone())
}
fn live(pin: &PinValue) -> bool {
    pin.expires
        .is_none_or(|expires| UnixMillis::now().is_ok_and(|now| now < expires))
}
fn readable(scope: &Scope, name: &PinName, pin: &PinValue) -> bool {
    if !live(pin) {
        return false;
    }
    matches!(scope, Scope::Owner)
        || match (&pin.policy, scope) {
            (PinPolicy::Public, _) => true,
            (PinPolicy::Jobs, Scope::Work { .. }) => true,
            (PinPolicy::Channel(channel), Scope::Work { job, .. }) => *channel == job.channel,
            (PinPolicy::Granted, Scope::Grant(grant)) => grant.pin == *name,
            _ => false,
        }
}
fn metadata_readable(scope: &Scope, name: &PinName, pin: &PinValue) -> bool {
    readable(scope, name, pin)
        && match scope {
            Scope::Work { closure, .. } => closure.contains(&pin.target.object()),
            _ => true,
        }
}

impl State {
    fn check(&self, scope: &Scope) -> Result<()> {
        if let Scope::Work {
            job,
            reservation,
            closure,
        } = scope
            && self
                .work
                .get(reservation)
                .is_none_or(|work| work.job != *job || work.closure != *closure)
        {
            return Err(Error::Denied);
        }
        Ok(())
    }
    fn load(&self, target: Target) -> Result<Bytes> {
        checked_bytes(
            self.objects
                .get(&target.object().id())
                .ok_or(Error::Missing)?,
            target.object(),
        )
    }
    /// ID-deduplicated traversal propagates the longest prefix of each shared
    /// subtree, so aliases cannot hide a path overflow or cause exponential walks.
    fn walk(&self, root: Target) -> Result<BTreeSet<ContentId>> {
        let mut reached = BTreeSet::new();
        let mut longest = BTreeMap::new();
        let mut pending = vec![(root, 0usize)];
        while let Some((target, path_len)) = pending.pop() {
            reached.insert(target.object().id());
            if let Target::Tree(object) = target {
                if longest
                    .get(&object.id())
                    .is_some_and(|old| *old >= path_len)
                {
                    continue;
                }
                longest.insert(object.id(), path_len);
                for (name, child) in Tree::decode(&self.load(target)?)?.entries() {
                    let length = path_len + usize::from(path_len != 0) + name.len();
                    if length > MAX_PATH_BYTES {
                        return Err(Error::Invalid("tree path length"));
                    }
                    pending.push((*child, length));
                }
            }
        }
        Ok(reached)
    }
    fn present(&self, scope: &Scope, object: ContentRef) -> Result<bool> {
        for (name, pin) in &self.pins {
            if readable(scope, name, pin)
                && self.walk(pin.target)?.contains(&object.id())
                && let Some(stored) = self.objects.get(&object.id())
            {
                checked_bytes(stored, object)?;
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn missing(&self, scope: &Scope, closure: &[ContentRef]) -> Result<u64> {
        let mut reachable = BTreeSet::new();
        for (name, pin) in &self.pins {
            if readable(scope, name, pin) {
                reachable.extend(self.walk(pin.target)?);
            }
        }
        closure
            .iter()
            .filter(|object| {
                let owned = if let Scope::Work { reservation, .. } = scope {
                    self.work
                        .get(reservation)
                        .is_some_and(|work| work.staged.contains_key(&object.id()))
                        || self.active.contains(&(*reservation, object.id()))
                } else {
                    false
                };
                owned
                    || !reachable.contains(&object.id())
                    || self
                        .objects
                        .get(&object.id())
                        .is_none_or(|stored| stored.bytes.len() as u64 != object.bytes())
            })
            .try_fold(0u64, |total, object| {
                total.checked_add(object.bytes()).ok_or(Error::Capacity)
            })
    }
    fn resolve(&self, scope: &Scope, at: &Path) -> Result<Option<Target>> {
        self.check(scope)?;
        PinName::new(at.pin.as_str().to_owned())?;
        super::tree::validate_path(&at.path, true)?;
        let Some(pin) = self
            .pins
            .get(&at.pin)
            .filter(|pin| readable(scope, &at.pin, pin))
        else {
            return Ok(None);
        };
        let mut target = pin.target;
        if !at.path.is_empty() {
            for name in at.path.split('/') {
                let Target::Tree(_) = target else {
                    return Err(Error::Invalid("path through object"));
                };
                let tree = Tree::decode(&self.load(target)?)?;
                let Some((_, child)) = tree.entries().iter().find(|(entry, _)| entry == name)
                else {
                    return Ok(None);
                };
                target = *child;
            }
        }
        if let Scope::Work { closure, .. } = scope
            && !closure.contains(&target.object())
        {
            return Ok(None);
        }
        self.load(target)?;
        Ok(Some(target))
    }
    fn change_pin(&mut self, name: PinName, value: Option<PinValue>) -> Result<()> {
        let generation = self.generation.checked_add(1).ok_or(Error::Capacity)?;
        let old = match &value {
            Some(value) => self.pins.insert(name.clone(), value.clone()),
            None => self.pins.remove(&name),
        };
        self.generation = generation;
        let event = PinEvent::Set {
            cursor: Cursor {
                generation,
                ..Default::default()
            },
            name,
            value,
        };
        let bytes = super::wire::event(&event).encoded_len();
        self.event_bytes += bytes;
        self.events.push_back((event, old, bytes));
        while self.event_bytes > body_limit() {
            if let Some((_, _, bytes)) = self.events.pop_front() {
                self.event_bytes -= bytes;
            }
        }
        Ok(())
    }
}
use prost::Message;
#[async_trait::async_trait]
impl ContentStore for MemoryStore {
    async fn stat(&self, scope: &Scope, at: &Path) -> Result<Option<Stat>> {
        Ok(self
            .state
            .lock()
            .map_err(|_| Error::Invalid("store lock"))?
            .resolve(scope, at)?
            .map(|target| Stat { target }))
    }
    async fn chunks(&self, scope: &Scope, at: &Path, cursor: Cursor) -> Result<ChunkPage> {
        let state = self
            .state
            .lock()
            .map_err(|_| Error::Invalid("store lock"))?;
        let target = state.resolve(scope, at)?.ok_or(Error::Missing)?;
        let object = state
            .objects
            .get(&target.object().id())
            .ok_or(Error::Missing)?;
        chunk_page(target.object(), &object.chunks, cursor)
    }
    async fn read(
        &self,
        scope: &Scope,
        at: &Path,
        range: std::ops::Range<u64>,
    ) -> Result<ByteStream> {
        let state = self
            .state
            .lock()
            .map_err(|_| Error::Invalid("store lock"))?;
        let target = state.resolve(scope, at)?.ok_or(Error::Missing)?;
        let bytes = state.load(target)?;
        if range.start > range.end || range.end > bytes.len() as u64 {
            return Err(Error::Invalid("read range"));
        }
        let stored = state
            .objects
            .get(&target.object().id())
            .ok_or(Error::Missing)?;
        let mut chunks = Vec::new();
        let mut offset = 0u64;
        for chunk in &stored.chunks {
            let end = offset + chunk.data_len;
            if offset < range.end && end > range.start {
                chunks.push(
                    bytes.slice(offset.max(range.start) as usize..end.min(range.end) as usize),
                );
            }
            offset = end;
        }
        let scope = scope.clone();
        let pin = at.pin.clone();
        let store = self.clone();
        let stream = futures::stream::try_unfold(
            (chunks.into_iter(), store, scope, pin),
            |(mut chunks, store, scope, pin)| async move {
                let Some(bytes) = chunks.next() else {
                    return Ok(None);
                };
                {
                    let state = store
                        .state
                        .lock()
                        .map_err(|_| Error::Invalid("store lock"))?;
                    state.check(&scope)?;
                    if state
                        .pins
                        .get(&pin)
                        .is_none_or(|value| !readable(&scope, &pin, value))
                    {
                        return Err(Error::Denied);
                    }
                }
                Ok(Some((bytes, (chunks, store, scope, pin))))
            },
        );
        Ok(ByteStream {
            object: target.object(),
            bytes: Box::pin(stream),
        })
    }
    async fn upload(
        &self,
        scope: &Scope,
        object: ContentRef,
        pin: Option<PinTarget>,
    ) -> Result<UploadSession> {
        let local = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| Error::Invalid("store lock"))?;
            state.check(scope)?;
            match scope {
                Scope::Owner if pin.is_some() => {}
                Scope::Work { closure, .. } if pin.is_none() && closure.contains(&object) => {}
                _ => return Err(Error::Denied),
            }
            let own = match scope {
                Scope::Work { reservation, .. } => state
                    .work
                    .get(reservation)
                    .and_then(|work| work.staged.get(&object.id()))
                    .map(|stored| checked_bytes(stored, object))
                    .transpose()?
                    .is_some(),
                _ => false,
            };
            if own || state.present(scope, object)? {
                if let Some(pin) = pin {
                    state.change_pin(
                        pin.name,
                        Some(PinValue {
                            target: Target::Object(object),
                            policy: pin.policy,
                            expires: None,
                        }),
                    )?;
                    self.changed.notify_waiters();
                }
                return Ok(UploadSession::present(object));
            }
            // Keep the progress check and reservation/allocation in one critical
            // section: a completed concurrent upload must not allocate twice.
            self.session(&mut state, scope, object, pin)?
        };
        Ok(UploadSession::local(object, local))
    }
    async fn acquire(
        &self,
        scope: &Scope,
        source: Source,
        expect: Option<ContentRef>,
        pin: PinTarget,
    ) -> Result<Acquisition> {
        if !matches!(scope, Scope::Owner) {
            return Err(Error::Denied);
        }
        super::acquire::memory(self, source, expect, pin).await
    }
    async fn set_pin(
        &self,
        scope: &Scope,
        name: &PinName,
        expected: Option<&PinValue>,
        new: Option<PinValue>,
    ) -> Result<()> {
        if !matches!(scope, Scope::Owner) {
            return Err(Error::Denied);
        }
        PinName::new(name.as_str().to_owned())?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::Invalid("store lock"))?;
        if state.pins.get(name).filter(|pin| live(pin)) != expected {
            return Err(Error::Conflict);
        }
        if let Some(value) = &new {
            state.walk(value.target)?;
            state.load(value.target)?;
        }
        state.change_pin(name.clone(), new)?;
        self.changed.notify_waiters();
        Ok(())
    }
    async fn pins(&self, scope: &Scope, prefix: &str, cursor: Cursor) -> Result<PinPage> {
        let state = self
            .state
            .lock()
            .map_err(|_| Error::Invalid("store lock"))?;
        state.check(scope)?;
        if cursor.offset != 0 && cursor.generation != state.generation {
            return Err(Error::Conflict);
        }
        let visible: Vec<_> = state
            .pins
            .iter()
            .filter(|(name, pin)| {
                name.as_str().starts_with(prefix) && metadata_readable(scope, name, pin)
            })
            .collect();
        let start = usize::try_from(cursor.offset).map_err(|_| Error::Invalid("pin cursor"))?;
        if start > visible.len() {
            return Err(Error::Invalid("pin cursor"));
        }
        let mut pins = Vec::new();
        let mut encoded = hellas_rpc::pb::content::ListPinsResponse {
            pins: Vec::new(),
            next: Some(super::wire::cursor(Cursor {
                offset: u64::MAX,
                generation: u64::MAX,
                object: None,
            })),
            cursor: Some(super::wire::cursor(Cursor {
                generation: state.generation,
                ..Default::default()
            })),
        }
        .encoded_len();
        for (name, pin) in &visible[start..] {
            let item = hellas_rpc::pb::content::ListPinsResponse {
                pins: vec![super::wire::pin(name, pin)],
                ..Default::default()
            }
            .encoded_len();
            if encoded + item > body_limit() {
                break;
            }
            encoded += item;
            pins.push(((*name).clone(), (*pin).clone()));
        }
        let end = start + pins.len();
        let current = Cursor {
            generation: state.generation,
            ..Default::default()
        };
        Ok(PinPage {
            pins,
            next: (end < visible.len()).then_some(Cursor {
                offset: end as u64,
                ..current
            }),
            cursor: current,
        })
    }
    async fn watch(&self, scope: &Scope, prefix: &str, from: Cursor) -> Result<PinEvents> {
        self.state
            .lock()
            .map_err(|_| Error::Invalid("store lock"))?
            .check(scope)?;
        let store = self.clone();
        let scope = scope.clone();
        let prefix = prefix.to_owned();
        Ok(Box::pin(futures::stream::unfold(
            (store, scope, prefix, Some(from.generation)),
            |(store, scope, prefix, seen)| async move {
                let mut seen = seen?;
                loop {
                    let wake = store.changed.clone().notified_owned();
                    tokio::pin!(wake);
                    wake.as_mut().enable();
                    let next = {
                        let state = store.state.lock().unwrap();
                        if let Err(error) = state.check(&scope) {
                            return Some((Err(error), (store.clone(), scope, prefix, None)));
                        }
                        let oldest =
                            state
                                .events
                                .front()
                                .map_or(state.generation, |(event, _, _)| match event {
                                    PinEvent::Set { cursor, .. } | PinEvent::Resync { cursor } => {
                                        cursor.generation.saturating_sub(1)
                                    }
                                });
                        if seen < oldest || seen > state.generation {
                            seen = state.generation;
                            Some(PinEvent::Resync {
                                cursor: Cursor {
                                    generation: seen,
                                    ..Default::default()
                                },
                            })
                        } else {
                            let mut next = None;
                            for (event, old, _) in &state.events {
                                let PinEvent::Set {
                                    cursor,
                                    name,
                                    value,
                                } = event
                                else {
                                    continue;
                                };
                                if cursor.generation <= seen {
                                    continue;
                                }
                                seen = cursor.generation;
                                if !name.as_str().starts_with(&prefix) {
                                    continue;
                                }
                                let current = state.pins.get(name);
                                if current == value.as_ref()
                                    && current
                                        .is_some_and(|pin| metadata_readable(&scope, name, pin))
                                {
                                    next = Some(event.clone());
                                    break;
                                }
                                let formerly_visible = old
                                    .as_ref()
                                    .is_some_and(|old| metadata_readable(&scope, name, old))
                                    || value.as_ref().is_some_and(|value| {
                                        metadata_readable(&scope, name, value)
                                    });
                                if formerly_visible {
                                    // A replay must not disclose a pin's old target after its
                                    // authority changes. Resync carries no private name or value.
                                    seen = state.generation;
                                    next = Some(PinEvent::Resync {
                                        cursor: Cursor {
                                            generation: seen,
                                            ..Default::default()
                                        },
                                    });
                                    break;
                                }
                            }
                            next
                        }
                    };
                    if let Some(next) = next {
                        return Some((Ok(next), (store, scope, prefix, Some(seen))));
                    }
                    wake.await;
                }
            },
        )))
    }
    async fn collect(&self, scope: &Scope) -> Result<Collected> {
        if !matches!(scope, Scope::Owner) {
            return Err(Error::Denied);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::Invalid("store lock"))?;
        let mut reached = BTreeSet::new();
        for pin in state.pins.values().filter(|pin| live(pin)) {
            reached.extend(state.walk(pin.target)?);
        }
        let mut collected = Collected::default();
        state.objects.retain(|id, object| {
            if reached.contains(id) {
                return true;
            }
            collected.objects += 1;
            collected.bytes += object.bytes.len() as u64;
            false
        });
        Ok(collected)
    }
}
