use catena_lang::{
    codegen::GpuDialect,
    runtime::{MemOwn, MemRef},
};
use hellas_rpc::{ContentId, ContentRef};
use hellas_store::content::VerifiedReader;
use std::{
    collections::BTreeMap,
    io::Read,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct Resident {
    memory: MemOwn,
    bytes: u64,
}
// Device allocations are process-wide device addresses. The owner never moves
// its allocation out, all public access borrows it, and Arc pins outlive IPC calls.
unsafe impl Send for Resident {}
unsafe impl Sync for Resident {}
impl Resident {
    pub fn view(&self, offset: u64, bytes: u64) -> Result<MemRef<'_>> {
        if offset.checked_add(bytes).is_none_or(|end| end > self.bytes) {
            return Err("asset view exceeds object".into());
        }
        let offset = usize::try_from(offset)?;
        // The Arc pin owns this whole allocation, including every tensor view.
        Ok(unsafe {
            MemRef::from_raw_parts(
                self.memory.as_ptr().cast::<u8>().add(offset).cast(),
                bytes,
                self.memory.dialect(),
                self,
            )
        })
    }
    pub fn memory(&self) -> &MemOwn {
        &self.memory
    }
}

struct State {
    entries: BTreeMap<ContentId, (Arc<Resident>, u64)>,
    used: u64,
    clock: u64,
}
pub struct Assets {
    state: Mutex<State>,
    capacity: u64,
    dialect: GpuDialect,
}
impl Assets {
    pub fn new(capacity: u64, dialect: GpuDialect) -> Self {
        Self {
            state: Mutex::new(State {
                entries: BTreeMap::new(),
                used: 0,
                clock: 0,
            }),
            capacity,
            dialect,
        }
    }
    pub fn pin(&self, reader: VerifiedReader, object: ContentRef) -> Result<Arc<Resident>> {
        self.pin_for_job(reader, object, &super::Cancellation::default(), None)
    }
    pub(crate) fn pin_for_job(
        &self,
        reader: VerifiedReader,
        object: ContentRef,
        cancel: &super::Cancellation,
        deadline: Option<Instant>,
    ) -> Result<Arc<Resident>> {
        let mut state = loop {
            if cancel.is_cancelled() || deadline.is_some_and(|end| Instant::now() >= end) {
                return Err("asset pin timed out or cancelled".into());
            }
            match self.state.try_lock() {
                Ok(state) => break state,
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err("resident cache poisoned".into());
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::sleep(Duration::from_millis(2))
                }
            }
        };
        state.clock += 1;
        let clock = state.clock;
        if let Some((resident, used)) = state.entries.get_mut(&object.id()) {
            if resident.bytes != object.bytes() {
                return Err("asset length differs from resident object".into());
            }
            *used = clock;
            return Ok(resident.clone());
        }
        let padded = object
            .bytes()
            .checked_add(object.bytes() % 2)
            .ok_or("asset length overflow")?;
        if padded > self.capacity {
            return Err("asset exceeds resident capacity".into());
        }
        while state
            .used
            .checked_add(padded)
            .is_none_or(|n| n > self.capacity)
        {
            let victim = state
                .entries
                .iter()
                .filter(|(_, (owner, _))| Arc::strong_count(owner) == 1)
                .min_by_key(|(_, (_, used))| *used)
                .map(|(id, _)| *id)
                .ok_or("resident capacity pinned by running jobs")?;
            let (old, _) = state.entries.remove(&victim).unwrap();
            state.used -= old.memory.byte_len();
        }
        let words = asset_words(reader, object)?;
        let resident = Arc::new(Resident {
            memory: MemOwn::from_u16_slice(&words, self.dialect)?,
            bytes: object.bytes(),
        });
        state.used += padded;
        state.entries.insert(object.id(), (resident.clone(), clock));
        Ok(resident)
    }
}

fn asset_words(reader: VerifiedReader, object: ContentRef) -> Result<Vec<u16>> {
    let len = usize::try_from(object.bytes())?;
    let count = len.checked_add(1).ok_or("asset length overflow")? / 2;
    let mut words = Vec::new();
    words.try_reserve_exact(count)?;
    words.resize(count, 0u16);
    // Initialized u16 storage accepts arbitrary bytes; the final padding byte remains zero.
    let bytes = unsafe { std::slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), len) };
    let mut reader = reader;
    reader.read_exact(bytes)?;
    if reader.read(&mut [0])? != 0 || ContentRef::for_bytes(bytes) != object {
        return Err("verified asset changed while reading".into());
    }
    Ok(words)
}

pub fn upload(bytes: &[u8], dialect: GpuDialect) -> Result<MemOwn> {
    let mut words = Vec::new();
    words.try_reserve_exact(bytes.len().div_ceil(2))?;
    for pair in bytes.chunks(2) {
        words.push(u16::from_ne_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    let memory = MemOwn::from_u16_slice(&words, dialect)?;
    if bytes.len().is_multiple_of(2) {
        return Ok(memory);
    }
    // Input ownership has an exact byte length; its allocation may have one padding byte.
    let ptr = memory.as_ptr();
    let mut memory = std::mem::ManuallyDrop::new(memory);
    match unsafe { MemOwn::from_raw_parts(ptr, bytes.len() as u64, dialect) } {
        Ok(exact) => Ok(exact),
        Err(error) => {
            unsafe {
                std::mem::ManuallyDrop::drop(&mut memory);
            }
            Err(error.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn reader(bytes: &[u8]) -> VerifiedReader {
        VerifiedReader::Memory(std::io::Cursor::new(bytes.to_vec().into()))
    }
    #[test]
    fn ram_assets_preserve_exact_bytes_and_private_padding() {
        let bytes = [0x11, 0x22, 0x33];
        let object = ContentRef::for_bytes(&bytes);
        let words = asset_words(reader(&bytes), object).unwrap();
        assert_eq!(words.len(), 2);
        assert_eq!(words[0].to_ne_bytes(), [0x11, 0x22]);
        assert_eq!(words[1].to_ne_bytes(), [0x33, 0]);
        assert!(asset_words(reader(&bytes), ContentRef::new(object.id(), 4)).is_err());
        assert!(asset_words(reader(&[0x44, 0x22, 0x33]), object).is_err());
    }
    #[tokio::test]
    async fn file_mutation_after_verified_open_is_rejected_before_gpu_upload() {
        use hellas_store::content::{
            ContentStore, DiskStore, IndexMode, LocalStore, Reservations, Scope,
        };
        let root = tempfile::tempdir().unwrap();
        let lower = root.path().join("lower");
        std::fs::create_dir(&lower).unwrap();
        let path = lower.join("weights");
        std::fs::write(&path, b"original").unwrap();
        let node = DiskStore::open(
            root.path().join("upper"),
            vec![lower],
            IndexMode::Resume,
            None,
            Reservations::ram(1 << 20),
        )
        .await
        .unwrap();
        node.finish_recovery().await.unwrap();
        let object = ContentRef::for_bytes(b"original");
        let target = hellas_channel::content::object_pin(object).unwrap();
        node.set_pin(
            &Scope::Owner,
            &target.name,
            None,
            Some(hellas_store::content::PinValue {
                target: hellas_store::content::Target::Object(object),
                policy: target.policy,
                expires: None,
            }),
        )
        .await
        .unwrap();
        let handle = LocalStore::Disk(node.clone())
            .open_verified(&Scope::Owner, object, None)
            .await
            .unwrap()
            .unwrap();
        std::fs::write(&path, b"modified").unwrap();
        assert!(asset_words(handle, object).is_err());
        node.close().await;
    }

    #[test]
    fn resident_pin_lock_wait_obeys_cancellation_and_deadline() {
        let assets = Assets::new(0, GpuDialect::Hip);
        let _held = assets.state.lock().unwrap();
        let object = ContentRef::for_bytes(b"not accessed");
        for cancelled in [false, true] {
            let cancel = super::super::Cancellation::default();
            if cancelled {
                cancel.cancel();
            }
            let start = Instant::now();
            let result = assets.pin_for_job(
                reader(b"not accessed"),
                object,
                &cancel,
                Some(start + Duration::from_millis(20)),
            );
            assert!(
                result
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("timed out or cancelled")
            );
            assert!(start.elapsed() < Duration::from_millis(100));
        }
    }
}
