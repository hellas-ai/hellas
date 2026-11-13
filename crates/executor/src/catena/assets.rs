use catena_lang::{
    codegen::GpuDialect,
    runtime::{MemOwn, MemRef},
};
use hellas_rpc::{ContentId, ContentRef};
use hellas_store::content::VerifiedReader;
use std::{collections::BTreeMap, io::Read, sync::Arc, time::Instant};
use tokio::sync::Mutex;

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
        let mut state = cancel
            .block_on(deadline, self.state.lock())
            .ok_or("asset pin timed out or cancelled")?;
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
        let mut memory = MemOwn::allocate(usize::try_from(padded)?, self.dialect)?;
        stream_asset(reader, object, |offset, bytes| {
            memory.write_bytes(offset, bytes)?;
            Ok(())
        })?;
        let resident = Arc::new(Resident {
            memory,
            bytes: object.bytes(),
        });
        state.used += padded;
        state.entries.insert(object.id(), (resident.clone(), clock));
        Ok(resident)
    }
}

// Model size does not change the host staging allocation. Device memory stays
// private until the bytes copied into it pass the content and length checks.
const ASSET_STAGING_BYTES: usize = 8 << 20;

fn stream_asset(
    mut reader: impl Read,
    object: ContentRef,
    mut write: impl FnMut(u64, &[u8]) -> Result<()>,
) -> Result<()> {
    let mut staging = vec![0; object.bytes().min(ASSET_STAGING_BYTES as u64) as usize];
    let mut hasher = hellas_xet::XetFileHasher::new();
    let mut offset = 0;
    while offset < object.bytes() {
        let count = (object.bytes() - offset).min(staging.len() as u64) as usize;
        let bytes = &mut staging[..count];
        reader.read_exact(bytes)?;
        hasher.update(bytes);
        write(offset, bytes)?;
        offset += count as u64;
    }
    if reader.read(&mut [0])? != 0
        || ContentId::from_bytes(hasher.finalize().into_bytes()) != object.id()
    {
        return Err("verified asset changed while reading".into());
    }
    if !object.bytes().is_multiple_of(2) {
        write(object.bytes(), &[0])?;
    }
    Ok(())
}

pub fn upload(bytes: &[u8], dialect: GpuDialect) -> Result<MemOwn> {
    Ok(MemOwn::from_bytes(bytes, dialect)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    fn reader(bytes: &[u8]) -> VerifiedReader {
        VerifiedReader::Memory(std::io::Cursor::new(bytes.to_vec().into()))
    }
    #[test]
    fn ram_assets_preserve_exact_bytes_and_private_padding() {
        let bytes = [0x11, 0x22, 0x33];
        let object = ContentRef::for_bytes(&bytes);
        let mut uploaded = Vec::new();
        stream_asset(reader(&bytes), object, |offset, chunk| {
            assert_eq!(offset as usize, uploaded.len());
            uploaded.extend_from_slice(chunk);
            Ok(())
        })
        .unwrap();
        assert_eq!(uploaded, [0x11, 0x22, 0x33, 0]);
        assert!(
            stream_asset(reader(&bytes), ContentRef::new(object.id(), 4), |_, _| Ok(
                ()
            ))
            .is_err()
        );
        assert!(
            stream_asset(
                reader(&bytes),
                ContentRef::for_bytes(&bytes[..2]),
                |_, _| Ok(())
            )
            .is_err()
        );
        assert!(stream_asset(reader(&[0x44, 0x22, 0x33]), object, |_, _| Ok(())).is_err());
    }
    #[test]
    fn large_assets_stream_with_bounded_reads_and_uploads() {
        struct BoundedReader<'a>(&'a [u8]);
        impl Read for BoundedReader<'_> {
            fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
                assert!(bytes.len() <= ASSET_STAGING_BYTES);
                self.0.read(bytes)
            }
        }
        let bytes = (0..ASSET_STAGING_BYTES * 2 + 17)
            .map(|i| i as u8)
            .collect::<Vec<_>>();
        let mut uploaded = 0;
        stream_asset(
            BoundedReader(&bytes),
            ContentRef::for_bytes(&bytes),
            |offset, chunk| {
                assert_eq!(offset, uploaded);
                assert!(chunk.len() <= ASSET_STAGING_BYTES);
                if offset < bytes.len() as u64 {
                    assert_eq!(
                        chunk,
                        &bytes[offset as usize..offset as usize + chunk.len()]
                    );
                } else {
                    assert_eq!(chunk, [0]);
                }
                uploaded += chunk.len() as u64;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(uploaded, bytes.len() as u64 + 1);
        assert!(
            stream_asset(reader(b"x"), ContentRef::for_bytes(b"x"), |_, _| Err(
                "upload failed".into()
            ))
            .is_err()
        );
    }

    #[tokio::test]
    async fn file_mutation_after_verified_open_is_rejected_before_residency() {
        use hellas_store::content::{
            ContentStore, DiskStore, IndexMode, LocalStore, Reservations, Scope,
        };
        let root = tempfile::tempdir().unwrap();
        let lower = root.path().join("lower");
        std::fs::create_dir(&lower).unwrap();
        let path = lower.join("weights");
        std::fs::write(&path, b"original").unwrap();
        let node = DiskStore::open(
            hellas_private::StoreLocation::for_test(root.path()).child("upper"),
            vec![lower],
            IndexMode::Resume,
            None,
            Reservations::ram(1 << 20),
            false,
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
        assert!(stream_asset(handle, object, |_, _| Ok(())).is_err());
        node.close().await;
    }

    #[test]
    #[ignore = "requires a HIP device"]
    fn hip_uploads_preserve_bytes_and_enforce_ranges() {
        let dialect = GpuDialect::Hip;
        let mut memory = MemOwn::from_bytes(&[1, 2, 3, 4], dialect).unwrap();
        memory.write_bytes(1, &[5, 6]).unwrap();
        memory.write_bytes(4, &[]).unwrap();
        assert!(memory.write_bytes(4, &[7]).is_err());
        assert!(memory.write_bytes(u64::MAX, &[7]).is_err());
        assert!(memory.write_bytes(5, &[]).is_err());
        assert_eq!(memory.try_to_u16_vec().unwrap(), [0x0501, 0x0406]);
        let bytes = [0x11, 0x22, 0x33];
        let assets = Assets::new(4, dialect);
        let resident = assets
            .pin(reader(&bytes), ContentRef::for_bytes(&bytes))
            .unwrap();
        assert_eq!(
            resident.memory().try_to_u16_vec().unwrap(),
            [0x2211, 0x0033]
        );
        assert_eq!(upload(&bytes, dialect).unwrap().byte_len(), 3);
    }

    #[test]
    fn resident_pin_lock_wait_obeys_cancellation_and_deadline() {
        let assets = Assets::new(0, GpuDialect::Hip);
        let held = assets.state.try_lock().unwrap();
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
        }
        let pin = |cancel: super::super::Cancellation| {
            let result = assets.pin_for_job(reader(b"not accessed"), object, &cancel, None);
            result.err().unwrap().to_string()
        };
        std::thread::scope(|scope| {
            // With the lock held throughout, only cancellation ends this wait.
            let cancel = super::super::Cancellation::default();
            let waiter = scope.spawn({
                let cancel = cancel.clone();
                move || pin(cancel)
            });
            cancel.cancel();
            assert!(waiter.join().unwrap().contains("timed out or cancelled"));
            // Releasing the lock wakes a waiter with no deadline; it then
            // reaches the capacity check.
            let waiter = scope.spawn(move || pin(Default::default()));
            drop(held);
            assert!(waiter.join().unwrap().contains("exceeds resident capacity"));
        });
    }
}
