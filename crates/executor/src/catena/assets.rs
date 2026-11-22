use catena_lang::{
    codegen::GpuDialect,
    runtime::{MemOwn, MemRef},
};
use hellas_rpc::ContentRef;
use hellas_store::content::VerifiedReader;
use std::{collections::BTreeMap, io::Read, sync::Arc, time::Instant};
use tokio::sync::Mutex;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// One continuous region of a verified file in a packed GPU allocation.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Span {
    start: u64,
    end: u64,
    device: u64,
}
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Layout {
    spans: Vec<Span>,
    bytes: u64,
}
impl Layout {
    fn new(object: ContentRef, mut ranges: Vec<(u64, u64)>) -> Result<Self> {
        ranges.sort_unstable();
        let mut spans: Vec<Span> = Vec::new();
        for (start, len) in ranges {
            let end = start
                .checked_add(len)
                .filter(|&end| end <= object.bytes())
                .ok_or("asset view exceeds object")?;
            if len == 0 {
                continue;
            }
            if let Some(last) = spans.last_mut()
                && start <= last.end
            {
                last.end = last.end.max(end);
            } else {
                spans.push(Span {
                    start,
                    end,
                    device: 0,
                });
            }
        }
        let mut bytes = 0u64;
        for span in &mut spans {
            // Keep the original address alignment of all subviews, including overlapping tensors.
            let padding = span.start.wrapping_sub(bytes) % 256;
            span.device = bytes.checked_add(padding).ok_or("asset layout overflow")?;
            bytes = span
                .device
                .checked_add(span.end - span.start)
                .ok_or("asset layout overflow")?;
        }
        let bytes = bytes
            .max(1)
            .checked_next_multiple_of(2)
            .ok_or("asset layout overflow")?;
        Ok(Self { spans, bytes })
    }
}

pub struct Resident {
    memory: MemOwn,
    layout: Layout,
    object: ContentRef,
}
// Device allocations are process-wide device addresses. The owner never moves
// its allocation out, all public access borrows it, and Arc pins outlive IPC calls.
unsafe impl Send for Resident {}
unsafe impl Sync for Resident {}
impl Resident {
    pub fn view(&self, offset: u64, bytes: u64) -> Result<MemRef<'_>> {
        if offset
            .checked_add(bytes)
            .is_none_or(|end| end > self.object.bytes())
        {
            return Err("asset view exceeds object".into());
        }
        let device = if bytes == 0 {
            0
        } else {
            let index = self.layout.spans.partition_point(|span| span.end <= offset);
            let span = self
                .layout
                .spans
                .get(index)
                .filter(|span| {
                    span.start <= offset
                        && offset.checked_add(bytes).is_some_and(|end| end <= span.end)
                })
                .ok_or("asset view outside resident ranges")?;
            span.device + (offset - span.start)
        };
        let offset = usize::try_from(device)?;
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
    entries: BTreeMap<(ContentRef, Layout), (Arc<Resident>, u64)>,
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
        self.pin_for_job(
            reader,
            object,
            vec![(0, object.bytes())],
            &super::Cancellation::default(),
            None,
        )
    }
    pub(crate) fn pin_for_job(
        &self,
        reader: VerifiedReader,
        object: ContentRef,
        ranges: Vec<(u64, u64)>,
        cancel: &super::Cancellation,
        deadline: Option<Instant>,
    ) -> Result<Arc<Resident>> {
        let mut state = cancel
            .block_on(deadline, self.state.lock())
            .ok_or("asset pin timed out or cancelled")?;
        state.clock += 1;
        let clock = state.clock;
        let layout = Layout::new(object, ranges)?;
        let key = (object, layout);
        if let Some((resident, used)) = state.entries.get_mut(&key) {
            *used = clock;
            return Ok(resident.clone());
        }
        let padded = key.1.bytes;
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
                .map(|(id, _)| id.clone())
                .ok_or("resident capacity pinned by running jobs")?;
            let (old, _) = state.entries.remove(&victim).unwrap();
            state.used -= old.memory.byte_len();
        }
        let words = packed_words(reader, object, &key.1)?;
        let resident = Arc::new(Resident {
            memory: MemOwn::from_u16_slice(&words, self.dialect)?,
            layout: key.1.clone(),
            object,
        });
        state.used += padded;
        state.entries.insert(key, (resident.clone(), clock));
        Ok(resident)
    }
}

/// Hash the same bytes we copy, including gaps, so a changed lower file never supplies a verified view.
fn packed_words(
    mut reader: VerifiedReader,
    object: ContentRef,
    layout: &Layout,
) -> Result<Vec<u16>> {
    let count = usize::try_from(layout.bytes / 2)?;
    let mut words = Vec::new();
    words.try_reserve_exact(count)?;
    words.resize(count, 0u16);
    // All u16 bit patterns are valid and the allocation outlives this exclusive byte slice.
    let output =
        unsafe { std::slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), count * 2) };
    let mut hasher = hellas_xet::XetFileHasher::new();
    let mut buffer = vec![0; 1 << 20];
    let mut position = 0;
    while position < object.bytes() {
        let len = (object.bytes() - position).min(buffer.len() as u64) as usize;
        let block = &mut buffer[..len];
        reader.read_exact(block)?;
        hasher.update(block);
        let end = position + len as u64;
        let first = layout.spans.partition_point(|span| span.end <= position);
        for span in layout.spans[first..]
            .iter()
            .take_while(|span| span.start < end)
        {
            let from = span.start.max(position);
            let through = span.end.min(end);
            let offset = (span.device + (from - span.start)) as usize;
            output[offset..offset + (through - from) as usize]
                .copy_from_slice(&block[(from - position) as usize..(through - position) as usize]);
        }
        position = end;
    }
    if reader.read(&mut [0])? != 0 || hasher.finalize() != object.id().digest() {
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
    use std::time::Duration;
    fn reader(bytes: &[u8]) -> VerifiedReader {
        VerifiedReader::Memory(std::io::Cursor::new(bytes.to_vec().into()))
    }
    fn asset_words(reader: VerifiedReader, object: ContentRef) -> Result<Vec<u16>> {
        packed_words(
            reader,
            object,
            &Layout::new(object, vec![(0, object.bytes())])?,
        )
    }
    #[test]
    fn packed_ranges_merge_aliases_preserve_alignment_and_verify_gaps() {
        let bytes = (0u8..=255).cycle().take(3000).collect::<Vec<_>>();
        let object = ContentRef::for_bytes(&bytes);
        let layout = Layout::new(object, vec![(258, 6), (260, 8), (258, 6), (2050, 3)]).unwrap();
        assert_eq!(layout.spans.len(), 2);
        assert_eq!(layout.bytes, 262);
        let words = packed_words(reader(&bytes), object, &layout).unwrap();
        let packed: Vec<u8> = words.into_iter().flat_map(u16::to_ne_bytes).collect();
        assert_eq!(&packed[2..12], &bytes[258..268]);
        assert_eq!(&packed[258..261], &bytes[2050..2053]);
        assert!(packed[12..258].iter().all(|&x| x == 0));
        let mut wrong = bytes;
        wrong[1000] ^= 1;
        assert!(packed_words(reader(&wrong), object, &layout).is_err());
        assert!(Layout::new(object, vec![(3000, 1)]).is_err());
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
        assert!(asset_words(handle, object).is_err());
        node.close().await;
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
                vec![(0, object.bytes())],
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
            let result = assets.pin_for_job(
                reader(b"not accessed"),
                object,
                vec![(0, object.bytes())],
                &cancel,
                None,
            );
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
