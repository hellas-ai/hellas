use catena_lang::{
    codegen::GpuDialect,
    runtime::{MemOwn, MemRef, RuntimeModule},
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
            .checked_next_multiple_of(8)
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
        let memory = allocate_asset(usize::try_from(padded)?, self.dialect)?;
        let (mut runtime, pid) = super::pool::spawn(cancel.clone(), self.dialect)?;
        let watchdog = super::process::Watchdog::with_cancel(
            pid,
            deadline.map(|end| end.saturating_duration_since(Instant::now())),
            cancel.clone(),
        );
        let result = (|| {
            let artifact = runtime.load(asset_program(self.dialect)?)?;
            stream_asset(reader, object, |offset, words| {
                let chunk = MemOwn::from_u64_slice(words, self.dialect)?;
                // Both allocations stay parent-owned. Returning an owner through
                // SafeRuntime would copy the entire destination on every chunk.
                artifact.exec_values(
                    "hellas.asset.write",
                    vec![
                        chunk.as_ref().into(),
                        (offset / 8).into(),
                        memory.as_ref().into(),
                        (words.len() as u64).into(),
                    ],
                )?;
                Ok(())
            })
        })();
        drop(runtime);
        if watchdog.finish() || cancel.is_cancelled() {
            return Err("asset upload timed out or cancelled".into());
        }
        result?;
        let resident = Arc::new(Resident {
            memory,
            bytes: object.bytes(),
        });
        state.used += padded;
        state.entries.insert(object.id(), (resident.clone(), clock));
        Ok(resident)
    }
}

fn allocate_asset(bytes: usize, dialect: GpuDialect) -> Result<MemOwn> {
    if bytes == 0 {
        return Ok(MemOwn::from_u64_slice(&[], dialect)?);
    }
    if bytes > isize::MAX as usize {
        return Err("asset length exceeds host address space".into());
    }
    // Plain Catena exposes only allocation-with-copy in Rust. A read-only
    // anonymous mapping supplies shared zero pages without touching a full host
    // buffer. Keep its fallible allocation API; generated allocation aborts on
    // GPU OOM. Drop the mapping immediately after the synchronous copy.
    let zeroes = memmap2::MmapMut::map_anon(bytes)?.make_read_only()?;
    // Anonymous mappings are page-aligned, initialized, and immutable. Asset
    // lengths have already been rounded to whole u64 words.
    let words = unsafe { std::slice::from_raw_parts(zeroes.as_ptr().cast::<u64>(), bytes / 8) };
    Ok(MemOwn::from_u64_slice(words, dialect)?)
}

fn asset_program(dialect: GpuDialect) -> Result<RuntimeModule> {
    let sources = catena_lang::stdlib::core_sources()
        .chain([include_str!("assets.hex")])
        .map(str::to_owned)
        .collect::<Vec<_>>();
    super::compile::compile_sources(&sources, dialect)
}

// Only these initialized words are hashed and copied. The final device owner
// stays private until the exact length and content hash pass; later changes to
// the source file cannot change it. Xet retains metadata per chunk.
const ASSET_STAGING_BYTES: usize = 8 << 20;

#[cfg(test)]
fn word_bytes(words: &[u64]) -> &[u8] {
    // Every bit pattern is valid, and this borrows the initialized word storage.
    unsafe { std::slice::from_raw_parts(words.as_ptr().cast(), std::mem::size_of_val(words)) }
}

fn stream_asset(
    mut reader: impl Read,
    object: ContentRef,
    mut write: impl FnMut(u64, &[u64]) -> Result<()>,
) -> Result<()> {
    let mut staging =
        vec![0u64; object.bytes().min(ASSET_STAGING_BYTES as u64).div_ceil(8) as usize];
    let mut hasher = hellas_xet::XetFileHasher::new();
    let mut offset = 0;
    while offset < object.bytes() {
        let count = (object.bytes() - offset).min(ASSET_STAGING_BYTES as u64) as usize;
        let words = &mut staging[..count.div_ceil(8)];
        // Clear the final physical word so bytes outside the logical object are zero.
        *words.last_mut().unwrap() = 0;
        let bytes =
            unsafe { std::slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), count) };
        reader.read_exact(bytes)?;
        hasher.update(bytes);
        write(offset, words)?;
        offset += count as u64;
    }
    if reader.read(&mut [0])? != 0
        || ContentId::from_bytes(hasher.finalize().into_bytes()) != object.id()
    {
        return Err("verified asset changed while reading".into());
    }
    Ok(())
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
    #[test]
    fn ram_assets_preserve_exact_bytes_and_private_padding() {
        let bytes = [0x11, 0x22, 0x33];
        let object = ContentRef::for_bytes(&bytes);
        let mut uploaded = Vec::new();
        stream_asset(reader(&bytes), object, |offset, words| {
            let chunk = word_bytes(words);
            assert_eq!(offset as usize, uploaded.len());
            uploaded.extend_from_slice(chunk);
            Ok(())
        })
        .unwrap();
        assert_eq!(uploaded, [0x11, 0x22, 0x33, 0, 0, 0, 0, 0]);
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
            |offset, words| {
                let chunk = word_bytes(words);
                assert_eq!(offset, uploaded);
                assert!(chunk.len() <= ASSET_STAGING_BYTES);
                let count = chunk.len().min(bytes.len() - offset as usize);
                assert_eq!(
                    &chunk[..count],
                    &bytes[offset as usize..offset as usize + count]
                );
                assert!(chunk[count..].iter().all(|byte| *byte == 0));
                uploaded += chunk.len() as u64;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(uploaded, (bytes.len() as u64).next_multiple_of(8));
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
    #[cfg(target_os = "linux")]
    fn upload_initializes_word_padding_without_changing_logical_length() {
        const CHILD: &str = "HELLAS_UPLOAD_PADDING_TEST_LIBRARY";
        if let Some(path) = std::env::var_os(CHILD) {
            let library = unsafe { libloading::Library::new(path) }.unwrap();
            let allocated =
                unsafe { library.get::<unsafe extern "C" fn() -> usize>(b"allocation_size\0") }
                    .unwrap();
            for bytes in [&[][..], &[0x11, 0x22, 0x33], &[0x11, 0x22], &[0x11]] {
                let memory = upload(bytes, GpuDialect::Hip).unwrap();
                assert_eq!(memory.byte_len(), bytes.len() as u64);
                if bytes.is_empty() {
                    assert!(memory.as_ptr().is_null());
                    continue;
                }
                let physical = unsafe { allocated() };
                assert_eq!(physical, bytes.len().next_multiple_of(2));
                // The child loads the host-memory HIP fixture, never a GPU runtime.
                let actual =
                    unsafe { std::slice::from_raw_parts(memory.as_ptr().cast::<u8>(), physical) };
                assert_eq!(&actual[..bytes.len()], bytes);
                assert!(actual[bytes.len()..].iter().all(|byte| *byte == 0));
            }
            for bytes in [0, 8, 24] {
                let memory = allocate_asset(bytes, GpuDialect::Hip).unwrap();
                assert_eq!(memory.byte_len(), bytes as u64);
                assert_eq!(memory.try_to_u64_vec().unwrap(), vec![0; bytes / 8]);
            }
            let fail =
                unsafe { library.get::<unsafe extern "C" fn()>(b"fail_allocations\0") }.unwrap();
            unsafe { fail() };
            assert!(allocate_asset(8, GpuDialect::Hip).is_err());
            return;
        }
        use std::{
            io::Write,
            process::{Command, Stdio},
        };
        let directory = tempfile::tempdir().unwrap();
        let library = directory.path().join("libamdhip64.so");
        let mut compiler = Command::new("cc")
            .args(["-shared", "-fPIC", "-x", "c", "-", "-o"])
            .arg(&library)
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        compiler
            .stdin
            .take()
            .unwrap()
            .write_all(
                br#"
#include <stdlib.h>
#include <string.h>
static size_t allocated;
static int fail;
void fail_allocations(void) { fail = 1; }
size_t allocation_size(void) { return allocated; }
int hipMalloc(void **pointer, size_t bytes) {
    if (fail) return 2;
    *pointer = malloc(bytes);
    if (!*pointer) return 1;
    allocated = bytes;
    memset(*pointer, 0xa5, bytes);
    return 0;
}
int hipMemcpy(void *destination, const void *source, size_t bytes, int kind) {
    (void)kind;
    memcpy(destination, source, bytes);
    return 0;
}
int hipFree(void *pointer) { free(pointer); return 0; }
"#,
            )
            .unwrap();
        assert!(compiler.wait().unwrap().success());
        assert!(
            Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg(
                    concat!(
                        module_path!(),
                        "::upload_initializes_word_padding_without_changing_logical_length"
                    )
                    .trim_start_matches("hellas_executor::")
                )
                .arg("--nocapture")
                .env(CHILD, &library)
                .env("LD_LIBRARY_PATH", directory.path())
                .status()
                .unwrap()
                .success()
        );
    }

    #[test]
    fn upload_program_compiles_for_both_dialects() {
        for dialect in [GpuDialect::Hip, GpuDialect::Cuda] {
            let module = asset_program(dialect).unwrap();
            let entry = module
                .functions
                .iter()
                .find(|f| f.source_name == "hellas.asset.write")
                .unwrap();
            use catena_lang::runtime::ValueKind::{MemRef, U64};
            assert_eq!(entry.inputs, [MemRef, U64, MemRef, U64]);
            assert_eq!(entry.outputs, [U64]);
        }
    }

    #[test]
    #[ignore = "requires a HIP device"]
    fn hip_uploads_preserve_bytes_and_enforce_ranges() {
        let dialect = GpuDialect::Hip;
        // Cross multiple transfers, preserve every byte pattern, and exercise padding.
        let bytes = (0..ASSET_STAGING_BYTES * 2 + 17)
            .map(|i| i as u8)
            .collect::<Vec<_>>();
        let assets = Assets::new((bytes.len() as u64).next_multiple_of(8), dialect);
        let resident = assets
            .pin(reader(&bytes), ContentRef::for_bytes(&bytes))
            .unwrap();
        let words = resident.memory().try_to_u64_vec().unwrap();
        let actual = word_bytes(&words);
        assert_eq!(&actual[..bytes.len()], bytes);
        assert!(actual[bytes.len()..].iter().all(|b| *b == 0));
        assert!(resident.view(bytes.len() as u64, 1).is_err());
        assert!(resident.view(u64::MAX, 2).is_err());
        assert_eq!(upload(&bytes[..3], dialect).unwrap().byte_len(), 3);
        // A failed hash must never publish a partially initialized resident.
        let corrupt = Assets::new(8, dialect);
        assert!(
            corrupt
                .pin(reader(b"bad"), ContentRef::for_bytes(b"yes"))
                .is_err()
        );
        assert!(corrupt.state.try_lock().unwrap().entries.is_empty());
        let empty = Assets::new(0, dialect)
            .pin(reader(b""), ContentRef::for_bytes(b""))
            .unwrap();
        assert_eq!(empty.memory().byte_len(), 0);
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
