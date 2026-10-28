use catena_lang::{codegen::GpuDialect, runtime::MemOwn};
use libloading::Library;
use std::{
    ffi::{c_int, c_void},
    path::PathBuf,
    sync::OnceLock,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn runtime(dialect: GpuDialect) -> Result<&'static Library> {
    static HIP: OnceLock<Library> = OnceLock::new();
    static CUDA: OnceLock<Library> = OnceLock::new();
    let (slot, roots, directories, name): (_, &[&str], &[&str], _) = match dialect {
        GpuDialect::Hip => (&HIP, &["ROCM_PATH", "HIP_PATH"], &["lib"], "libamdhip64.so"),
        GpuDialect::Cuda => (
            &CUDA,
            &["CUDA_PATH", "CUDA_HOME"],
            &["lib64", "lib"],
            "libcudart.so",
        ),
    };
    if let Some(lib) = slot.get() {
        return Ok(lib);
    }
    // Match upstream's order so allocation, transfer and release use the same runtime.
    let mut paths = vec![PathBuf::from(name)];
    for root in roots.iter().filter_map(std::env::var_os) {
        for directory in directories {
            let path = PathBuf::from(&root).join(directory).join(name);
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
    }
    for path in paths {
        if let Ok(lib) = unsafe { Library::new(path) } {
            let _ = slot.set(lib);
            return Ok(slot.get().unwrap());
        }
    }
    Err(format!("cannot load {dialect:?} runtime").into())
}

/// Upstream exposes typed reads only; declared byte buffers can have odd lengths.
pub fn download(memory: &MemOwn) -> Result<Vec<u8>> {
    let len = usize::try_from(memory.byte_len())?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(len)?;
    bytes.resize(len, 0);
    if len != 0 {
        let lib = runtime(memory.dialect())?;
        let name: &[u8] = match memory.dialect() {
            GpuDialect::Hip => b"hipMemcpy\0",
            GpuDialect::Cuda => b"cudaMemcpy\0",
        };
        let copy = unsafe {
            lib.get::<unsafe extern "C" fn(*mut c_void, *const c_void, usize, c_int) -> c_int>(
                name,
            )?
        };
        let status = unsafe { copy(bytes.as_mut_ptr().cast(), memory.as_ptr(), len, 2) };
        if status != 0 {
            return Err(format!("GPU download failed with status {status}").into());
        }
    }
    Ok(bytes)
}

pub fn zeroed(bytes: u64, dialect: GpuDialect) -> Result<MemOwn> {
    let len = usize::try_from(bytes)?;
    let lib = runtime(dialect)?;
    let (alloc_name, clear_name, free_name): (&[u8], &[u8], &[u8]) = match dialect {
        GpuDialect::Hip => (b"hipMalloc\0", b"hipMemset\0", b"hipFree\0"),
        GpuDialect::Cuda => (b"cudaMalloc\0", b"cudaMemset\0", b"cudaFree\0"),
    };
    let alloc =
        unsafe { lib.get::<unsafe extern "C" fn(*mut *mut c_void, usize) -> c_int>(alloc_name)? };
    let clear =
        unsafe { lib.get::<unsafe extern "C" fn(*mut c_void, c_int, usize) -> c_int>(clear_name)? };
    let free = unsafe { lib.get::<unsafe extern "C" fn(*mut c_void) -> c_int>(free_name)? };
    let mut ptr = std::ptr::null_mut();
    let status = unsafe { alloc(&mut ptr, len) };
    if status != 0 {
        return Err(format!("GPU allocation failed with status {status}").into());
    }
    let status = unsafe { clear(ptr, 0, len) };
    if status != 0 {
        unsafe {
            free(ptr);
        }
        return Err(format!("GPU zero failed with status {status}").into());
    }
    match unsafe { MemOwn::from_raw_parts(ptr, bytes, dialect) } {
        Ok(memory) => Ok(memory),
        Err(e) => {
            unsafe {
                free(ptr);
            }
            Err(e.into())
        }
    }
}
