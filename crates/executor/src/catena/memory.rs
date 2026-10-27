use catena_lang::{codegen::GpuDialect, runtime::MemOwn};
use libloading::Library;
use std::{
    ffi::{c_int, c_void},
    path::PathBuf,
    sync::OnceLock,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn hip() -> Result<&'static Library> {
    static LIB: OnceLock<Library> = OnceLock::new();
    if let Some(lib) = LIB.get() {
        return Ok(lib);
    }
    let mut paths: Vec<PathBuf> = ["ROCM_PATH", "HIP_PATH"]
        .into_iter()
        .filter_map(std::env::var_os)
        .map(|root| PathBuf::from(root).join("lib/libamdhip64.so"))
        .collect();
    paths.push("libamdhip64.so".into());
    for path in paths {
        if let Ok(lib) = unsafe { Library::new(path) } {
            let _ = LIB.set(lib);
            return Ok(LIB.get().unwrap());
        }
    }
    Err("cannot load HIP runtime".into())
}

/// Upstream exposes typed reads only; declared byte buffers can have odd lengths.
pub fn download(memory: &MemOwn) -> Result<Vec<u8>> {
    let len = usize::try_from(memory.byte_len())?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(len)?;
    bytes.resize(len, 0);
    if len != 0 {
        let lib = hip()?;
        let copy = unsafe {
            lib.get::<unsafe extern "C" fn(*mut c_void, *const c_void, usize, c_int) -> c_int>(
                b"hipMemcpy\0",
            )?
        };
        let status = unsafe { copy(bytes.as_mut_ptr().cast(), memory.as_ptr(), len, 2) };
        if status != 0 {
            return Err(format!("HIP download failed with status {status}").into());
        }
    }
    Ok(bytes)
}

pub fn zeroed(bytes: u64) -> Result<MemOwn> {
    let len = usize::try_from(bytes)?;
    let lib = hip()?;
    let alloc = unsafe {
        lib.get::<unsafe extern "C" fn(*mut *mut c_void, usize) -> c_int>(b"hipMalloc\0")?
    };
    let clear = unsafe {
        lib.get::<unsafe extern "C" fn(*mut c_void, c_int, usize) -> c_int>(b"hipMemset\0")?
    };
    let free = unsafe { lib.get::<unsafe extern "C" fn(*mut c_void) -> c_int>(b"hipFree\0")? };
    let mut ptr = std::ptr::null_mut();
    let status = unsafe { alloc(&mut ptr, len) };
    if status != 0 {
        return Err(format!("HIP allocation failed with status {status}").into());
    }
    let status = unsafe { clear(ptr, 0, len) };
    if status != 0 {
        unsafe {
            free(ptr);
        }
        return Err(format!("HIP zero failed with status {status}").into());
    }
    match unsafe { MemOwn::from_raw_parts(ptr, bytes, GpuDialect::Hip) } {
        Ok(memory) => Ok(memory),
        Err(e) => {
            unsafe {
                free(ptr);
            }
            Err(e.into())
        }
    }
}
