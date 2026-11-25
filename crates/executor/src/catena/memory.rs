use catena_lang::{codegen::GpuDialect, runtime::MemOwn};
use libloading::Library;
use std::{
    ffi::{CStr, c_int, c_void},
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

/// The architecture of the runtime's current device, as its compiler names
/// it: `sm_120` or `gfx1151`.
pub fn architecture(dialect: GpuDialect) -> Result<String> {
    type Status = c_int;
    let lib = runtime(dialect)?;
    let check = |status: Status| match status {
        0 => Ok(()),
        status => Err(format!("GPU device query failed with status {status}")),
    };
    let get_device: &[u8] = match dialect {
        GpuDialect::Hip => b"hipGetDevice\0",
        GpuDialect::Cuda => b"cudaGetDevice\0",
    };
    let get_device = unsafe { lib.get::<unsafe extern "C" fn(*mut c_int) -> Status>(get_device)? };
    let mut device = 0;
    check(unsafe { get_device(&mut device) })?;
    match dialect {
        GpuDialect::Cuda => {
            let attribute = unsafe {
                lib.get::<unsafe extern "C" fn(*mut c_int, c_int, c_int) -> Status>(
                    b"cudaDeviceGetAttribute\0",
                )?
            };
            // cudaDevAttrComputeCapabilityMajor and cudaDevAttrComputeCapabilityMinor.
            let (mut major, mut minor) = (0, 0);
            check(unsafe { attribute(&mut major, 75, device) })?;
            check(unsafe { attribute(&mut minor, 76, device) })?;
            Ok(format!("sm_{major}{minor}"))
        }
        GpuDialect::Hip => {
            // The ABI-frozen hipDeviceProp_tR0600: 1472 bytes, `gcnArchName` at 1160.
            #[repr(C, align(8))]
            struct Properties {
                _head: [u8; 1160],
                arch: [u8; 256],
                _tail: [u8; 56],
            }
            let properties = unsafe {
                lib.get::<unsafe extern "C" fn(*mut Properties, c_int) -> Status>(
                    b"hipGetDevicePropertiesR0600\0",
                )?
            };
            let mut device_properties = Properties {
                _head: [0; 1160],
                arch: [0; 256],
                _tail: [0; 56],
            };
            check(unsafe { properties(&mut device_properties, device) })?;
            // `gfx90a:sramecc+:xnack-` names the target, then its features.
            let name = CStr::from_bytes_until_nul(&device_properties.arch)?.to_str()?;
            Ok(name.split(':').next().unwrap_or_default().to_owned())
        }
    }
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
