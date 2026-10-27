use bincode::Options;
use catena_lang::{
    codegen::{CodegenKind, GpuDialect},
    report::CompileReport,
    runtime::{ModuleCache, RuntimeModule},
};
use hellas_rpc::Retention;
use hellas_rpc::protocol::invocation::compute::MAX_SOURCE_BYTES;
use std::{
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};

use super::process::{Cancellation, Watchdog, isolate_child};

// Decision 23's killable compile child, specified in plan-v4 §§2.2/2.5.
// Decision 41 removes its deadline but retains explicit cancellation.
const COMPILE_ENV: &str = "HELLAS_CATENA_COMPILE";
const MAX_MODULE_BYTES: u64 = 256 << 20;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn child_main() -> Result<bool> {
    let compile = std::env::var(COMPILE_ENV).ok();
    let runtime = std::env::var_os("CATENA_SAFE_RUNTIME_CHILD").is_some();
    if compile.is_none() && !runtime {
        return Ok(false);
    }
    isolate_child()?;
    if let Some(dialect) = compile {
        let dialect = match dialect.as_str() {
            "hip" => GpuDialect::Hip,
            "cuda" => GpuDialect::Cuda,
            _ => return Err("unknown compile GPU dialect".into()),
        };
        let mut bytes = Vec::new();
        std::io::stdin()
            .take(MAX_SOURCE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_SOURCE_BYTES {
            return Err("sources exceed compile limit".into());
        }
        let sources: Vec<String> = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(MAX_SOURCE_BYTES)
            .reject_trailing_bytes()
            .deserialize(&bytes)?;
        let module = compile_sources(&sources, dialect)?;
        bincode::serialize_into(std::io::stdout().lock(), &module)?;
        return Ok(true);
    }
    Ok(catena_lang::safe_runtime::run_safe_runtime_child_if_requested()?)
}

pub fn compile_sources(sources: &[String], dialect: GpuDialect) -> Result<RuntimeModule> {
    let texts: Vec<_> = catena_lang::stdlib::core_sources()
        .map(|s| -> &str { s })
        .chain(sources.iter().map(String::as_str))
        .collect();
    let raw = metacat::theory::RawTheorySet::from_texts(texts)?;
    Ok(catena_lang::compile::compile(
        &mut CompileReport::new(raw),
        CodegenKind::Default,
        dialect,
    )?)
}

pub fn compile(
    sources: &[String],
    executable: &Path,
    dialect: GpuDialect,
) -> Result<RuntimeModule> {
    compile_cancellable(
        sources,
        executable,
        &Cancellation::default(),
        Retention::Retain,
        dialect,
    )
}

pub fn compile_cancellable(
    sources: &[String],
    executable: &Path,
    cancel: &Cancellation,
    retention: Retention,
    dialect: GpuDialect,
) -> Result<RuntimeModule> {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    static CACHE_BUSY: AtomicBool = AtomicBool::new(false);
    struct CacheGuard;
    impl Drop for CacheGuard {
        fn drop(&mut self) {
            CACHE_BUSY.store(false, Ordering::Release);
        }
    }
    let check_cancelled = || -> Result<()> {
        if cancel.is_cancelled() {
            return Err("Catena frontend compile cancelled".into());
        }
        Ok(())
    };
    if sources
        .iter()
        .try_fold(0u64, |sum, s| sum.checked_add(s.len() as u64))
        .is_none_or(|n| n > MAX_SOURCE_BYTES)
    {
        return Err("sources exceed compile limit".into());
    }
    let all: Vec<_> = catena_lang::stdlib::core_sources()
        .map(|s| -> &str { s })
        .chain(sources.iter().map(String::as_str))
        .collect();
    let cache = if retention == Retention::Retain {
        ModuleCache::from_sources(&all, CodegenKind::Default, dialect)
    } else {
        None
    };
    let Some(cache) = cache else {
        check_cancelled()?;
        let result = compile_child(sources, executable, cancel.clone(), dialect);
        check_cancelled()?;
        return result;
    };
    // ModuleCache takes a blocking OS file lock. One bounded background operation
    // keeps a lock held by another process from blocking the executor or creating
    // an unbounded number of abandoned threads.
    while CACHE_BUSY
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        check_cancelled()?;
        std::thread::sleep(Duration::from_millis(2));
    }
    let guard = CacheGuard;
    let sources = sources.to_vec();
    let executable = executable.to_owned();
    check_cancelled()?;
    let (send, receive) = mpsc::sync_channel(1);
    let child_cancel = cancel.clone();
    std::thread::spawn(move || {
        let _guard = guard;
        let result = cache
            .get_or_compile(|| {
                if child_cancel.is_cancelled() {
                    return Err("Catena frontend compile cancelled".into());
                }
                compile_child(&sources, &executable, child_cancel.clone(), dialect)
            })
            .map_err(|error| error.to_string());
        let _ = send.send(result);
    });
    loop {
        check_cancelled()?;
        match receive.recv_timeout(Duration::from_millis(2)) {
            Ok(result) => {
                check_cancelled()?;
                return result.map_err(Into::into);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(_) => {
                check_cancelled()?;
                return Err("Catena cache operation failed".into());
            }
        }
    }
}

fn compile_child(
    sources: &[String],
    executable: &Path,
    cancel: Cancellation,
    dialect: GpuDialect,
) -> Result<RuntimeModule> {
    use std::os::unix::process::CommandExt;
    let input = bincode::serialize(sources)?;
    if input.len() as u64 > MAX_SOURCE_BYTES {
        return Err("sources exceed compile limit".into());
    }
    let mut child = Command::new(executable)
        .env(
            COMPILE_ENV,
            match dialect {
                GpuDialect::Hip => "hip",
                GpuDialect::Cuda => "cuda",
            },
        )
        .env_remove("CATENA_SAFE_RUNTIME_CHILD")
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let watchdog = Watchdog::with_cancel(child.id() as i32, None, cancel.clone());
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let output = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(MAX_MODULE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let errors = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.take(64 << 10).read_to_end(&mut bytes).map(|_| bytes)
    });
    let status = child.wait()?;
    let interrupted = watchdog.finish();
    let write = writer.join().map_err(|_| "compile writer panicked")?;
    let bytes = output.join().map_err(|_| "compile reader panicked")??;
    let stderr = errors
        .join()
        .map_err(|_| "compile stderr reader panicked")??;
    if cancel.is_cancelled() || interrupted {
        return Err("Catena frontend compile cancelled".into());
    }
    if !status.success() {
        return Err(format!(
            "Catena frontend exited {status}: {}",
            String::from_utf8_lossy(&stderr)
        )
        .into());
    }
    write?;
    if bytes.len() as u64 > MAX_MODULE_BYTES {
        return Err("compiled module exceeds size limit".into());
    }
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_MODULE_BYTES)
        .reject_trailing_bytes()
        .deserialize(&bytes)?)
}
