use std::io;
use std::sync::{
    Once,
    atomic::{AtomicBool, Ordering},
};

static INSTALL_PANIC_HOOK: Once = Once::new();
static REDACT_PANICS: AtomicBool = AtomicBool::new(false);

/// Tokio and Commonware can catch a task panic while sibling services keep
/// running. A CLI process cannot safely continue after losing an owned task.
pub(crate) fn install_fatal_panic_hook() {
    INSTALL_PANIC_HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if REDACT_PANICS.load(Ordering::Relaxed) {
                eprintln!("provider process panicked; sensitive details suppressed");
            } else {
                previous(info);
            }
            std::process::exit(1);
        }));
    });
}

pub(crate) fn harden_provider_process() -> io::Result<()> {
    disable_core_dumps()?;
    REDACT_PANICS.store(true, Ordering::Relaxed);
    install_fatal_panic_hook();
    Ok(())
}

#[cfg(unix)]
fn disable_core_dumps() -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid `rlimit` value and remains alive for the call.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn disable_core_dumps() -> io::Result<()> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::mem::MaybeUninit;

    #[test]
    fn task_panics_exit_the_process() {
        const CHILD: &str = "HELLAS_FATAL_PANIC_TEST";
        if let Ok(mode) = std::env::var(CHILD) {
            install_fatal_panic_hook();
            if mode == "provider" {
                harden_provider_process().unwrap();
            }
            if mode == "thread" {
                let _ = std::thread::spawn(|| panic!("task failure fixture")).join();
            } else {
                tokio::runtime::Runtime::new().unwrap().block_on(async {
                    let _ = tokio::spawn(async { panic!("task failure fixture") }).await;
                });
            }
            // Catching the panic and returning normally is the regression.
            std::process::exit(0);
        }
        for mode in ["thread", "tokio", "provider"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "platform_hardening::tests::task_panics_exit_the_process",
                    "--nocapture",
                ])
                .env(CHILD, mode)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(1), "{mode}: {output:?}");
            let stderr = String::from_utf8_lossy(&output.stderr);
            if mode == "provider" {
                assert!(stderr.contains("sensitive details suppressed"));
                assert!(!stderr.contains("task failure fixture"));
            } else {
                assert!(stderr.contains("task failure fixture"));
            }
        }
    }

    #[test]
    fn hardening_disables_core_dumps() {
        disable_core_dumps().expect("disabling core dumps should succeed");

        let mut limit = MaybeUninit::<libc::rlimit>::uninit();
        // SAFETY: `limit` points to writable storage for one `rlimit` value.
        let result = unsafe { libc::getrlimit(libc::RLIMIT_CORE, limit.as_mut_ptr()) };
        assert_eq!(
            result,
            0,
            "getrlimit failed: {}",
            io::Error::last_os_error()
        );
        // SAFETY: a successful `getrlimit` initialized `limit`.
        let limit = unsafe { limit.assume_init() };
        assert_eq!(limit.rlim_cur, 0);
        assert_eq!(limit.rlim_max, 0);
    }
}
