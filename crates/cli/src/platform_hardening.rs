use std::io;
use std::sync::Once;

static INSTALL_PANIC_HOOK: Once = Once::new();

pub(crate) fn harden_provider_process() -> io::Result<()> {
    disable_core_dumps()?;
    INSTALL_PANIC_HOOK.call_once(|| {
        std::panic::set_hook(Box::new(|_| {
            eprintln!("provider process panicked; sensitive details suppressed");
        }));
    });
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
