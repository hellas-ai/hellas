use std::process::Stdio;

use anyhow::Context;
use tokio::process::{Child, Command};

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::{c_int, c_ulong};

    pub const PR_SET_PDEATHSIG: c_int = 1;
    pub const SIGTERM: c_ulong = 15;

    unsafe extern "C" {
        pub fn prctl(option: c_int, ...) -> c_int;
        pub fn getppid() -> c_int;
        pub fn _exit(status: c_int) -> !;
    }
}

/// Spawn the wrapped command. The child inherits this process's stdio so
/// shell redirection on the wrapped command works as the user expects, and
/// is configured with `kill_on_drop(true)` so dropping the returned `Child`
/// (e.g. on gateway shutdown) tears it down too.
///
/// OpenAI, Anthropic and Kimi clients receive the gateway URL and its bearer
/// credential through their environment overrides. Anthropic uses
/// `ANTHROPIC_AUTH_TOKEN` so it sends the required Authorization header.
pub fn spawn(
    cmd: &str,
    args: &[String],
    base_url: &str,
    credential: &str,
) -> anyhow::Result<Child> {
    let mut command = Command::new(cmd);
    command
        .args(args)
        .env("OPENAI_BASE_URL", format!("{base_url}/v1"))
        .env("ANTHROPIC_BASE_URL", base_url)
        .env("OPENAI_API_KEY", credential)
        .env("ANTHROPIC_AUTH_TOKEN", credential)
        .env("KIMI_MODEL_BASE_URL", format!("{base_url}/v1"))
        .env("KIMI_MODEL_API_KEY", credential)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);

    // PR_SET_PDEATHSIG: if the gateway dies (panic / SIGKILL), the kernel
    // delivers SIGTERM to the wrapped child instead of stranding it as an
    // orphan. Linux-only; on macOS/BSD we rely on `kill_on_drop` for orderly
    // shutdown but a hard parent kill leaves the child running.
    #[cfg(target_os = "linux")]
    unsafe {
        command.pre_exec(|| {
            if linux::prctl(linux::PR_SET_PDEATHSIG, linux::SIGTERM) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Race window: if the parent already died between fork and prctl,
            // the signal will never fire. Re-check; bail if we're now reparented
            // to init.
            if linux::getppid() == 1 {
                linux::_exit(0);
            }
            Ok(())
        });
    }

    command
        .spawn()
        .with_context(|| format!("failed to spawn `{cmd}`"))
}
