use std::{
    io,
    pin::pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll, Wake, Waker},
    thread,
    time::{Duration, Instant},
};
use tokio::sync::oneshot;
use tokio_util::sync::{CancellationToken, DropGuard};

#[derive(Clone, Default, Debug)]
pub struct Cancellation {
    token: CancellationToken,
    deadline: Arc<OnceLock<Instant>>,
}
impl Cancellation {
    pub fn cancel(&self) {
        self.token.cancel();
    }
    pub fn is_cancelled(&self) -> bool {
        self.token.is_cancelled() || self.timed_out()
    }
    pub(crate) async fn cancelled(&self) {
        self.token.cancelled().await;
    }
    pub(crate) fn drop_guard(&self) -> DropGuard {
        self.token.clone().drop_guard()
    }
    pub(crate) fn timed_out(&self) -> bool {
        self.deadline
            .get()
            .is_some_and(|deadline| Instant::now() >= *deadline)
    }
    pub(crate) fn set_deadline(&self, timeout: Duration) {
        match Instant::now().checked_add(timeout) {
            Some(deadline) => {
                let _ = self.deadline.set(deadline);
            }
            None => self.cancel(),
        }
    }
    /// Blocks this std thread until `work` completes. `None` means cancellation,
    /// this cancellation's deadline, or `deadline` came first; each wakes it directly.
    pub(crate) fn block_on<T>(
        &self,
        deadline: Option<Instant>,
        work: impl Future<Output = T>,
    ) -> Option<T> {
        struct Unpark(thread::Thread);
        impl Wake for Unpark {
            fn wake(self: Arc<Self>) {
                self.0.unpark();
            }
        }
        let waker = Waker::from(Arc::new(Unpark(thread::current())));
        let mut context = Context::from_waker(&waker);
        let deadline = deadline
            .into_iter()
            .chain(self.deadline.get().copied())
            .min();
        let mut cancelled = pin!(self.token.cancelled());
        let mut work = pin!(work);
        loop {
            if cancelled.as_mut().poll(&mut context).is_ready() {
                return None;
            }
            if let Poll::Ready(value) = work.as_mut().poll(&mut context) {
                return Some(value);
            }
            match deadline.map(|end| end.saturating_duration_since(Instant::now())) {
                None => thread::park(),
                Some(left) if left.is_zero() => return None,
                Some(left) => thread::park_timeout(left),
            }
        }
    }
}

/// Called by the re-executed worker before its protocol loop.
pub fn isolate_child() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let parent = unsafe { libc::getppid() };
        if unsafe { libc::setpgid(0, 0) } != 0
            || unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::getppid() } != parent {
            unsafe { libc::_exit(128 + libc::SIGKILL) };
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(io::Error::other("Catena process isolation requires Linux"))
    }
}

pub(crate) fn kill_group(pid: i32) {
    #[cfg(not(unix))]
    unreachable!("Catena process isolation cannot create child {pid} on this platform");
    #[cfg(unix)]
    if pid > 1 {
        unsafe {
            libc::killpg(pid, libc::SIGKILL);
        }
    }
}

pub(crate) struct Watchdog {
    done: Option<oneshot::Sender<()>>,
    task: Option<thread::JoinHandle<bool>>,
}
impl Watchdog {
    /// Kills `pid`'s group on cancellation, at `timeout`, or when dropped
    /// without `finish`. The thread wakes once for whichever comes first.
    pub(crate) fn with_cancel(pid: i32, timeout: Option<Duration>, cancel: Cancellation) -> Self {
        let (done, finished) = oneshot::channel();
        let deadline = timeout.and_then(|limit| Instant::now().checked_add(limit));
        let task = thread::spawn(move || {
            match cancel.block_on(deadline, finished) {
                Some(Ok(())) => return false,
                Some(Err(_)) => {}
                None => cancel.cancel(),
            }
            kill_group(pid);
            true
        });
        Self {
            done: Some(done),
            task: Some(task),
        }
    }
    /// Whether the watchdog killed the group (or panicked).
    pub(crate) fn finish(mut self) -> bool {
        let _ = self.done.take().unwrap().send(());
        self.task.take().unwrap().join().unwrap_or(true)
    }
}
impl Drop for Watchdog {
    fn drop(&mut self) {
        self.done.take();
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_from_another_thread_wakes_a_blocked_wait() {
        let cancel = Cancellation::default();
        let canceller = thread::spawn({
            let cancel = cancel.clone();
            move || cancel.cancel()
        });
        // The work never completes: only the token can end this wait.
        assert_eq!(cancel.block_on(None, std::future::pending::<()>()), None);
        canceller.join().unwrap();
    }

    #[test]
    fn completion_from_another_thread_wakes_a_blocked_wait() {
        let (send, receive) = oneshot::channel();
        let sender = thread::spawn(move || send.send(7).unwrap());
        let cancel = Cancellation::default();
        assert_eq!(cancel.block_on(None, receive), Some(Ok(7)));
        sender.join().unwrap();
        cancel.cancel();
        let (_send, receive) = oneshot::channel::<()>();
        assert_eq!(cancel.block_on(None, receive), None);
    }

    #[test]
    fn deadlines_end_a_wait_without_cancelling() {
        let cancel = Cancellation::default();
        let past = Some(Instant::now());
        assert_eq!(cancel.block_on(past, std::future::pending::<()>()), None);
        assert!(!cancel.is_cancelled());
        cancel.set_deadline(Duration::ZERO);
        assert_eq!(cancel.block_on(None, std::future::pending::<()>()), None);
    }

    #[cfg(unix)]
    fn blocked_child() -> (std::process::Child, std::process::ChildStdin) {
        use std::os::unix::process::CommandExt;
        let mut child = std::process::Command::new("cat")
            .process_group(0)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        // `cat` exits only when killed while this stdin stays open.
        let stdin = child.stdin.take().unwrap();
        (child, stdin)
    }

    #[cfg(unix)]
    #[test]
    fn watchdog_kills_on_cancellation_or_timeout_and_spares_finished_work() {
        use std::os::unix::process::ExitStatusExt;
        for timeout in [None, Some(Duration::ZERO)] {
            let (mut child, _stdin) = blocked_child();
            let cancel = Cancellation::default();
            let watchdog = Watchdog::with_cancel(child.id() as i32, timeout, cancel.clone());
            if timeout.is_none() {
                cancel.cancel();
            }
            assert_eq!(child.wait().unwrap().signal(), Some(libc::SIGKILL));
            assert!(watchdog.finish());
            assert!(cancel.is_cancelled());
        }
        let (mut child, _stdin) = blocked_child();
        let cancel = Cancellation::default();
        let watchdog = Watchdog::with_cancel(child.id() as i32, None, cancel.clone());
        assert!(!watchdog.finish());
        assert!(!cancel.is_cancelled());
        child.kill().unwrap();
        child.wait().unwrap();
    }
}
