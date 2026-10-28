use std::{
    io,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Default, Debug)]
pub struct Cancellation {
    cancelled: Arc<AtomicBool>,
    deadline: Arc<OnceLock<Instant>>,
}
impl Cancellation {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire) || self.timed_out()
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
    if pid > 1 {
        unsafe {
            libc::killpg(pid, libc::SIGKILL);
        }
    }
}

pub(crate) struct Watchdog {
    done: Option<mpsc::Sender<()>>,
    task: Option<thread::JoinHandle<()>>,
    fired: Arc<AtomicBool>,
}
impl Watchdog {
    pub(crate) fn with_cancel(pid: i32, timeout: Option<Duration>, cancel: Cancellation) -> Self {
        let (done, rx) = mpsc::channel();
        let fired = Arc::new(AtomicBool::new(false));
        let flag = fired.clone();
        let task = thread::spawn(move || {
            let start = Instant::now();
            loop {
                if cancel.is_cancelled() || timeout.is_some_and(|limit| start.elapsed() >= limit) {
                    flag.store(true, Ordering::Release);
                    cancel.cancel();
                    kill_group(pid);
                    break;
                }
                let interval = timeout.map_or(Duration::from_millis(2), |limit| {
                    Duration::from_millis(2).min(limit.saturating_sub(start.elapsed()))
                });
                match rx.recv_timeout(interval) {
                    Ok(()) => break,
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        flag.store(true, Ordering::Release);
                        kill_group(pid);
                        break;
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
            }
        });
        Self {
            done: Some(done),
            task: Some(task),
            fired,
        }
    }
    pub(crate) fn fired(&self) -> bool {
        self.fired.load(Ordering::Acquire)
    }
    pub(crate) fn finish(mut self) -> bool {
        let _ = self.done.take().unwrap().send(());
        let panicked = self.task.take().unwrap().join().is_err();
        panicked || self.fired()
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
