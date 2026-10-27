use super::scratch::Scratch;
use super::{
    driver::Device,
    process::{Cancellation, Watchdog, kill_group},
};
use catena_lang::{
    codegen::GpuDialect,
    runtime::{RuntimeModule, Value},
    safe_runtime::{Artifact, SafeRuntime},
};
use hellas_rpc::Retention;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashMap},
    fs, io,
    sync::{Arc, Mutex, OnceLock, mpsc},
    thread,
    time::Duration,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn children() -> io::Result<BTreeSet<i32>> {
    let mut found = BTreeSet::new();
    for ent in fs::read_dir("/proc")? {
        let ent = ent?;
        let Some(pid) = ent.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        let Ok(status) = fs::read_to_string(ent.path().join("status")) else {
            continue;
        };
        if !status.lines().any(|l| {
            l.strip_prefix("PPid:")
                .is_some_and(|p| p.trim().parse() == Ok(std::process::id()))
        }) {
            continue;
        }
        let Ok(env) = fs::read(ent.path().join("environ")) else {
            continue;
        };
        if env
            .split(|b| *b == 0)
            .any(|s| s == b"CATENA_SAFE_RUNTIME_CHILD=1")
        {
            found.insert(pid);
        }
    }
    Ok(found)
}

struct Spawned {
    runtime: Option<SafeRuntime>,
    pid: i32,
    _scratch: Option<Arc<Scratch>>,
}
impl Spawned {
    fn into_parts(mut self) -> (SafeRuntime, i32) {
        (self.runtime.take().unwrap(), self.pid)
    }
}
impl Drop for Spawned {
    fn drop(&mut self) {
        if self.runtime.is_some() {
            kill_group(self.pid);
        }
    }
}
type SpawnReply = std::result::Result<Spawned, String>;
enum SpawnRequest {
    New {
        cancel: Cancellation,
        scratch: Option<Arc<Scratch>>,
        reply: mpsc::Sender<SpawnReply>,
    },
}

fn start_spawner() -> mpsc::SyncSender<SpawnRequest> {
    let (send, receive) = mpsc::sync_channel(0);
    // Linux PDEATHSIG follows the creating thread. This process-lifetime thread
    // owns every spawn, even when the job requesting it runs on a short-lived thread.
    thread::spawn(move || {
        for request in receive {
            match request {
                SpawnRequest::New {
                    cancel,
                    scratch,
                    reply,
                } => {
                    let result = spawn_child(cancel, scratch.as_deref())
                        .map(|(runtime, pid)| Spawned {
                            runtime: Some(runtime),
                            pid,
                            _scratch: scratch,
                        })
                        .map_err(|e| e.to_string());
                    let _ = reply.send(result);
                }
            }
        }
    });
    send
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SpawnError {
    #[error("SafeRuntime initialization cancelled")]
    Cancelled,
    #[error("SafeRuntime spawner unavailable")]
    Unavailable,
    #[error("SafeRuntime initialization failed: {0}")]
    Initialization(String),
}
impl SpawnError {
    fn counts_for_health(&self) -> bool {
        !matches!(self, Self::Cancelled)
    }
}

fn spawner() -> &'static mpsc::SyncSender<SpawnRequest> {
    static SPAWNER: OnceLock<mpsc::SyncSender<SpawnRequest>> = OnceLock::new();
    SPAWNER.get_or_init(start_spawner)
}
fn spawn(
    cancel: Cancellation,
    scratch: Option<Arc<Scratch>>,
) -> std::result::Result<(SafeRuntime, i32), SpawnError> {
    spawn_on(spawner(), cancel, scratch)
}
fn spawn_on(
    spawner: &mpsc::SyncSender<SpawnRequest>,
    cancel: Cancellation,
    scratch: Option<Arc<Scratch>>,
) -> std::result::Result<(SafeRuntime, i32), SpawnError> {
    let (reply, receive) = mpsc::channel();
    let mut request = SpawnRequest::New {
        cancel: cancel.clone(),
        scratch,
        reply,
    };
    loop {
        if cancel.is_cancelled() {
            return Err(SpawnError::Cancelled);
        }
        match spawner.try_send(request) {
            Ok(()) => break,
            Err(mpsc::TrySendError::Full(queued)) => {
                request = queued;
                thread::sleep(Duration::from_millis(2));
            }
            Err(_) => return Err(SpawnError::Unavailable),
        }
    }
    loop {
        if cancel.is_cancelled() {
            return Err(SpawnError::Cancelled);
        }
        match receive.recv_timeout(Duration::from_millis(2)) {
            Ok(result) => {
                // Cleanup may produce an EOF error at the same time as cancellation.
                // Classify the caller's cancellation before that transport consequence.
                if cancel.is_cancelled() {
                    return Err(SpawnError::Cancelled);
                }
                return result
                    .map(Spawned::into_parts)
                    .map_err(SpawnError::Initialization);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(_) => return Err(SpawnError::Unavailable),
        }
    }
}

fn monitor_init(
    before: BTreeSet<i32>,
    cancel: Cancellation,
    resolved: mpsc::Receiver<bool>,
) -> io::Result<i32> {
    let mut pid = None;
    let mut failure = None;
    loop {
        match children() {
            Ok(children) => {
                let new: Vec<_> = children.difference(&before).copied().collect();
                if new.len() > 1 {
                    failure = Some("ambiguous SafeRuntime child discovery");
                }
                if let Some(p) = new.first() {
                    pid = Some(*p);
                }
                if failure.is_some() || cancel.is_cancelled() {
                    failure.get_or_insert("SafeRuntime initialization cancelled");
                    for p in new {
                        kill_group(p);
                        unsafe {
                            libc::kill(p, libc::SIGKILL);
                        }
                    }
                }
            }
            Err(_) => {
                failure = Some("SafeRuntime process discovery failed");
                if let Some(p) = pid {
                    kill_group(p);
                }
            }
        }
        // Stay armed after cancellation: SafeRuntime may create its child late,
        // after loading its parent transport. That late child must still be killed.
        match resolved.recv_timeout(Duration::from_millis(2)) {
            Ok(success) => {
                if let Some(reason) = failure {
                    if let Some(p) = pid {
                        kill_group(p);
                    }
                    return Err(io::Error::other(reason));
                }
                if !success {
                    if let Some(p) = pid {
                        kill_group(p);
                    }
                    return Err(io::Error::other("SafeRuntime initialization failed"));
                }
                let p = pid
                    .or_else(|| children().ok()?.difference(&before).copied().next())
                    .ok_or_else(|| io::Error::other("SafeRuntime child not found"))?;
                if cancel.is_cancelled() || unsafe { libc::getpgid(p) } != p {
                    kill_group(p);
                    unsafe {
                        libc::kill(p, libc::SIGKILL);
                    }
                    return Err(io::Error::other(
                        "SafeRuntime initialization cancelled or not isolated",
                    ));
                }
                return Ok(p);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if let Some(p) = pid {
                    kill_group(p);
                }
                return Err(io::Error::other("SafeRuntime initializer disconnected"));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
}

fn spawn_child(cancel: Cancellation, scratch: Option<&Scratch>) -> Result<(SafeRuntime, i32)> {
    if cancel.is_cancelled() {
        return Err("SafeRuntime initialization cancelled".into());
    }
    let _scratch = scratch.map(Scratch::inherit).transpose()?;
    let before = children()?;
    let (done, receive) = mpsc::channel();
    let monitor = thread::spawn(move || monitor_init(before, cancel, receive));
    let runtime = SafeRuntime::new(GpuDialect::Hip);
    let _ = done.send(runtime.is_ok());
    let pid = monitor.join().map_err(|_| "spawn monitor panicked")?;
    match (runtime, pid) {
        (Ok(runtime), Ok(pid)) => Ok((runtime, pid)),
        (Err(error), _) => Err(error.into()),
        (Ok(runtime), Err(error)) => {
            drop(runtime);
            Err(error.into())
        }
    }
}

fn key(module: &RuntimeModule) -> Result<[u8; 32]> {
    Ok(Sha256::digest(bincode::serialize(module)?).into())
}

struct Worker {
    runtime: SafeRuntime,
    pid: i32,
    artifacts: HashMap<[u8; 32], Artifact>,
    // Last: SafeRuntime must reap the child before scratch is removed.
    scratch: Option<Arc<Scratch>>,
}
impl Drop for Worker {
    fn drop(&mut self) {
        kill_group(self.pid);
        self.artifacts.clear();
    }
}

struct Slot {
    worker: Option<Worker>,
    busy: bool,
}
struct PoolState {
    workers: Vec<Slot>,
    consecutive_failures: u8,
}
#[derive(Clone)]
pub struct Pool {
    state: Arc<Mutex<PoolState>>,
    max_programs: usize,
}
impl Pool {
    pub fn new(workers: usize, max_programs: usize) -> Result<Self> {
        if workers == 0 || max_programs == 0 {
            return Err("worker and program counts must be positive".into());
        }
        Ok(Self {
            state: Arc::new(Mutex::new(PoolState {
                workers: (0..workers)
                    .map(|_| Slot {
                        worker: None,
                        busy: false,
                    })
                    .collect(),
                consecutive_failures: 0,
            })),
            max_programs,
        })
    }
    fn record_initialization_error(&self, error: &SpawnError) {
        if error.counts_for_health()
            && let Ok(mut state) = self.state.lock()
        {
            state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        }
    }
    pub fn available(&self) -> bool {
        self.state.lock().is_ok_and(|s| s.consecutive_failures < 3)
    }
    pub fn lease(&self, module: &RuntimeModule, execution_timeout: Duration) -> Result<Lease> {
        self.lease_cancellable(module, execution_timeout, Cancellation::default())
    }
    pub fn lease_cancellable(
        &self,
        module: &RuntimeModule,
        execution_timeout: Duration,
        cancel: Cancellation,
    ) -> Result<Lease> {
        let key = key(module)?;
        let mut state = self.state.lock().map_err(|_| "worker pool poisoned")?;
        if state.consecutive_failures >= 3 {
            return Err("Catena executor unavailable after three initialization failures".into());
        }
        let index = state
            .workers
            .iter()
            .position(|s| {
                !s.busy
                    && s.worker
                        .as_ref()
                        .is_some_and(|w| w.artifacts.contains_key(&key))
            })
            .or_else(|| {
                state
                    .workers
                    .iter()
                    .position(|s| !s.busy && s.worker.is_none())
            })
            .or_else(|| state.workers.iter().position(|s| !s.busy))
            .ok_or("all Catena workers are busy")?;
        let slot = &mut state.workers[index];
        slot.busy = true;
        let worker = slot
            .worker
            .take()
            .filter(|w| w.artifacts.contains_key(&key) || w.artifacts.len() < self.max_programs);
        Ok(Lease {
            pool: self.clone(),
            worker,
            index,
            key,
            execution_timeout,
            watchdog: None,
            loaded: false,
            failed: false,
            cancel,
        })
    }
}

pub struct Lease {
    pool: Pool,
    worker: Option<Worker>,
    index: usize,
    key: [u8; 32],
    execution_timeout: Duration,
    watchdog: Option<Watchdog>,
    loaded: bool,
    cancel: Cancellation,
    failed: bool,
}
impl Lease {
    pub fn cancellation(&self) -> Cancellation {
        self.cancel.clone()
    }
    pub fn pid(&self) -> Option<i32> {
        self.worker.as_ref().map(|w| w.pid)
    }
}

impl Device for Lease {
    fn load(&mut self, module: &RuntimeModule, retention: Retention) -> Result<Cancellation> {
        if self.cancel.timed_out() {
            return Err(super::driver::Interruption::TimedOut.into());
        }
        if self.cancel.is_cancelled() {
            return Err(super::driver::Interruption::Cancelled.into());
        }
        if self.loaded || key(module)? != self.key {
            return Err("lease module mismatch or repeated load".into());
        }
        let ephemeral = retention == Retention::Ephemeral;
        // Workers keep separate native artifact lifetimes for retained and ephemeral jobs.
        if self
            .worker
            .as_ref()
            .is_some_and(|w| w.scratch.is_some() != ephemeral)
        {
            self.worker = None;
        }
        if self.worker.is_none() {
            let scratch = if ephemeral {
                Some(Arc::new(Scratch::new()?))
            } else {
                None
            };
            match spawn(self.cancel.clone(), scratch.clone()) {
                Ok((runtime, pid)) => {
                    self.pool
                        .state
                        .lock()
                        .map_err(|_| "worker pool poisoned")?
                        .consecutive_failures = 0;
                    self.worker = Some(Worker {
                        runtime,
                        pid,
                        artifacts: HashMap::new(),
                        scratch,
                    });
                }
                Err(e) => {
                    self.pool.record_initialization_error(&e);
                    self.failed = true;
                    return Err(e.into());
                }
            }
        }
        let worker = self.worker.as_mut().unwrap();
        if !worker.artifacts.contains_key(&self.key) {
            let watchdog = Watchdog::with_cancel(worker.pid, None, self.cancel.clone());
            let artifact = worker.runtime.load(module.clone());
            let interrupted = watchdog.finish();
            match artifact {
                Ok(artifact) if !interrupted && !self.cancel.is_cancelled() => {
                    if let Some(scratch) = &worker.scratch
                        && let Err(error) = scratch.clear()
                    {
                        self.failed = true;
                        kill_group(worker.pid);
                        drop(artifact);
                        self.worker = None;
                        return Err(error.into());
                    }
                    worker.artifacts.insert(self.key, artifact);
                }
                result => {
                    self.failed = true;
                    kill_group(worker.pid);
                    let error: Box<dyn std::error::Error> = if self.cancel.is_cancelled() {
                        super::driver::Interruption::Cancelled.into()
                    } else {
                        format!("Catena load failed (cancelled={interrupted}): {result:?}").into()
                    };
                    // A racing successful Artifact also owns the runtime session.
                    // Release it before reaping the worker and removing build files.
                    drop(result);
                    self.worker = None;
                    return Err(error);
                }
            }
        }
        self.cancel.set_deadline(self.execution_timeout);
        self.watchdog = Some(Watchdog::with_cancel(
            worker.pid,
            Some(self.execution_timeout),
            self.cancel.clone(),
        ));
        self.loaded = true;
        Ok(self.cancel.clone())
    }

    fn call(&mut self, entry: &str, args: Vec<Value<'_>>) -> Result<Vec<Value<'static>>> {
        if !self.loaded
            || self.failed
            || self.cancel.is_cancelled()
            || self.watchdog.as_ref().is_some_and(Watchdog::fired)
        {
            self.failed = true;
            return Err("worker lease is not executable".into());
        }
        let worker = self.worker.as_ref().unwrap();
        match worker.artifacts[&self.key].exec_values(entry, args) {
            Ok(values)
                if !self.cancel.is_cancelled()
                    && !self.watchdog.as_ref().is_some_and(Watchdog::fired) =>
            {
                Ok(values)
            }
            Ok(_) => {
                self.failed = true;
                kill_group(worker.pid);
                Err("Catena execution timed out or cancelled".into())
            }
            Err(error) => {
                self.failed = true;
                kill_group(worker.pid);
                Err(error.into())
            }
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.failed |= std::thread::panicking() || self.cancel.is_cancelled();
        if let Some(watchdog) = self.watchdog.take() {
            self.failed |= watchdog.finish();
        }
        if self.failed {
            self.worker = None;
        }
        if let Ok(mut state) = self.pool.state.lock() {
            state.workers[self.index].worker = self.worker.take();
            state.workers[self.index].busy = false;
        }
    }
}
