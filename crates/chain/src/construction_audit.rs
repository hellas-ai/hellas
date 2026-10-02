//! Opt-in test evidence for chain construction and connection attempts.
//! The file sink also observes CLI subprocesses; normal builds contain no hook.
use std::sync::atomic::{AtomicUsize, Ordering};
static EVENTS: AtomicUsize = AtomicUsize::new(0);

pub fn events() -> usize {
    EVENTS.load(Ordering::SeqCst)
}

pub(crate) fn record() {
    use std::io::Write;
    EVENTS.fetch_add(1, Ordering::SeqCst);
    if let Some(path) = std::env::var_os("HELLAS_CHAIN_CONSTRUCTION_AUDIT") {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open chain construction audit");
        file.write_all(b"chain-client\n")
            .expect("record chain construction audit");
    }
}
