use super::{Error, Result};
use std::sync::{Arc, Mutex};

/// Shared node RAM staging accounting. Accepted jobs transfer their charge to
/// the host's live execution accounting; owner-held RAM stays charged until GC.
#[derive(Clone)]
pub struct Reservations(Arc<Mutex<Pool>>);
struct Pool {
    limit: u64,
    held: u64,
}
pub(crate) struct Reservation {
    pool: Reservations,
    state: Mutex<Charge>,
}
struct Charge {
    bytes: u64,
    transferred: bool,
}
impl Reservations {
    pub fn ram(limit: u64) -> Self {
        Self(Arc::new(Mutex::new(Pool { limit, held: 0 })))
    }
    pub fn held(&self) -> u64 {
        self.0.lock().unwrap().held
    }
    pub(crate) fn reserve(&self, bytes: u64) -> Result<Arc<Reservation>> {
        let mut pool = self
            .0
            .lock()
            .map_err(|_| Error::Invalid("reservation lock"))?;
        let held = pool
            .held
            .checked_add(bytes)
            .filter(|held| *held <= pool.limit)
            .ok_or(Error::Capacity)?;
        pool.held = held;
        Ok(Arc::new(Reservation {
            pool: self.clone(),
            state: Mutex::new(Charge {
                bytes,
                transferred: false,
            }),
        }))
    }
}
impl Reservation {
    pub(crate) fn bytes(&self) -> u64 {
        self.state.lock().unwrap().bytes
    }
    pub(crate) fn extend(&self, extra: u64) -> Result<()> {
        let mut charge = self
            .state
            .lock()
            .map_err(|_| Error::Invalid("reservation lock"))?;
        let bytes = charge.bytes.checked_add(extra).ok_or(Error::Capacity)?;
        if !charge.transferred {
            let mut pool = self
                .pool
                .0
                .lock()
                .map_err(|_| Error::Invalid("reservation lock"))?;
            pool.held = pool
                .held
                .checked_add(extra)
                .filter(|held| *held <= pool.limit)
                .ok_or(Error::Capacity)?;
        }
        charge.bytes = bytes;
        Ok(())
    }
    pub(crate) fn transfer(&self) {
        let mut charge = self.state.lock().unwrap();
        if !charge.transferred {
            self.pool.0.lock().unwrap().held -= charge.bytes;
            charge.transferred = true;
        }
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        let charge = self.state.get_mut().unwrap();
        if !charge.transferred {
            self.pool.0.lock().unwrap().held -= charge.bytes;
        }
    }
}
