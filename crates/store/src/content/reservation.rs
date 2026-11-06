use super::{Error, Result, StoreStats};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

/// Node-wide staging accounting. Disk counts owned usage separately from the
/// outstanding, unwritten reservation; lower files never enter this pool.
#[derive(Clone)]
pub struct Reservations(Arc<Mutex<Pool>>);
struct Pool {
    limit: u64,
    held: u64,
    next_id: u64,
    used: u64,
    disk: Option<PathBuf>,
}
pub(crate) struct Reservation {
    pool: Reservations,
    state: Mutex<Charge>,
}
struct Charge {
    unwritten: u64,
    written: u64,
    transferred: bool,
}
impl Pool {
    fn admit(&self, extra: u64) -> Result<u64> {
        self.admit_observed(
            extra,
            self.disk.as_ref().map(|root| free(root)).transpose()?,
        )
    }
    fn admit_observed(&self, extra: u64, free: Option<u64>) -> Result<u64> {
        let held = self.held.checked_add(extra).ok_or(Error::Capacity)?;
        if self
            .used
            .checked_add(held)
            .is_none_or(|total| total > self.limit)
            || free.is_some_and(|free| held > free)
        {
            return Err(Error::Capacity);
        }
        Ok(held)
    }
}
impl Reservations {
    pub fn ram(limit: u64) -> Self {
        Self::new(limit, None, 0)
    }
    pub(crate) fn disk(root: PathBuf, capacity: Option<u64>, used: u64) -> Self {
        Self::new(capacity.unwrap_or(u64::MAX), Some(root), used)
    }
    fn new(limit: u64, disk: Option<PathBuf>, used: u64) -> Self {
        Self(Arc::new(Mutex::new(Pool {
            limit,
            held: 0,
            next_id: 0,
            used,
            disk,
        })))
    }
    pub(crate) fn limit(&self) -> u64 {
        self.0.lock().unwrap().limit
    }
    pub fn held(&self) -> u64 {
        self.0.lock().unwrap().held
    }
    pub fn stats(&self) -> Result<StoreStats> {
        let pool = self
            .0
            .lock()
            .map_err(|_| Error::Invalid("reservation lock"))?;
        Ok(StoreStats {
            used: pool.used,
            outstanding: pool.held,
            free: match &pool.disk {
                Some(root) => free(root)?,
                None => pool.limit.saturating_sub(pool.held),
            },
        })
    }
    pub(crate) fn next_id(&self) -> Result<u64> {
        let mut pool = self
            .0
            .lock()
            .map_err(|_| Error::Invalid("reservation lock"))?;
        pool.next_id = pool.next_id.checked_add(1).ok_or(Error::Capacity)?;
        Ok(pool.next_id)
    }
    pub(crate) fn check(&self) -> Result<()> {
        self.0
            .lock()
            .map_err(|_| Error::Invalid("reservation lock"))?
            .admit(0)
            .map(drop)
    }
    pub(crate) fn reconcile_used(&self, bytes: u64) {
        self.0.lock().unwrap().used = bytes;
    }
    pub(crate) fn remove_owned(&self, bytes: u64) {
        self.0.lock().unwrap().used -= bytes;
    }
    pub(crate) fn reserve(&self, bytes: u64) -> Result<Arc<Reservation>> {
        let mut pool = self
            .0
            .lock()
            .map_err(|_| Error::Invalid("reservation lock"))?;
        if bytes != 0 {
            pool.held = pool.admit(bytes)?;
        }
        Ok(Arc::new(Reservation {
            pool: self.clone(),
            state: Mutex::new(Charge {
                unwritten: bytes,
                written: 0,
                transferred: false,
            }),
        }))
    }
}
impl Reservation {
    pub(crate) fn restore(&self, bytes: u64) -> Result<()> {
        let mut charge = self
            .state
            .lock()
            .map_err(|_| Error::Invalid("reservation lock"))?;
        let mut pool = self
            .pool
            .0
            .lock()
            .map_err(|_| Error::Invalid("reservation lock"))?;
        let unwritten = charge.unwritten.checked_add(bytes).ok_or(Error::Capacity)?;
        let held = pool.held.checked_add(bytes).ok_or(Error::Capacity)?;
        charge.unwritten = unwritten;
        pool.held = held;
        Ok(())
    }
    pub(crate) fn extend(&self, extra: u64) -> Result<()> {
        let mut charge = self
            .state
            .lock()
            .map_err(|_| Error::Invalid("reservation lock"))?;
        let unwritten = charge.unwritten.checked_add(extra).ok_or(Error::Capacity)?;
        if !charge.transferred {
            let mut pool = self
                .pool
                .0
                .lock()
                .map_err(|_| Error::Invalid("reservation lock"))?;
            pool.held = pool.admit(extra)?;
        }
        charge.unwritten = unwritten;
        Ok(())
    }
    /// Called by the worker after each successful disk write, before it accepts
    /// another chunk. Written staging counts as usage, never as free capacity.
    pub(crate) fn written(&self, bytes: u64) -> Result<()> {
        let mut charge = self
            .state
            .lock()
            .map_err(|_| Error::Invalid("reservation lock"))?;
        if bytes > charge.unwritten {
            return Err(Error::Capacity);
        }
        let mut pool = self
            .pool
            .0
            .lock()
            .map_err(|_| Error::Invalid("reservation lock"))?;
        if pool.disk.is_none() {
            return Ok(());
        }
        pool.held -= bytes;
        pool.used = pool.used.checked_add(bytes).ok_or(Error::Capacity)?;
        charge.unwritten -= bytes;
        charge.written += bytes;
        Ok(())
    }
    pub(crate) fn rewind(&self, bytes: u64) {
        let mut charge = self.state.lock().unwrap();
        let mut pool = self.pool.0.lock().unwrap();
        charge.written -= bytes;
        charge.unwritten += bytes;
        pool.used -= bytes;
        pool.held += bytes;
    }
    pub(crate) fn discarded(&self, bytes: u64) {
        let mut charge = self.state.lock().unwrap();
        charge.written -= bytes;
        self.pool.remove_owned(bytes);
    }
    pub(crate) fn published(&self, bytes: u64) {
        let mut charge = self.state.lock().unwrap();
        charge.written -= bytes;
    }
    /// RAM acceptance hands accounting to the host's live-job reservation.
    pub(crate) fn transfer(&self) {
        let mut charge = self.state.lock().unwrap();
        if !charge.transferred {
            self.pool.0.lock().unwrap().held -= charge.unwritten;
            charge.transferred = true;
        }
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        let charge = self.state.get_mut().unwrap();
        if !charge.transferred {
            let mut pool = self.pool.0.lock().unwrap();
            pool.held -= charge.unwritten;
            pool.used -= charge.written;
        }
    }
}
#[cfg(unix)]
#[allow(
    clippy::unnecessary_cast,
    reason = "libc statvfs field widths differ across Unix targets"
)]
fn free(root: &Path) -> Result<u64> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let path =
        CString::new(root.as_os_str().as_bytes()).map_err(|_| Error::Invalid("upper path"))?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let stat = unsafe { stat.assume_init() };
    (stat.f_bavail as u64)
        .checked_mul(stat.f_frsize as u64)
        .ok_or(Error::Capacity)
}
#[cfg(not(unix))]
fn free(_: &Path) -> Result<u64> {
    Err(Error::Invalid(
        "filesystem free-space sampling is unsupported",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capacity_and_physical_space_are_separate_inclusive_admission_constraints() {
        let mut pool = Pool {
            limit: 100,
            held: 10,
            next_id: 0,
            used: 80,
            disk: Some(PathBuf::new()),
        };
        assert_eq!(pool.admit_observed(10, Some(20)).unwrap(), 20);
        assert!(matches!(
            pool.admit_observed(11, Some(1000)),
            Err(Error::Capacity)
        ));
        pool.limit = 1000;
        pool.used = 800;
        assert!(matches!(
            pool.admit_observed(11, Some(20)),
            Err(Error::Capacity)
        ));
        assert_eq!(pool.admit_observed(10, Some(20)).unwrap(), 20);
    }
}
