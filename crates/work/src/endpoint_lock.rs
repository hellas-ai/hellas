//! Async endpoint ownership with fail-closed panic handling.

use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};

use tokio::sync::{Mutex, MutexGuard, OwnedMutexGuard};

#[derive(Debug)]
pub(crate) struct EndpointLock<T>(Arc<Mutex<State<T>>>);

#[derive(Debug)]
struct State<T> {
    value: T,
    failed: bool,
}

impl<T> EndpointLock<T> {
    pub(crate) fn new(value: T) -> Self {
        Self(Arc::new(Mutex::new(State {
            value,
            failed: false,
        })))
    }

    pub(crate) async fn lock(&self) -> Result<EndpointGuard<'_, T>, ()> {
        let held = self.0.lock().await;
        if held.failed {
            return Err(());
        }
        Ok(EndpointGuard(held))
    }

    pub(crate) async fn lock_owned(&self) -> Result<OwnedEndpointGuard<T>, ()> {
        let held = self.0.clone().lock_owned().await;
        if held.failed {
            return Err(());
        }
        Ok(OwnedEndpointGuard(held))
    }
}

pub(crate) struct OwnedEndpointGuard<T>(OwnedMutexGuard<State<T>>);
impl<T> Deref for OwnedEndpointGuard<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0.value
    }
}
impl<T> DerefMut for OwnedEndpointGuard<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0.value
    }
}
impl<T> Drop for OwnedEndpointGuard<T> {
    fn drop(&mut self) {
        self.0.failed |= std::thread::panicking();
    }
}

pub(crate) struct EndpointGuard<'a, T>(MutexGuard<'a, State<T>>);

impl<T> Deref for EndpointGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0.value
    }
}

impl<T> DerefMut for EndpointGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0.value
    }
}

impl<T> Drop for EndpointGuard<'_, T> {
    fn drop(&mut self) {
        // Set this while still holding the mutex, before another task can enter.
        self.0.failed |= std::thread::panicking();
    }
}
