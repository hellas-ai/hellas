//! Opaque secrets in an explicitly selected store. Native operations block:
//! async callers must use a blocking worker, not an executor worker thread.
use std::{fmt, io, path::PathBuf};
use zeroize::Zeroizing;

/// Upper bound for one opaque secret. Native stores may impose a smaller limit
/// (Windows Credential Manager accepts at most 2,560 bytes per credential).
pub const MAX_SECRET_BYTES: usize = 65_536;

/// Errors contain no secret values or backend diagnostic payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretError {
    InvalidName,
    InvalidData,
    TooLarge,
    AccessDenied,
    Unavailable,
    Ambiguous,
    Unsupported,
}
impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidName => "invalid secret store name",
            Self::InvalidData => "invalid secret store data",
            Self::TooLarge => "secret exceeds store limit",
            Self::AccessDenied => "secret store access denied",
            Self::Unavailable => "secret store unavailable",
            Self::Ambiguous => "multiple matching secrets",
            Self::Unsupported => "native secret store unsupported",
        })
    }
}
impl std::error::Error for SecretError {}

#[derive(Clone, Debug)]
enum Backend {
    Native,
    HeadlessFiles(PathBuf),
}

/// A service-scoped store with no discovery, fallback, or authority policy.
/// Service and key names are 1–128 ASCII letters, digits, hyphens or underscores.
/// An OS error never selects the explicit headless file backend.
#[derive(Clone, Debug)]
pub struct SecretStore {
    service: String,
    backend: Backend,
}
impl SecretStore {
    pub fn native(service: impl Into<String>) -> Result<Self, SecretError> {
        let service = service.into();
        validate_name(&service)?;
        Ok(Self {
            service,
            backend: Backend::Native,
        })
    }

    /// Select private files explicitly, for headless deployments only.
    /// Construction does not create files; set creates a private service directory.
    pub fn headless_files(
        directory: PathBuf,
        service: impl Into<String>,
    ) -> Result<Self, SecretError> {
        let service = service.into();
        validate_name(&service)?;
        if directory.as_os_str().is_empty() {
            return Err(SecretError::InvalidName);
        }
        Ok(Self {
            service,
            backend: Backend::HeadlessFiles(directory),
        })
    }

    /// Validate a key before publishing configuration; performs no store access.
    pub fn validate_key(&self, key: &str) -> Result<(), SecretError> {
        validate_name(key)
    }

    pub fn get(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, SecretError> {
        self.validate_key(key)?;
        match &self.backend {
            Backend::Native => native::get(&self.service, key),
            Backend::HeadlessFiles(root) => {
                match private_directory(root, false) {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                    result => result.map_err(file_error)?,
                }
                let directory = root.join(&self.service);
                match private_directory(&directory, false) {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                    result => result.map_err(file_error)?,
                }
                let file = match crate::open_regular_file_nofollow(&directory.join(key)) {
                    Ok(file) => file,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                    Err(error) => return Err(file_error(error)),
                };
                crate::read_private_bounded(file, MAX_SECRET_BYTES)
                    .map(Some)
                    .map_err(file_error)
            }
        }
    }

    pub fn set(&self, key: &str, bytes: &[u8]) -> Result<(), SecretError> {
        self.validate_key(key)?;
        if bytes.len() > MAX_SECRET_BYTES {
            return Err(SecretError::TooLarge);
        }
        match &self.backend {
            Backend::Native => native::set(&self.service, key, bytes),
            Backend::HeadlessFiles(root) => {
                let directory = root.join(&self.service);
                private_directory(root, true).map_err(file_error)?;
                private_directory(&directory, true).map_err(file_error)?;
                let path = directory.join(key);
                // Refuse existing links and special files instead of following or
                // replacing an unexpected object in the service's namespace.
                match crate::open_regular_file_nofollow(&path) {
                    Ok(file) => {
                        if !crate::is_private(&file).map_err(file_error)? {
                            return Err(SecretError::AccessDenied);
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(file_error(error)),
                }
                crate::write_atomically(&path, ".secret", bytes).map_err(file_error)
            }
        }
    }

    /// Delete an entry, returning whether one existed.
    pub fn delete(&self, key: &str) -> Result<bool, SecretError> {
        self.validate_key(key)?;
        match &self.backend {
            Backend::Native => native::delete(&self.service, key),
            Backend::HeadlessFiles(root) => {
                match private_directory(root, false) {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
                    result => result.map_err(file_error)?,
                }
                let directory = root.join(&self.service);
                match private_directory(&directory, false) {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
                    result => result.map_err(file_error)?,
                }
                let path = directory.join(key);
                match crate::open_regular_file_nofollow(&path) {
                    Ok(file) => {
                        if !crate::is_private(&file).map_err(file_error)? {
                            return Err(SecretError::AccessDenied);
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
                    Err(error) => return Err(file_error(error)),
                }
                std::fs::remove_file(path).map_err(file_error)?;
                crate::sync_directory(&directory).map_err(file_error)?;
                Ok(true)
            }
        }
    }
}

fn validate_name(name: &str) -> Result<(), SecretError> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(SecretError::InvalidName);
    }
    Ok(())
}

fn private_directory(path: &std::path::Path, create: bool) -> io::Result<()> {
    if create {
        crate::create_dir_all_durable(path)?;
    }
    if !std::fs::symlink_metadata(path)?.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secret directory must not be a link",
        ));
    }
    let directory = crate::open_directory(path)?;
    if !crate::imp::is_private(&directory)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "secret directory must be private",
        ));
    }
    Ok(())
}
fn file_error(error: io::Error) -> SecretError {
    match error.kind() {
        io::ErrorKind::PermissionDenied => SecretError::AccessDenied,
        io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput => SecretError::InvalidData,
        _ => SecretError::Unavailable,
    }
}

mod native;
#[cfg(test)]
mod tests;
