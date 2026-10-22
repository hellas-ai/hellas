use super::{MAX_SECRET_BYTES, SecretError};
#[cfg(target_os = "linux")]
use base64::{Engine as _, engine::general_purpose::STANDARD};
use keyring_core::{Entry, Error, api::CredentialStoreApi as _};
use zeroize::Zeroizing;

fn entry(service: &str, key: &str) -> Result<Entry, SecretError> {
    #[cfg(target_os = "linux")]
    let store = dbus_secret_service_keyring_store::Store::new().map_err(error)?;
    #[cfg(target_os = "macos")]
    let store = apple_native_keyring_store::keychain::Store::new().map_err(error)?;
    #[cfg(windows)]
    let store = windows_native_keyring_store::Store::new().map_err(error)?;
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    {
        // Windows defaults to roaming credentials. Keep application secrets on
        // this machine; the service/key alphabet excludes the target delimiter.
        #[cfg(windows)]
        let modifiers = Some(std::collections::HashMap::from([("persistence", "local")]));
        #[cfg(not(windows))]
        let modifiers = None;
        store.build(service, key, modifiers.as_ref()).map_err(error)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = (service, key);
        Err(SecretError::Unsupported)
    }
}

pub(super) fn get(service: &str, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, SecretError> {
    let bytes = match entry(service, key)?.get_secret() {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(Error::NoEntry) => return Ok(None),
        Err(source) => return Err(error(source)),
    };
    #[cfg(target_os = "linux")]
    let bytes = {
        if bytes.len() > MAX_SECRET_BYTES.div_ceil(3) * 4 {
            return Err(SecretError::TooLarge);
        }
        // KWallet's Secret Service accepts only UTF-8. Encode at this backend
        // boundary so the common API preserves arbitrary bytes on Linux too.
        Zeroizing::new(
            STANDARD
                .decode(&bytes)
                .map_err(|_| SecretError::InvalidData)?,
        )
    };
    if bytes.len() > MAX_SECRET_BYTES {
        return Err(SecretError::TooLarge);
    }
    Ok(Some(bytes))
}

pub(super) fn set(service: &str, key: &str, bytes: &[u8]) -> Result<(), SecretError> {
    #[cfg(target_os = "linux")]
    let encoded = Zeroizing::new(STANDARD.encode(bytes));
    #[cfg(target_os = "linux")]
    let bytes = encoded.as_bytes();
    entry(service, key)?.set_secret(bytes).map_err(error)
}

pub(super) fn delete(service: &str, key: &str) -> Result<bool, SecretError> {
    match entry(service, key)?.delete_credential() {
        Ok(()) => Ok(true),
        Err(Error::NoEntry) => Ok(false),
        Err(source) => Err(error(source)),
    }
}

fn error(source: Error) -> SecretError {
    match source {
        Error::NoStorageAccess(_) => SecretError::AccessDenied,
        Error::TooLong(_, _) => SecretError::TooLarge,
        Error::BadEncoding(_) | Error::BadDataFormat(_, _) | Error::BadStoreFormat(_) => {
            SecretError::InvalidData
        }
        Error::Invalid(_, _) => SecretError::InvalidData,
        Error::Ambiguous(_) => SecretError::Ambiguous,
        Error::NotSupportedByStore(_) => SecretError::Unsupported,
        _ => SecretError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn backend_errors_never_disclose_secret_payloads() {
        for source in [
            Error::BadEncoding(b"PRIVATE-PAYLOAD".to_vec()),
            Error::Invalid("PRIVATE-PAYLOAD".into(), "PRIVATE-PAYLOAD".into()),
        ] {
            let mapped = error(source);
            assert!(!format!("{mapped:?}: {mapped}").contains("PRIVATE-PAYLOAD"));
        }
    }
}
