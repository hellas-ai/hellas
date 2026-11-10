//! One principal key for the whole invocation: the home's, created on first
//! use, or one held outside the home.
use clap::Args;
use hellas_kernel::SoftPasskey;
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// The principal key every command acting for a principal uses by default.
const PRINCIPAL_KEY: &str = "principal.key";

#[derive(Args, Debug, Default)]
pub(crate) struct OwnerArgs {
    /// A principal key held outside the home: 32 raw bytes or 64 hex digits.
    /// Default: `principal.key` in the home, created on first use.
    #[arg(long, global = true)]
    passkey: Option<PathBuf>,
}

impl OwnerArgs {
    /// The selected key, or the home principal key if it already exists.
    /// Commands acting for a principal create it with [`principal`].
    pub(crate) fn load(&self, home: &Path) -> anyhow::Result<Option<SoftPasskey>> {
        if let Some(path) = &self.passkey {
            return crate::commands::chain::passkey(path).map(Some);
        }
        let path = home.join(PRINCIPAL_KEY);
        path.try_exists()?
            .then(|| crate::commands::chain::passkey(&path))
            .transpose()
    }
}

/// The home principal key, created on first use: a private P-256 software
/// key that never leaves this machine.
pub(crate) fn principal(home: &Path) -> anyhow::Result<SoftPasskey> {
    let path = home.join(PRINCIPAL_KEY);
    if !path.try_exists()? {
        hellas_private::create_dir_all_durable(home)?;
        let secret = loop {
            let secret = rand::random::<[u8; 32]>();
            if SoftPasskey::from_secret_scalar(secret).is_ok() {
                break secret;
            }
        };
        let mut file = hellas_private::private_tempfile(home, ".principal-", ".new")?;
        file.write_all(&secret)?;
        file.as_file().sync_all()?;
        // A concurrent first use created it; both use the one that won.
        if file.persist_noclobber(&path).is_ok() {
            hellas_private::sync_directory(home)?;
            eprintln!("Created principal key: {}", path.display());
        }
    }
    crate::commands::chain::passkey(&path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_home_principal_is_created_once_privately_and_then_selected() {
        let home = tempfile::tempdir().unwrap();
        let none = OwnerArgs::default();
        assert!(none.load(home.path()).unwrap().is_none());
        let created = principal(home.path()).unwrap();
        let path = home.path().join(PRINCIPAL_KEY);
        let original = std::fs::read(&path).unwrap();
        assert_eq!(
            principal(home.path()).unwrap().party_key(),
            created.party_key()
        );
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_eq!(
            none.load(home.path()).unwrap().unwrap().party_key(),
            created.party_key()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let outside = home.path().join("outside.key");
        std::fs::write(&outside, [0x41; 32]).unwrap();
        let explicit = OwnerArgs {
            passkey: Some(outside),
        };
        assert_ne!(
            explicit.load(home.path()).unwrap().unwrap().party_key(),
            created.party_key()
        );
        for removed in ["--faucet", "--faucet-account"] {
            assert!(
                <crate::Cli as clap::Parser>::try_parse_from(["hellas", removed, "serve"]).is_err()
            );
        }
    }
}
