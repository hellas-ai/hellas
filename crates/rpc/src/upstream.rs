//! Caller-signed TLS requirements and the peer observed by a Fetch driver.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamPolicy {
    pub host: String,
    pub spki_sha256: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamPeer {
    pub host: String,
    pub spki_sha256: String,
}

impl UpstreamPolicy {
    pub fn validate(&self) -> Result<(), &'static str> {
        let url = url::Url::parse(&format!("https://{}/", self.host))
            .map_err(|_| "invalid upstream host")?;
        if self.host.is_empty()
            || url.host_str() != Some(self.host.as_str())
            || url.port().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || self.spki_sha256.len() > 16
        {
            return Err("upstream policy requires an exact canonical TLS hostname");
        }
        for pin in &self.spki_sha256 {
            validate_pin(pin)?;
        }
        Ok(())
    }

    pub fn permits_host(&self, host: &str) -> Result<(), &'static str> {
        self.validate()?;
        if self.host != host {
            return Err("upstream hostname differs from caller-signed policy");
        }
        Ok(())
    }

    pub fn verify_peer(&self, peer: &UpstreamPeer) -> Result<(), &'static str> {
        self.permits_host(&peer.host)?;
        validate_pin(&peer.spki_sha256)?;
        if !self.spki_sha256.is_empty() && !self.spki_sha256.contains(&peer.spki_sha256) {
            return Err("observed upstream SPKI differs from caller-signed policy");
        }
        Ok(())
    }
}

pub fn validate_pin(pin: &str) -> Result<(), &'static str> {
    if pin.len() != 64
        || !pin
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err("SPKI must be 64 lowercase SHA-256 hex digits");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn policy_requires_exact_host_and_pin_and_rejects_url_syntax() {
        let policy = UpstreamPolicy {
            host: "api.example".into(),
            spki_sha256: vec!["ab".repeat(32)],
        };
        policy
            .verify_peer(&UpstreamPeer {
                host: "api.example".into(),
                spki_sha256: "ab".repeat(32),
            })
            .unwrap();
        assert!(
            policy
                .verify_peer(&UpstreamPeer {
                    host: "other.example".into(),
                    spki_sha256: "ab".repeat(32)
                })
                .is_err()
        );
        assert!(
            policy
                .verify_peer(&UpstreamPeer {
                    host: "api.example".into(),
                    spki_sha256: "cd".repeat(32)
                })
                .is_err()
        );
        for host in [
            "api.example/path",
            "user@api.example",
            "api.example:443",
            "API.EXAMPLE",
            "api.example?x",
            "",
        ] {
            assert!(
                UpstreamPolicy {
                    host: host.into(),
                    spki_sha256: vec![]
                }
                .validate()
                .is_err(),
                "{host}"
            );
        }
    }
}
