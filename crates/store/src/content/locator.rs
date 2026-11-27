use super::{Error, Source, validate_https};
use hellas_rpc::ContentId;
use iroh::EndpointAddr;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, net::SocketAddr, str::FromStr};
use url::Url;

pub(super) const NO_PEER: &str = "no peer known to hold ID; add ?seed=";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Locator {
    Hellas {
        id: ContentId,
        seeds: Vec<EndpointAddr>,
    },
    Hub(crate::hf::ModelReference),
    Https(Url),
}

impl Locator {
    pub fn into_source(
        self,
        bytes: Option<u64>,
        sha256: Option<[u8; 32]>,
    ) -> super::Result<Source> {
        match self {
            Self::Hellas { id, seeds } if sha256.is_none() => Ok(Source::Peer { id, seeds }),
            Self::Hub(reference) if sha256.is_none() => Ok(Source::HfXet {
                repo: reference.repo,
                path: reference.selector,
            }),
            Self::Https(url) => Ok(Source::Https { url, bytes, sha256 }),
            _ => Err(Error::Invalid("--sha256 requires a plain HTTPS locator")),
        }
    }
}

pub(super) fn seed(value: &str) -> super::Result<EndpointAddr> {
    let (node, ip) = value
        .split_once('@')
        .map_or((value, None), |(node, ip)| (node, Some(ip)));
    let mut address = EndpointAddr::new(node.parse().map_err(|_| Error::Invalid("seed node ID"))?);
    if let Some(ip) = ip {
        address = address.with_ip_addr(
            ip.parse::<SocketAddr>()
                .map_err(|_| Error::Invalid("seed IP:port"))?,
        );
    }
    Ok(address)
}

pub(super) fn display_seed(seed: &EndpointAddr) -> String {
    let mut value = seed.id.to_string();
    if let Some(ip) = seed.ip_addrs().next() {
        value.push('@');
        value.push_str(&ip.to_string());
    }
    value
}

#[derive(Debug, thiserror::Error)]
pub enum LocatorError {
    #[error(transparent)]
    Content(#[from] Error),
    #[error(transparent)]
    Hub(#[from] crate::hf::FetchError),
}

impl FromStr for Locator {
    type Err = LocatorError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        if let Some(value) = value.strip_prefix("hellas://") {
            let (id, query) = value
                .split_once('?')
                .map_or((value, None), |(id, query)| (id, Some(query)));
            let id = id
                .parse()
                .map_err(|_| Error::Invalid("hellas content ID"))?;
            let seeds = query
                .map(|query| {
                    query
                        .split('&')
                        .map(|item| {
                            seed(
                                item.strip_prefix("seed=")
                                    .ok_or(Error::Invalid("expected seed="))?,
                            )
                        })
                        .collect::<super::Result<Vec<_>>>()
                })
                .transpose()?
                .unwrap_or_default();
            return Ok(Self::Hellas { id, seeds });
        }
        if value.starts_with("hf://") {
            return Ok(Self::Hub(crate::hf::ModelReference::parse(value)?));
        }
        let url = Url::parse(value).map_err(|_| Error::Invalid("expected a content locator"))?;
        validate_https(&url)?;
        if url.host_str() == Some("huggingface.co") {
            return Ok(Self::Hub(crate::hf::ModelReference::from_url(&url)?));
        }
        Ok(Self::Https(url))
    }
}

impl fmt::Display for Locator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hellas { id, seeds } => {
                write!(f, "hellas://{id}")?;
                for (i, seed) in seeds.iter().enumerate() {
                    let delimiter = if i == 0 { '?' } else { '&' };
                    write!(f, "{delimiter}seed={}", display_seed(seed))?;
                }
                Ok(())
            }
            Self::Hub(reference) => fmt::Display::fmt(reference, f),
            Self::Https(url) => fmt::Display::fmt(url, f),
        }
    }
}

impl Serialize for Locator {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Locator {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

pub(super) fn no_peer() -> Error {
    Error::Invalid(NO_PEER)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_locator_round_trips_ordered_seeds() {
        let id = ContentId::from_bytes([1; 32]);
        let first = iroh::SecretKey::from_bytes(&[2; 32]).public();
        let second = iroh::SecretKey::from_bytes(&[3; 32]).public();
        let text = format!("hellas://{id}?seed={first}@[::1]:8765&seed={second}");
        let locator: Locator = text.parse().unwrap();
        assert_eq!(locator.to_string(), text);
        let Locator::Hellas { id: parsed, seeds } = locator else {
            unreachable!();
        };
        assert_eq!(id, parsed);
        assert_eq!(seeds[0].id, first);
        assert_eq!(seeds[1].id, second);
        assert!(format!("hellas://{id}@{first}").parse::<Locator>().is_err());
    }
}
