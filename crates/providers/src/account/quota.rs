//! Read the existing exporter snapshot; scraping never polls a vendor.
use super::{AccountError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaSource {
    pub url: String,
    pub provider: String,
    pub upstream: String,
    pub account: String,
    pub max_age_seconds: u32,
    pub reserve: Reserve,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Reserve {
    RemainingRatio {
        minimum: f64,
        scope: String,
        windows: Vec<String>,
    },
    Credits {
        minimum: f64,
    },
}
impl QuotaSource {
    pub fn validate(&self) -> Result<()> {
        let url = url::Url::parse(&self.url).map_err(|_| AccountError("invalid quota URL"))?;
        if !matches!(url.scheme(), "http" | "https")
            || self.provider.is_empty()
            || self.upstream.is_empty()
            || self.account.is_empty()
            || self.max_age_seconds == 0
        {
            return Err(AccountError("invalid quota source"));
        }
        let minimum = match &self.reserve {
            Reserve::RemainingRatio {
                minimum,
                scope,
                windows,
            } => {
                if scope.is_empty()
                    || windows.is_empty()
                    || windows.iter().any(String::is_empty)
                    || *minimum > 1.
                {
                    return Err(AccountError("invalid ratio reserve"));
                }
                *minimum
            }
            Reserve::Credits { minimum } => *minimum,
        };
        if !minimum.is_finite() || minimum <= 0. {
            return Err(AccountError("reserve must be positive"));
        }
        Ok(())
    }
    pub async fn check(&self, client: &reqwest::Client, now: u64) -> Result<u64> {
        let mut response = client
            .get(&self.url)
            .send()
            .await
            .map_err(|_| AccountError("quota exporter unavailable"))?;
        if !response.status().is_success() {
            return Err(AccountError("quota exporter failed"));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| AccountError("quota read failed"))?
        {
            if bytes.len().saturating_add(chunk.len()) > 4 * 1024 * 1024 {
                return Err(AccountError("quota snapshot exceeds bound"));
            }
            bytes.extend_from_slice(&chunk);
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|_| AccountError("invalid quota snapshot"))?;
        self.check_snapshot(text, now)
    }
    pub fn check_snapshot(&self, text: &str, now: u64) -> Result<u64> {
        let samples: Vec<_> = text
            .lines()
            .filter(|l| {
                [
                    "llm_account_info{",
                    "llm_quota_data_fresh{",
                    "llm_quota_last_success_timestamp_seconds{",
                    "llm_quota_utilization_ratio{",
                    "llm_credits_balance{",
                ]
                .iter()
                .any(|prefix| l.starts_with(prefix))
            })
            .map(parse_sample)
            .collect::<Result<_>>()?;
        let value = |name: &str, extra: &[(&str, &str)]| -> Result<f64> {
            let mut found = samples.iter().filter(|s| {
                s.name == name
                    && s.labels.get("provider").map(String::as_str) == Some(&self.provider)
                    && extra
                        .iter()
                        .all(|(k, v)| s.labels.get(*k).map(String::as_str) == Some(*v))
            });
            let sample = found
                .next()
                .ok_or(AccountError("required quota metric missing"))?;
            if found.next().is_some() || !sample.value.is_finite() {
                return Err(AccountError("ambiguous or invalid quota metric"));
            }
            Ok(sample.value)
        };
        if value(
            "llm_account_info",
            &[("upstream", &self.upstream), ("account", &self.account)],
        )? != 1.
            || value("llm_quota_data_fresh", &[])? != 1.
        {
            return Err(AccountError("quota snapshot failed or stale"));
        }
        let timestamp = value("llm_quota_last_success_timestamp_seconds", &[])?.floor();
        if timestamp < 0.
            || timestamp > now as f64
            || now as f64 - timestamp > self.max_age_seconds as f64
        {
            return Err(AccountError("quota snapshot timestamp stale or in future"));
        }
        match &self.reserve {
            Reserve::Credits { minimum } => {
                if value("llm_credits_balance", &[])? < *minimum {
                    return Err(AccountError("upstream credit reserve reached"));
                }
            }
            Reserve::RemainingRatio {
                minimum,
                scope,
                windows,
            } => {
                for window in windows {
                    let used = value(
                        "llm_quota_utilization_ratio",
                        &[("scope", scope), ("window", window)],
                    )?;
                    if !(0. ..=1.).contains(&used) || used > 1. - *minimum {
                        return Err(AccountError("upstream quota reserve reached"));
                    }
                }
                // Also respect any additional window the exporter reports for this scope.
                for sample in &samples {
                    if sample.name == "llm_quota_utilization_ratio"
                        && sample.labels.get("provider") == Some(&self.provider)
                        && sample.labels.get("scope") == Some(scope)
                        && (!sample.value.is_finite()
                            || !(0. ..=1.).contains(&sample.value)
                            || sample.value > 1. - *minimum)
                    {
                        return Err(AccountError("upstream quota reserve reached"));
                    }
                }
            }
        }
        Ok(timestamp as u64 + u64::from(self.max_age_seconds))
    }
}
struct Sample {
    name: String,
    labels: BTreeMap<String, String>,
    value: f64,
}
fn parse_sample(line: &str) -> Result<Sample> {
    let fail = || AccountError("malformed exporter metric");
    let mut labels = BTreeMap::new();
    let (name, tail) = if let Some((name, rest)) = line.split_once('{') {
        let mut rest = rest;
        loop {
            let (key, value) = rest.split_once('=').ok_or_else(fail)?;
            let mut strings = serde_json::Deserializer::from_str(value).into_iter::<String>();
            let decoded = strings.next().ok_or_else(fail)?.map_err(|_| fail())?;
            let end = strings.byte_offset();
            if labels.insert(key.to_owned(), decoded).is_some() {
                return Err(fail());
            }
            rest = &value[end..];
            if let Some(tail) = rest.strip_prefix('}') {
                break (name, tail);
            }
            rest = rest.strip_prefix(',').ok_or_else(fail)?;
        }
    } else {
        line.split_once(char::is_whitespace).ok_or_else(fail)?
    };
    let mut fields = tail.split_whitespace();
    let value = fields
        .next()
        .ok_or_else(fail)?
        .parse()
        .map_err(|_| fail())?;
    if fields.next().is_some() {
        return Err(fail());
    }
    Ok(Sample {
        name: name.to_owned(),
        labels,
        value,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn source() -> QuotaSource {
        QuotaSource {
            url: "http://127.0.0.1:9184/metrics".into(),
            provider: "openai-personal".into(),
            upstream: "openai".into(),
            account: "personal".into(),
            max_age_seconds: 600,
            reserve: Reserve::RemainingRatio {
                minimum: 0.2,
                scope: "all".into(),
                windows: vec!["seven_day".into()],
            },
        }
    }
    fn snapshot(used: &str) -> String {
        format!(
            r#"llm_account_info{{provider="openai-personal",upstream="openai",account="personal"}} 1
llm_quota_data_fresh{{provider="openai-personal"}} 1
llm_quota_scrape_success{{provider="openai-personal"}} 1
llm_quota_last_success_timestamp_seconds{{provider="openai-personal"}} 1000
llm_quota_utilization_ratio{{provider="openai-personal",scope="all",window="seven_day"}} {used}
"#
        )
    }
    #[test]
    fn reserve_is_measured_and_fail_closed() {
        let source = source();
        assert!(source.check_snapshot(&snapshot("0.5"), 1001).is_ok());
        assert!(source.check_snapshot(&snapshot("0.8"), 1001).is_ok());
        assert!(
            source
                .check_snapshot(&snapshot("0.5").replace(" 1000", " 1000.5"), 1000)
                .is_ok()
        );
        for text in [
            snapshot("1"),
            snapshot("NaN"),
            snapshot("-1"),
            snapshot("0.5").replace(" 1000", " 2000"),
            snapshot("0.5").replace(" 1000", " 0"),
            snapshot("0.5").replace("seven_day", "daily"),
            snapshot("0.5").replace("personal\"}", "other\"}"),
            snapshot("0.5").replace("fresh{", "absent{"),
            snapshot("0.5") + &snapshot("0.5"),
        ] {
            assert!(source.check_snapshot(&text, 1001).is_err(), "{text}");
        }
        assert!(source.check_snapshot(&snapshot("0.5"), 1601).is_err());
    }
    #[test]
    fn credits_and_extra_windows_are_enforced() {
        let mut source = source();
        let text = snapshot("0.5")
            + "llm_quota_utilization_ratio{provider=\"openai-personal\",scope=\"all\",window=\"daily\"} 1\n";
        assert!(source.check_snapshot(&text, 1001).is_err());
        source.reserve = Reserve::Credits { minimum: 1. };
        assert!(
            source
                .check_snapshot(
                    &(snapshot("0.5") + "llm_credits_balance{provider=\"openai-personal\"} 0\n"),
                    1001
                )
                .is_err()
        );
        assert!(
            source
                .check_snapshot(
                    &(snapshot("0.5") + "llm_credits_balance{provider=\"openai-personal\"} 2\n"),
                    1001
                )
                .is_ok()
        );
    }
}
