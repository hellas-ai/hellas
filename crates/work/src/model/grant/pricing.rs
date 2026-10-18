//! Operator prices in USD micro-units. These are Hellas rates, not vendor invoices.
use super::budget::{Charge, Meter};
use hellas_auth::authority::Revision;
use serde::{Deserialize, Serialize};
use std::num::NonZeroU64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pricing {
    pub revision: Revision,
    /// None is unpriced; an empty table explicitly rates all usage at zero.
    /// Unlisted usage meters have zero price. A rate may never price money itself.
    pub rates: Option<Vec<UnitPrice>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitPrice {
    pub meter: Meter,
    pub usd_micros: u64,
    pub units: NonZeroU64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PricingError {
    #[error("invalid price revision or rate table")]
    Invalid,
    #[error("rated charge exceeds the money counter")]
    Overflow,
}

impl Pricing {
    pub fn validate(&self) -> Result<(), PricingError> {
        if self.revision.0 == 0 {
            return Err(PricingError::Invalid);
        }
        if let Some(rates) = &self.rates
            && (rates.len() > 4
                || !hellas_rpc::protocol::value::all_distinct(rates.iter().map(|r| r.meter))
                || rates.iter().any(|r| r.meter == Meter::UsdMicros))
        {
            return Err(PricingError::Invalid);
        }
        Ok(())
    }

    /// Each rated component rounds up once per job, for reservation and settlement.
    /// u128 products are exact for two u64 factors; the summed charge must fit u64.
    pub fn quote(&self, usage: Charge) -> Result<Option<u64>, PricingError> {
        self.validate()?;
        let Some(rates) = &self.rates else {
            return Ok(None);
        };
        let mut total = 0u64;
        for rate in rates {
            let product = u128::from(usage.get(rate.meter)) * u128::from(rate.usd_micros);
            let cost = u64::try_from(product.div_ceil(u128::from(rate.units.get())))
                .map_err(|_| PricingError::Overflow)?;
            total = total.checked_add(cost).ok_or(PricingError::Overflow)?;
        }
        Ok(Some(total))
    }

    pub fn reserve(&self, mut usage: Charge) -> Result<Charge, PricingError> {
        usage.set(Meter::UsdMicros, self.quote(usage)?.unwrap_or(0));
        Ok(usage)
    }

    /// Never refund an unrepresentable verified overrun. Because admission used
    /// these same monotone rates and succeeded, overflow implies a usage overrun;
    /// the ledger retains the exhausted money counter and quarantines the resource.
    pub fn settle(&self, mut usage: Charge) -> Result<Charge, PricingError> {
        let amount = match self.quote(usage) {
            Ok(value) => value.unwrap_or(0),
            Err(PricingError::Overflow) => u64::MAX,
            Err(error) => return Err(error),
        };
        usage.set(Meter::UsdMicros, amount);
        Ok(usage)
    }
}
