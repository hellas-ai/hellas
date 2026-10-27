//! Owner-approved terms for automatic paid-channel offers.
use super::{setup::ProviderChannelPolicy, work::*};
use hellas_auth::authority::Revision;
use hellas_kernel::{
    EdgeValues, Fees, MAX_OMIT_RESPONSE_BLOCKS, MIN_OMIT_RESPONSE_BLOCKS, NetworkId,
    work_payment_settlement,
};
use hellas_rpc::protocol::invocation::InvocationPolicy;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaidPolicy {
    pub channel_policy: PaidChannelPolicyV1,
    pub invocation_policy: InvocationPolicy,
    pub payment_policy: JobPaymentPolicyV2,
    #[serde(with = "edge_values")]
    pub expected_payment_values: EdgeValues,
    pub min_omit_response_blocks: u64,
    #[serde(default = "default_jobs_per_channel")]
    pub jobs_per_channel: u64,
    pub offers: OfferPolicy,
}

const fn default_jobs_per_channel() -> u64 {
    10
}
const fn redelegate() -> bool {
    true
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferPolicy {
    pub max_stake_per_client: u64,
    pub bond_lifetime_blocks: u64,
    pub max_open_offers: u32,
    pub omission_bond: u64,
    #[serde(default = "redelegate")]
    pub redelegate_payout: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredPaidPolicy {
    pub revision: Revision,
    pub policy_salt: [u8; 32],
    pub policy: PaidPolicy,
}

impl PaidPolicy {
    pub fn check(&self) -> Result<(), PaidWorkError> {
        self.invocation_policy.validate()?;
        self.payment_policy.check()?;
        let capacity = self
            .jobs_per_channel
            .checked_mul(self.payment_policy.fixed_price)
            .filter(|n| *n > 0)
            .ok_or(PaidWorkError::Mismatch {
                field: "jobs_per_channel",
            })?;
        let settlement =
            work_payment_settlement(self.expected_payment_values, self.offers.omission_bond)
                .ok_or(PaidWorkError::Mismatch {
                    field: "expected_payment_values",
                })?;
        if settlement.capacity() != capacity || self.offers.omission_bond <= capacity {
            return Err(PaidWorkError::Mismatch {
                field: "channel capacity or omission collateral",
            });
        }
        if self.channel_policy.compute_credit_limit < self.payment_policy.fixed_price
            || self.channel_policy.delivery_credit_limit < self.payment_policy.fixed_price
            || !(MIN_OMIT_RESPONSE_BLOCKS..=MAX_OMIT_RESPONSE_BLOCKS)
                .contains(&self.min_omit_response_blocks)
            || self.offers.max_stake_per_client == 0
            || self.offers.max_open_offers == 0
            || !(1..=1_000_000).contains(&self.offers.bond_lifetime_blocks)
        {
            return Err(PaidWorkError::Mismatch {
                field: "offer policy bounds",
            });
        }
        Ok(())
    }
}

impl StoredPaidPolicy {
    pub fn provider_policy(&self, network: NetworkId) -> ProviderChannelPolicy {
        ProviderChannelPolicy {
            network,
            policy_salt: self.policy_salt,
            channel_policy: self.policy.channel_policy,
            invocation_policy: self.policy.invocation_policy.clone(),
            payment_policy: self.policy.payment_policy,
            expected_payment_values: self.policy.expected_payment_values,
            min_omit_response_blocks: self.policy.min_omit_response_blocks,
        }
    }
}

pub(crate) mod edge_values {
    use super::*;
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Values {
        value: u64,
        reserve: u64,
        close_fees: CloseFees,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CloseFees {
        base: u64,
        slot: u64,
        proof: u64,
        lifetime: u64,
    }
    pub fn serialize<S: serde::Serializer>(value: &EdgeValues, s: S) -> Result<S::Ok, S::Error> {
        let fees = value.close_fees();
        Values {
            value: value.value(),
            reserve: value.reserve(),
            close_fees: CloseFees {
                base: fees.base(),
                slot: fees.slot(),
                proof: fees.proof(),
                lifetime: fees.lifetime(),
            },
        }
        .serialize(s)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<EdgeValues, D::Error> {
        let v = Values::deserialize(d)?;
        Ok(EdgeValues::new(
            v.value,
            v.reserve,
            Fees::new(
                v.close_fees.base,
                v.close_fees.slot,
                v.close_fees.proof,
                v.close_fees.lifetime,
            ),
        ))
    }
}
