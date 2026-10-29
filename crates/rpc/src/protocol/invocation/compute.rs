//! A program, immutable bytes, and a caller-declared sequence of calls.
use serde::{Deserialize, Serialize};

use crate::ContentRef;

pub const EVALUATOR: &str = "hellas/catena-d116170a7e66";
pub const MAX_ENVIRONMENT_BYTES: usize = 1 << 20;
// Every reference contains at least its 32-byte content identifier.
pub const MAX_ENVIRONMENT_REFERENCES: usize = MAX_ENVIRONMENT_BYTES / 32;
pub const MAX_SOURCE_BYTES: u64 = 16 << 20;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Environment {
    pub sources: Vec<ContentRef>,
    pub assets: Vec<NamedAsset>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedAsset {
    pub name: String,
    pub object: ContentRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub calls: Vec<Call>,
    pub step: Option<Step>,
    pub outputs: Vec<Declared>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Call {
    pub entry: String,
    pub args: Vec<Arg>,
    pub bind: Vec<Bind>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub entry: String,
    pub args: Vec<StepArg>,
    pub bind: Vec<Bind>,
    pub emit: String,
    pub stop: Stop,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum Arg {
    Bool(bool),
    U16(u16),
    U32(u32),
    U64(u64),
    F32Bits(u32),
    Input {
        object: String,
    },
    Zeroed {
        bytes: u64,
    },
    Asset {
        name: String,
        offset: u64,
        bytes: u64,
    },
    Slot {
        name: String,
    },
    Counter {
        base: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum StepArg {
    Arg(Arg),
    FirstThen { first: Arg, then: Arg },
}

impl StepArg {
    pub fn at(&self, step: u64) -> &Arg {
        match self {
            Self::Arg(arg) => arg,
            Self::FirstThen { first, then } => {
                if step == 0 {
                    first
                } else {
                    then
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum Bind {
    Name(String),
    Discard,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stop {
    pub any_of: Vec<u64>,
    pub max_steps: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ValueKind {
    Bool,
    U16,
    U32,
    U64,
    F32,
    MemOwn,
    MemRef,
}

impl ValueKind {
    pub fn scalar_bytes(self) -> Option<u64> {
        match self {
            Self::Bool => Some(1),
            Self::U16 => Some(2),
            Self::U32 | Self::F32 => Some(4),
            Self::U64 => Some(8),
            Self::MemOwn | Self::MemRef => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Declared {
    pub slot: String,
    pub kind: OutputKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum OutputKind {
    Scalar(ValueKind),
    Buffer { max_bytes: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum StopReason {
    Matched(u64),
    MaxSteps,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunMetadata {
    pub steps: u64,
    pub stop: Option<StopReason>,
}

impl OutputKind {
    pub fn format(&self) -> &'static str {
        match self {
            Self::Scalar(ValueKind::Bool) => "catena.bool.v1",
            Self::Scalar(ValueKind::U16) => "catena.u16le.v1",
            Self::Scalar(ValueKind::U32) => "catena.u32le.v1",
            Self::Scalar(ValueKind::U64) => "catena.u64le.v1",
            Self::Scalar(ValueKind::F32) => "catena.f32le.v1",
            _ => "catena.bytes.v1",
        }
    }
}

/// A failed prefix still consumes the owner's output allowance.
pub fn validate_failed_output(
    output: &super::output::InvocationOutput,
    max_output_bytes: u64,
) -> Result<(), crate::value::CanonicalDecodeError> {
    let bytes = output.artifacts.iter().try_fold(0u64, |sum, artifact| {
        sum.checked_add(artifact.bytes.as_bytes().len() as u64)
    });
    if bytes.is_none_or(|bytes| bytes > max_output_bytes) {
        return Err(super::error(
            "failed compute prefix exceeds its output bound",
        ));
    }
    Ok(())
}

/// Authentication establishes provenance; this check establishes conformance to
/// the caller's declared output shapes and stop rule, without re-execution.
pub fn validate_output(
    plan: &Plan,
    output: &super::output::InvocationOutput,
) -> Result<(), crate::value::CanonicalDecodeError> {
    use super::{error, validate_artifacts};
    if !output.is_success() {
        return Err(error("failed invocation has no payable compute result"));
    }
    validate_artifacts(&output.artifacts)?;
    let metadata: RunMetadata =
        crate::value::decode_canonical_dag_cbor(output.metadata.as_bytes())?;
    let expected = plan.outputs.len() + usize::from(plan.step.is_some());
    if output.artifacts.len() != expected {
        return Err(error("compute output artifact count mismatch"));
    }
    for d in &plan.outputs {
        let artifact = output
            .artifacts
            .iter()
            .find(|a| a.name == d.slot)
            .ok_or_else(|| error("missing declared output"))?;
        let bytes = artifact.bytes.as_bytes();
        let valid = match d.kind {
            OutputKind::Scalar(kind) => {
                kind.scalar_bytes() == Some(bytes.len() as u64)
                    && (kind != ValueKind::Bool || bytes[0] <= 1)
            }
            OutputKind::Buffer { max_bytes } => bytes.len() as u64 <= max_bytes,
        };
        if !valid || artifact.format != d.kind.format() {
            return Err(error("declared compute output shape mismatch"));
        }
    }
    match &plan.step {
        None if metadata.steps == 0 && metadata.stop.is_none() => Ok(()),
        Some(step) => {
            let artifact = output
                .artifacts
                .iter()
                .find(|a| a.name == "emitted")
                .ok_or_else(|| error("missing emitted output"))?;
            let bytes = artifact.bytes.as_bytes();
            if artifact.format != "catena.u64le.v1"
                || !bytes.len().is_multiple_of(8)
                || metadata.steps != (bytes.len() / 8) as u64
                || metadata.steps == 0
                || metadata.steps > step.stop.max_steps
            {
                return Err(error("invalid compute step count"));
            }
            let values: Vec<_> = bytes
                .as_chunks::<8>()
                .0
                .iter()
                .map(|b| u64::from_le_bytes(*b))
                .collect();
            if values[..values.len() - 1]
                .iter()
                .any(|v| step.stop.any_of.contains(v))
            {
                return Err(error("compute continued after stop value"));
            }
            let last = *values.last().unwrap();
            let expected = if step.stop.any_of.contains(&last) {
                StopReason::Matched(last)
            } else if metadata.steps == step.stop.max_steps {
                StopReason::MaxSteps
            } else {
                return Err(error("compute stopped before its stop rule"));
            };
            if metadata.stop != Some(expected) {
                return Err(error("compute stop reason mismatch"));
            }
            Ok(())
        }
        _ => Err(error("unexpected compute step metadata")),
    }
}

pub const ADAPTOR: &str = "compute-0.0.1";
impl Environment {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, crate::value::CanonicalDecodeError> {
        super::encode(&("hellas.compute.environment.v1", self))
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, crate::value::CanonicalDecodeError> {
        use crate::protocol::value::CanonicalDecoder;
        super::bound(bytes, MAX_ENVIRONMENT_BYTES)?;
        let mut decoder = CanonicalDecoder::new(bytes);
        decoder.array_exact(2)?;
        decoder.expect_str("hellas.compute.environment.v1")?;
        decoder.map_exact(2)?;
        decoder.expect_str("assets")?;
        let assets_len = decoder.array_len()?;
        if assets_len > MAX_ENVIRONMENT_REFERENCES {
            return Err(super::error("too many compute content references"));
        }
        let mut assets = Vec::with_capacity(assets_len);
        for _ in 0..assets_len {
            decoder.map_exact(2)?;
            decoder.expect_str("name")?;
            let name = decoder.str()?;
            super::label(name)?;
            let name = name.to_owned();
            decoder.expect_str("object")?;
            assets.push(NamedAsset {
                name,
                object: decode_ref(&mut decoder)?,
            });
        }
        decoder.expect_str("sources")?;
        let sources_len = decoder.array_len()?;
        if sources_len > MAX_ENVIRONMENT_REFERENCES - assets_len {
            return Err(super::error("too many compute content references"));
        }
        let mut sources = Vec::with_capacity(sources_len);
        for _ in 0..sources_len {
            sources.push(decode_ref(&mut decoder)?);
        }
        decoder.finish()?;
        Ok(Self { sources, assets })
    }
    pub fn manifest(&self) -> Result<crate::ProgramManifest, crate::value::CanonicalDecodeError> {
        Ok(crate::ProgramManifest::new(
            crate::Application::new(EVALUATOR, ADAPTOR).map_err(|e| super::error(e.to_string()))?,
            crate::ContentId::hash(&self.canonical_bytes()?),
        ))
    }
}
fn decode_ref(
    decoder: &mut crate::protocol::value::CanonicalDecoder<'_>,
) -> Result<ContentRef, crate::value::CanonicalDecodeError> {
    decoder.map_exact(2)?;
    decoder.expect_str("id")?;
    let id = crate::ContentId::from_bytes(decoder.bytes_32()?);
    decoder.expect_str("bytes")?;
    Ok(ContentRef::new(id, decoder.u64()?))
}
impl Plan {
    /// Bounds decidable before program acquisition or native compilation.
    pub fn validate_bounds(
        &self,
        limits: &super::Limits,
    ) -> Result<u64, crate::value::CanonicalDecodeError> {
        use super::{MAX_ARTIFACTS, error, label};
        use std::collections::BTreeSet;
        limits.validate()?;
        if self
            .outputs
            .len()
            .checked_add(usize::from(self.step.is_some()))
            .is_none_or(|n| n > MAX_ARTIFACTS)
        {
            return Err(error("compute declares too many output artifacts"));
        }
        let steps = self.step.as_ref().map_or(0, |step| step.stop.max_steps);
        if self.step.is_some() && (steps == 0 || steps > limits.max_steps) {
            return Err(error("compute step bound exceeds policy"));
        }
        let mut output = steps
            .checked_mul(8)
            .ok_or_else(|| error("compute output bound overflow"))?;
        let mut names = BTreeSet::new();
        for declared in &self.outputs {
            label(&declared.slot)?;
            if !names.insert(&declared.slot) || (self.step.is_some() && declared.slot == "emitted")
            {
                return Err(error("compute output labels must be unique"));
            }
            let bytes = match declared.kind {
                OutputKind::Scalar(kind) => kind
                    .scalar_bytes()
                    .ok_or_else(|| error("compute scalar output has a memory kind"))?,
                OutputKind::Buffer { max_bytes } => max_bytes,
            };
            output = output
                .checked_add(bytes)
                .ok_or_else(|| error("compute output bound overflow"))?;
        }
        if output > limits.max_output_bytes || output > super::MAX_INVOCATION_BYTES as u64 {
            return Err(error(
                "compute output bound exceeds policy or protocol limit",
            ));
        }
        Ok(output)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, crate::value::CanonicalDecodeError> {
        super::encode(&("hellas.compute.plan.v1", self))
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, crate::value::CanonicalDecodeError> {
        super::bound(bytes, 1 << 20)?;
        let (domain, plan): (String, Self) = crate::value::decode_canonical_dag_cbor(bytes)?;
        super::domain_is(&domain, "hellas.compute.plan.v1")?;
        Ok(plan)
    }
}
