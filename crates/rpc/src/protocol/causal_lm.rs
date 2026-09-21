//! Canonical environment interpreted by the Catena causal-LM application.
//!
//! This is application-owned data below [`crate::ProgramManifest::root`]. It
//! contains only the byte objects and ABI parameters needed to execute token
//! IDs. Tokenizers, templates, text decoding, acquisition hints, GPU dialects,
//! and provider-local architecture choices are deliberately absent.
//!
//! `causal-lm-0.0.1` fixes the entry-point ABI. Inputs are token IDs as one
//! borrowed `u64` buffer, the ordered owned state buffers, capacity and position
//! as `u64`, then the ordered borrowed static slices. Outputs are replacement
//! owned states, one owned `f32` logits buffer with `vocabulary_size` elements,
//! and one greedy token as `u64`. Catena entry-point metadata supplies the value
//! kinds, so this object does not repeat them.
//!
//! Every environment commits `[fixed_capacity, prefill_chunk_tokens]`: prefill
//! calls consume consecutive chunks of that size (the last may be shorter),
//! discard intermediate predictions, and decode one token per call thereafter.
//! Schedules can differ for arbitrary programs and have distinct content IDs.
//! Providers may reuse an exact-prefix checkpoint only if all mutable state is
//! restored independently at the same capacity and chunk boundary.

use crate::{Application, ContentId, DagCborEncoder, ProgramManifest};

use super::value::{CanonicalDecodeError, CanonicalDecoder};

/// Exact evaluator identity for the persistent Catena safe GPU runtime.
pub const CATENA_GPU_EVALUATOR: &str = "hellas/catena-gpu-0.0.1";
/// Exact adaptor identity for the token-native causal-LM ABI in this module.
pub const CAUSAL_LM_ADAPTOR: &str = "causal-lm-0.0.1";

/// Maximum canonical byte length of one causal-LM environment root.
pub const MAX_CAUSAL_LM_ENVIRONMENT_BYTES: usize = 256 * 1024;
/// Maximum aggregate bytes across the ordered logical static-input slices.
/// Repeated and overlapping slices each count toward this protocol ceiling.
pub const MAX_CAUSAL_LM_STATIC_BYTES: u64 = 1 << 40;
const MAX_ENTRYPOINT_BYTES: usize = 128;
const MAX_PROGRAM_BYTES: u64 = 16 * 1024 * 1024;
const MAX_STATIC_OBJECTS: usize = 64;
const MAX_STATIC_SLICES: usize = 4_096;
const MAX_STATES: usize = 8;
const MAX_STATE_BYTES: u64 = 1 << 40;
const MAX_VOCABULARY_SIZE: u64 = u32::MAX as u64 + 1;
const MAXIMUM_CAPACITY: u64 = 8_388_608;

/// An exact Xet-addressed content object and its expected byte length.
///
/// Acquisition must verify both before the object is compiled or lent to the
/// persistent Catena runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContentRef {
    id: ContentId,
    bytes: u64,
}

impl ContentRef {
    /// Names content together with the length its verified handle must expose.
    #[must_use]
    pub const fn new(id: ContentId, bytes: u64) -> Self {
        Self { id, bytes }
    }

    /// Returns the Xet content identifier.
    #[must_use]
    pub const fn id(self) -> ContentId {
        self.id
    }

    /// Returns the exact expected object length.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.bytes
    }
}

/// One ordered, read-only entry-point input borrowed from a static object.
///
/// `object` indexes [`CausalLmEnvironment::static_objects`]. `offset..offset +
/// bytes` is the view lent to Catena; the underlying object remains resident and
/// is not copied for each invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StaticSlice {
    object: u32,
    offset: u64,
    bytes: u64,
}

impl StaticSlice {
    /// Describes one ordered borrowed view into `object`.
    #[must_use]
    pub const fn new(object: u32, offset: u64, bytes: u64) -> Self {
        Self {
            object,
            offset,
            bytes,
        }
    }

    /// Returns the index into the environment's static-object table.
    #[must_use]
    pub const fn object(self) -> u32 {
        self.object
    }

    /// Returns the byte offset within the selected object.
    #[must_use]
    pub const fn offset(self) -> u64 {
        self.offset
    }

    /// Returns the nonzero byte length of the borrowed view.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.bytes
    }
}

/// Forward-call semantics committed by every causal-LM environment.
/// Capacity and chunk boundaries are observable by arbitrary Catena programs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CausalLmGenerationSchedule {
    pub fixed_capacity: u64,
    pub prefill_chunk_tokens: u32,
}

/// The complete token-native environment below a causal-LM manifest root.
///
/// Each state multiplier describes a zero-initialized `f32` allocation of
/// `capacity * multiplier` bytes. The state list and static-slice list are in ABI
/// order. Static objects are an index table only and every object must be
/// reachable from at least one slice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CausalLmEnvironment {
    program: ContentRef,
    entrypoint: String,
    static_objects: Vec<ContentRef>,
    static_inputs: Vec<StaticSlice>,
    state_bytes_per_capacity: Vec<u64>,
    vocabulary_size: u64,
    maximum_capacity: u64,
    generation_schedule: CausalLmGenerationSchedule,
}

impl CausalLmEnvironment {
    /// Builds and validates one complete causal-LM environment.
    ///
    /// The three vectors are ordered ABI data, not sets. Construction rejects
    /// unreachable or repeated static objects and any resource declaration over
    /// the application hard bounds.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        program: ContentRef,
        entrypoint: impl Into<String>,
        static_objects: Vec<ContentRef>,
        static_inputs: Vec<StaticSlice>,
        state_bytes_per_capacity: Vec<u64>,
        vocabulary_size: u64,
        maximum_capacity: u64,
        generation_schedule: CausalLmGenerationSchedule,
    ) -> Result<Self, CausalLmEnvironmentError> {
        let environment = Self {
            program,
            entrypoint: entrypoint.into(),
            static_objects,
            static_inputs,
            state_bytes_per_capacity,
            vocabulary_size,
            maximum_capacity,
            generation_schedule,
        };
        environment.validate()?;
        Ok(environment)
    }

    /// Replaces the committed generation schedule.
    pub fn with_generation_schedule(
        mut self,
        schedule: CausalLmGenerationSchedule,
    ) -> Result<Self, CausalLmEnvironmentError> {
        self.generation_schedule = schedule;
        self.validate()?;
        Ok(self)
    }

    #[must_use]
    pub const fn generation_schedule(&self) -> CausalLmGenerationSchedule {
        self.generation_schedule
    }

    /// Returns the Catena source object.
    #[must_use]
    pub const fn program(&self) -> ContentRef {
        self.program
    }

    /// Returns the source-level Catena entry-point name.
    #[must_use]
    pub fn entrypoint(&self) -> &str {
        &self.entrypoint
    }

    /// Returns the unique static objects attached to the resident runtime.
    #[must_use]
    pub fn static_objects(&self) -> &[ContentRef] {
        &self.static_objects
    }

    /// Returns the ordered borrowed inputs into the static objects.
    #[must_use]
    pub fn static_inputs(&self) -> &[StaticSlice] {
        &self.static_inputs
    }

    /// Returns the ordered zeroed-state byte multipliers.
    #[must_use]
    pub fn state_bytes_per_capacity(&self) -> &[u64] {
        &self.state_bytes_per_capacity
    }

    /// Returns the number of legal token IDs and `f32` logits.
    #[must_use]
    pub const fn vocabulary_size(&self) -> u64 {
        self.vocabulary_size
    }

    /// Returns the greatest prompt-plus-generation capacity this root admits.
    #[must_use]
    pub const fn maximum_capacity(&self) -> u64 {
        self.maximum_capacity
    }

    /// Conservative logical heap retained by one owner of this metadata.
    ///
    /// This is computed directly from the fixed value and the requested
    /// capacities of its owned buffers; it does not serialize or otherwise
    /// allocate. Callers retaining the same value through an [`std::sync::Arc`]
    /// may deliberately charge this once per owner. Allocator bookkeeping is
    /// instead bounded by the owner's independent entry-count limit.
    #[must_use]
    pub fn retained_heap_bytes(&self) -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(self.entrypoint.capacity())?
            .checked_add(
                self.static_objects
                    .capacity()
                    .checked_mul(std::mem::size_of::<ContentRef>())?,
            )?
            .checked_add(
                self.static_inputs
                    .capacity()
                    .checked_mul(std::mem::size_of::<StaticSlice>())?,
            )?
            .checked_add(
                self.state_bytes_per_capacity
                    .capacity()
                    .checked_mul(std::mem::size_of::<u64>())?,
            )
    }

    /// Strict DAG-CBOR array encoding selected by `causal-lm-0.0.1`.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = DagCborEncoder::new();
        encoder.array(8);
        encode_content_ref(&mut encoder, self.program);
        encoder.str(&self.entrypoint);
        encoder.array(self.static_objects.len() as u64);
        for object in &self.static_objects {
            encode_content_ref(&mut encoder, *object);
        }
        encoder.array(self.static_inputs.len() as u64);
        for slice in &self.static_inputs {
            encoder.array(3);
            encoder.u64(u64::from(slice.object));
            encoder.u64(slice.offset);
            encoder.u64(slice.bytes);
        }
        encoder.array(self.state_bytes_per_capacity.len() as u64);
        for multiplier in &self.state_bytes_per_capacity {
            encoder.u64(*multiplier);
        }
        encoder.u64(self.vocabulary_size);
        encoder.u64(self.maximum_capacity);
        encoder.array(2);
        encoder.u64(self.generation_schedule.fixed_capacity);
        encoder.u64(u64::from(self.generation_schedule.prefill_chunk_tokens));
        encoder.into_bytes()
    }

    /// Decodes, bounds, validates, and reproduces the strict canonical bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CausalLmEnvironmentError> {
        if bytes.len() > MAX_CAUSAL_LM_ENVIRONMENT_BYTES {
            return Err(CausalLmEnvironmentError::Invalid(format!(
                "causal-LM environment is {} bytes, over the {MAX_CAUSAL_LM_ENVIRONMENT_BYTES}-byte limit",
                bytes.len()
            )));
        }
        let mut decoder = CanonicalDecoder::new(bytes);
        let field_count = decoder.array_len()?;
        if field_count != 8 {
            return Err(
                CanonicalDecodeError::new("causal-LM environment must contain 8 fields").into(),
            );
        }
        let program = decode_content_ref(&mut decoder)?;
        let entrypoint = decoder.str()?;
        validate_entrypoint(entrypoint)?;
        let entrypoint = entrypoint.to_string();

        let object_count = decoder.array_len()?;
        if object_count > MAX_STATIC_OBJECTS {
            return Err(CausalLmEnvironmentError::Invalid(format!(
                "causal-LM environment has {object_count} static objects, over the {MAX_STATIC_OBJECTS} object limit"
            )));
        }
        let mut static_objects = Vec::with_capacity(object_count);
        for _ in 0..object_count {
            static_objects.push(decode_content_ref(&mut decoder)?);
        }

        let slice_count = decoder.array_len()?;
        if slice_count > MAX_STATIC_SLICES {
            return Err(CausalLmEnvironmentError::Invalid(format!(
                "causal-LM environment has {slice_count} static slices, over the {MAX_STATIC_SLICES} slice limit"
            )));
        }
        let mut static_inputs = Vec::with_capacity(slice_count);
        for _ in 0..slice_count {
            decoder.array_exact(3)?;
            static_inputs.push(StaticSlice::new(
                decoder.u32()?,
                decoder.u64()?,
                decoder.u64()?,
            ));
        }

        let state_count = decoder.array_len()?;
        if state_count > MAX_STATES {
            return Err(CausalLmEnvironmentError::Invalid(format!(
                "causal-LM environment has {state_count} states, over the {MAX_STATES} state limit"
            )));
        }
        let mut state_bytes_per_capacity = Vec::with_capacity(state_count);
        for _ in 0..state_count {
            state_bytes_per_capacity.push(decoder.u64()?);
        }

        let vocabulary_size = decoder.u64()?;
        let maximum_capacity = decoder.u64()?;
        decoder.array_exact(2)?;
        let schedule = CausalLmGenerationSchedule {
            fixed_capacity: decoder.u64()?,
            prefill_chunk_tokens: decoder.u32()?,
        };
        decoder.finish()?;

        let environment = Self::new(
            program,
            entrypoint,
            static_objects,
            static_inputs,
            state_bytes_per_capacity,
            vocabulary_size,
            maximum_capacity,
            schedule,
        )?;
        if environment.canonical_bytes() != bytes {
            return Err(CanonicalDecodeError::new(
                "causal-LM environment is not in canonical DAG-CBOR form",
            )
            .into());
        }
        Ok(environment)
    }

    /// Returns the Xet content identifier of the canonical environment bytes.
    #[must_use]
    pub fn content_id(&self) -> ContentId {
        ContentId::hash(&self.canonical_bytes())
    }

    /// Wraps this environment root in its exact generic application identity.
    #[must_use]
    pub fn manifest(&self) -> ProgramManifest {
        let application = Application::new(CATENA_GPU_EVALUATOR, CAUSAL_LM_ADAPTOR)
            .expect("causal-LM protocol application IDs are valid");
        ProgramManifest::new(application, self.content_id())
    }

    fn validate(&self) -> Result<(), CausalLmEnvironmentError> {
        let schedule = self.generation_schedule;
        invalid_if(
            schedule.fixed_capacity == 0 || schedule.fixed_capacity > self.maximum_capacity,
            "fixed generation capacity must be in 1..=maximum_capacity",
        )?;
        invalid_if(
            schedule.prefill_chunk_tokens == 0
                || u64::from(schedule.prefill_chunk_tokens) > schedule.fixed_capacity,
            "prefill chunk must be in 1..=fixed_capacity",
        )?;
        invalid_if(
            self.program.bytes == 0 || self.program.bytes > MAX_PROGRAM_BYTES,
            format!(
                "Catena program length must be in 1..={MAX_PROGRAM_BYTES} bytes, got {}",
                self.program.bytes
            ),
        )?;
        validate_entrypoint(&self.entrypoint)?;
        invalid_if(
            self.static_objects.len() > MAX_STATIC_OBJECTS,
            format!(
                "causal-LM environment has {} static objects, over the {MAX_STATIC_OBJECTS} object limit",
                self.static_objects.len()
            ),
        )?;
        invalid_if(
            self.static_inputs.len() > MAX_STATIC_SLICES,
            format!(
                "causal-LM environment has {} static slices, over the {MAX_STATIC_SLICES} slice limit",
                self.static_inputs.len()
            ),
        )?;
        invalid_if(
            self.state_bytes_per_capacity.len() > MAX_STATES,
            format!(
                "causal-LM environment has {} states, over the {MAX_STATES} state limit",
                self.state_bytes_per_capacity.len()
            ),
        )?;

        let mut static_bytes = 0_u64;
        for (index, object) in self.static_objects.iter().enumerate() {
            invalid_if(object.bytes == 0, "static objects must not be empty")?;
            invalid_if(
                self.static_objects[..index]
                    .iter()
                    .any(|previous| previous.id == object.id),
                format!("static object {index} repeats content id {}", object.id),
            )?;
            static_bytes = static_bytes.checked_add(object.bytes).ok_or_else(|| {
                CausalLmEnvironmentError::Invalid(
                    "aggregate static object length overflowed u64".to_string(),
                )
            })?;
        }
        invalid_if(
            static_bytes > MAX_CAUSAL_LM_STATIC_BYTES,
            format!(
                "causal-LM static objects total {static_bytes} bytes, over the {MAX_CAUSAL_LM_STATIC_BYTES}-byte limit"
            ),
        )?;

        let mut referenced_objects = [false; MAX_STATIC_OBJECTS];
        let mut static_input_bytes = 0_u64;
        for (index, slice) in self.static_inputs.iter().enumerate() {
            invalid_if(slice.bytes == 0, format!("static slice {index} is empty"))?;
            let object_index = usize::try_from(slice.object).map_err(|_| {
                CausalLmEnvironmentError::Invalid(format!(
                    "static slice {index} object index exceeds usize"
                ))
            })?;
            let object = self.static_objects.get(object_index).ok_or_else(|| {
                CausalLmEnvironmentError::Invalid(format!(
                    "static slice {index} names missing object {}",
                    slice.object
                ))
            })?;
            referenced_objects[object_index] = true;
            let end = slice.offset.checked_add(slice.bytes).ok_or_else(|| {
                CausalLmEnvironmentError::Invalid(format!(
                    "static slice {index} byte range overflowed u64"
                ))
            })?;
            invalid_if(
                end > object.bytes,
                format!(
                    "static slice {index} range {}..{end} exceeds object {} ({} bytes)",
                    slice.offset, slice.object, object.bytes
                ),
            )?;
            static_input_bytes = static_input_bytes.checked_add(slice.bytes).ok_or_else(|| {
                CausalLmEnvironmentError::Invalid(
                    "aggregate static input length overflowed u64".to_string(),
                )
            })?;
        }
        invalid_if(
            static_input_bytes > MAX_CAUSAL_LM_STATIC_BYTES,
            format!(
                "causal-LM static inputs total {static_input_bytes} bytes, over the {MAX_CAUSAL_LM_STATIC_BYTES}-byte limit"
            ),
        )?;
        if let Some(index) = referenced_objects[..self.static_objects.len()]
            .iter()
            .position(|referenced| !referenced)
        {
            return Err(CausalLmEnvironmentError::Invalid(format!(
                "static object {index} is not reachable from any input slice"
            )));
        }

        invalid_if(
            !(1..=MAXIMUM_CAPACITY).contains(&self.maximum_capacity),
            format!(
                "maximum capacity must be in 1..={MAXIMUM_CAPACITY}, got {}",
                self.maximum_capacity
            ),
        )?;
        let mut state_bytes = 0_u64;
        for (index, multiplier) in self.state_bytes_per_capacity.iter().enumerate() {
            invalid_if(
                *multiplier == 0,
                format!("state {index} has a zero byte multiplier"),
            )?;
            invalid_if(
                !multiplier.is_multiple_of(4),
                format!("state {index} byte multiplier is not divisible by four"),
            )?;
            let bytes = multiplier
                .checked_mul(self.maximum_capacity)
                .ok_or_else(|| {
                    CausalLmEnvironmentError::Invalid(format!(
                        "state {index} allocation overflows u64 at maximum capacity"
                    ))
                })?;
            state_bytes = state_bytes.checked_add(bytes).ok_or_else(|| {
                CausalLmEnvironmentError::Invalid(
                    "aggregate state allocation overflowed u64".to_string(),
                )
            })?;
        }
        invalid_if(
            state_bytes > MAX_STATE_BYTES,
            format!(
                "causal-LM states total {state_bytes} bytes at maximum capacity, over the {MAX_STATE_BYTES}-byte limit"
            ),
        )?;
        invalid_if(
            !(1..=MAX_VOCABULARY_SIZE).contains(&self.vocabulary_size),
            format!(
                "vocabulary size must be in 1..={MAX_VOCABULARY_SIZE}, got {}",
                self.vocabulary_size
            ),
        )?;
        invalid_if(
            self.canonical_bytes().len() > MAX_CAUSAL_LM_ENVIRONMENT_BYTES,
            format!(
                "canonical causal-LM environment exceeds the {MAX_CAUSAL_LM_ENVIRONMENT_BYTES}-byte limit"
            ),
        )
    }
}

fn validate_entrypoint(entrypoint: &str) -> Result<(), CausalLmEnvironmentError> {
    invalid_if(
        entrypoint.is_empty() || entrypoint.len() > MAX_ENTRYPOINT_BYTES,
        format!(
            "Catena entrypoint must be 1..={MAX_ENTRYPOINT_BYTES} UTF-8 bytes, got {}",
            entrypoint.len()
        ),
    )
}

fn encode_content_ref(encoder: &mut DagCborEncoder, content: ContentRef) {
    encoder.array(2);
    encoder.bytes(content.id.as_bytes());
    encoder.u64(content.bytes);
}

fn decode_content_ref(
    decoder: &mut CanonicalDecoder<'_>,
) -> Result<ContentRef, CanonicalDecodeError> {
    decoder.array_exact(2)?;
    Ok(ContentRef::new(
        ContentId::from_bytes(decoder.bytes_32()?),
        decoder.u64()?,
    ))
}

fn invalid_if(condition: bool, message: impl Into<String>) -> Result<(), CausalLmEnvironmentError> {
    if condition {
        Err(CausalLmEnvironmentError::Invalid(message.into()))
    } else {
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CausalLmEnvironmentError {
    /// The bytes are not the one strict DAG-CBOR spelling of this environment.
    #[error("invalid canonical causal-LM environment: {0}")]
    Canonical(#[from] CanonicalDecodeError),
    /// The decoded environment violates the causal-LM application contract.
    #[error("invalid causal-LM environment: {0}")]
    Invalid(String),
}

#[cfg(test)]
mod tests;
