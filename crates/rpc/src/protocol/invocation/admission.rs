//! Application checks exposed to funding code as neutral resource facts.
use super::{
    Admission, CapacityDomain, InvocationPolicy, Limits, MAX_INVOCATION_BYTES, PreparedInvocation,
    compute, error, output,
};
use crate::protocol::value::CanonicalDecodeError;
use crate::{ContentId, ContentRef, OutputEventEnvelope, ProgramManifest, Retention};
use hellas_auth::PublicKey;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionFacts {
    pub limits: Limits,
    pub capacity_domain: CapacityDomain,
    pub retention: Retention,
    pub max_encoded_prepared_input: u32,
    pub max_encoded_result_frame: u32,
    pub max_spool_bytes: u64,
    pub max_output_events: u64,
    pub max_transcript_payload_bytes: u64,
}
impl AdmissionFacts {
    fn for_admission(admission: &Admission, limits: Limits) -> Result<Self, CanonicalDecodeError> {
        let hard = MAX_INVOCATION_BYTES as u64;
        let (input, frame, spool, events, payload) = match admission {
            Admission::Compute { .. } => {
                let bounds = output::compute_bounds(limits)?;
                (
                    hard,
                    bounds.frame,
                    bounds.spool,
                    bounds.events,
                    bounds.payload,
                )
            }
            Admission::Fetch { admission } => {
                let framing = u64::from(admission.limits.max_output_events)
                    .saturating_mul(4)
                    .saturating_add(2);
                (
                    u64::from(admission.limits.max_encoded_prepared_input),
                    u64::from(admission.limits.max_encoded_result_frame),
                    admission.limits.max_spool_bytes,
                    limits.max_output_bytes.saturating_add(framing),
                    admission.limits.max_spool_bytes,
                )
            }
        };
        let spool = spool.min(hard);
        Ok(Self {
            limits,
            capacity_domain: admission.capacity_domain(),
            retention: admission.retention(),
            max_encoded_prepared_input: input.min(hard) as u32,
            max_encoded_result_frame: frame.min(spool).min(hard) as u32,
            max_spool_bytes: spool,
            max_output_events: events.min(spool),
            max_transcript_payload_bytes: payload.min(spool),
        })
    }
    fn union(&mut self, other: Self) -> Result<(), CanonicalDecodeError> {
        if self.capacity_domain != other.capacity_domain || self.retention != other.retention {
            return Err(error("ambiguous invocation capacity or retention"));
        }
        self.max_encoded_prepared_input = self
            .max_encoded_prepared_input
            .max(other.max_encoded_prepared_input);
        self.max_encoded_result_frame = self
            .max_encoded_result_frame
            .max(other.max_encoded_result_frame);
        self.max_spool_bytes = self.max_spool_bytes.max(other.max_spool_bytes);
        self.max_output_events = self.max_output_events.max(other.max_output_events);
        self.max_transcript_payload_bytes = self
            .max_transcript_payload_bytes
            .max(other.max_transcript_payload_bytes);
        Ok(())
    }
    fn check_events(
        &self,
        events: &[OutputEventEnvelope],
        encoded: &[u8],
    ) -> Result<(), CanonicalDecodeError> {
        if events.len() as u64 > self.max_output_events
            || encoded.len() as u64 > self.max_spool_bytes
        {
            return Err(error("invocation transcript exceeds event or spool bounds"));
        }
        for event in events {
            if super::encode(event)?.len() as u64 > u64::from(self.max_encoded_result_frame) {
                return Err(error("invocation output frame exceeds its bound"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedOutput {
    pub output: output::InvocationOutput,
    pub output_id: ContentId,
    pub transcript: ContentRef,
    pub transcript_bytes: Vec<u8>,
}

impl InvocationPolicy {
    /// The manifest opens one application-owned root. Funding code only needs
    /// these exact content identities and sizes, never application parameters.
    pub fn content_closure(
        &self,
        manifest: &ProgramManifest,
        program_root: &[u8],
    ) -> Result<Vec<ContentRef>, CanonicalDecodeError> {
        self.classify_manifest(manifest)?;
        if self
            .admissions_for(manifest)
            .any(|admission| matches!(admission, Admission::Fetch { .. }))
        {
            if !program_root.is_empty() {
                return Err(error("Fetch has no program-root content opening"));
            }
            return Ok(vec![]);
        }
        super::bound(program_root, compute::MAX_ENVIRONMENT_BYTES)?;
        let root = ContentRef::for_bytes(program_root);
        if root.id() != manifest.root() {
            return Err(error(
                "compute root opening differs from the signed manifest",
            ));
        }
        let environment = compute::Environment::from_canonical_bytes(program_root)?;
        let mut names = std::collections::BTreeSet::new();
        for asset in &environment.assets {
            if !names.insert(&asset.name) {
                return Err(error("compute asset names must be unique"));
            }
        }
        let source_bytes = environment
            .sources
            .iter()
            .try_fold(0u64, |sum, source| sum.checked_add(source.bytes()));
        if source_bytes.is_none_or(|bytes| bytes > compute::MAX_SOURCE_BYTES) {
            return Err(error("compute sources exceed the 16 MiB limit"));
        }
        let mut objects = std::collections::BTreeMap::new();
        for object in std::iter::once(root)
            .chain(environment.sources)
            .chain(environment.assets.into_iter().map(|asset| asset.object))
        {
            if objects
                .insert(object.id(), object.bytes())
                .is_some_and(|bytes| bytes != object.bytes())
            {
                return Err(error("compute content identity has conflicting lengths"));
            }
        }
        Ok(objects
            .into_iter()
            .map(|(id, bytes)| ContentRef::new(id, bytes))
            .collect())
    }

    /// Only admitted, known application metadata may determine staging retention.
    pub fn classify_manifest(
        &self,
        manifest: &ProgramManifest,
    ) -> Result<AdmissionFacts, CanonicalDecodeError> {
        self.validate()?;
        self.facts(self.admissions_for(manifest))
    }
    fn facts<'a>(
        &self,
        admissions: impl Iterator<Item = &'a Admission>,
    ) -> Result<AdmissionFacts, CanonicalDecodeError> {
        let mut facts: Option<AdmissionFacts> = None;
        for admission in admissions {
            let next = AdmissionFacts::for_admission(admission, self.limits)?;
            if let Some(facts) = &mut facts {
                facts.union(next)?;
            } else {
                facts = Some(next);
            }
        }
        facts.ok_or_else(|| error("invocation application is unknown or not admitted"))
    }
    fn matching_inputs<'a>(
        &'a self,
        prepared: &PreparedInvocation,
        caller: &PublicKey,
    ) -> Result<Vec<&'a Admission>, CanonicalDecodeError> {
        self.validate()?;
        prepared.validate()?;
        if prepared.application_policy.as_bytes() != self.canonical_bytes()?.as_slice() {
            return Err(error(
                "invocation application policy differs from the owner-approved policy",
            ));
        }
        let encoded = prepared.canonical_bytes()?;
        if encoded.len() > MAX_INVOCATION_BYTES {
            return Err(error("invocation input exceeds its byte bound"));
        }
        let manifest = prepared.manifest()?;
        let mut admitted = Vec::new();
        let mut last = None;
        for admission in self
            .admissions
            .iter()
            .filter(|admission| admission.admits_manifest(&manifest))
        {
            let facts = AdmissionFacts::for_admission(admission, self.limits)?;
            let result = if encoded.len() > facts.max_encoded_prepared_input as usize {
                Err(error("invocation input exceeds its admitted bound"))
            } else {
                match admission {
                    Admission::Compute { .. } => {
                        compute::Plan::from_canonical_bytes(prepared.input.parameters.as_bytes())
                            .and_then(|plan| plan.validate_bounds(&self.limits).map(|_| ()))
                    }
                    Admission::Fetch {
                        admission: _admission,
                    } => {
                        #[cfg(feature = "fetch")]
                        {
                            super::fetch::validate_input(
                                prepared,
                                _admission,
                                self.limits.max_output_bytes,
                                caller,
                            )
                            .map(|_| ())
                        }
                        #[cfg(not(feature = "fetch"))]
                        {
                            let _ = caller;
                            Err(error("Fetch support is disabled"))
                        }
                    }
                }
            };
            match result {
                Ok(()) => admitted.push(admission),
                Err(error) => last = Some(error),
            }
        }
        if admitted.is_empty() {
            return Err(
                last.unwrap_or_else(|| error("invocation application is unknown or not admitted"))
            );
        }
        Ok(admitted)
    }
    pub fn admit(
        &self,
        prepared: &PreparedInvocation,
        caller: &PublicKey,
    ) -> Result<AdmissionFacts, CanonicalDecodeError> {
        self.facts(self.matching_inputs(prepared, caller)?.into_iter())
    }
}
impl PreparedInvocation {
    pub fn verify_output(
        &self,
        policy: &InvocationPolicy,
        caller: &PublicKey,
        provider: &PublicKey,
        events: &[OutputEventEnvelope],
    ) -> Result<VerifiedOutput, CanonicalDecodeError> {
        let matching = policy.matching_inputs(self, caller)?;
        let capture = policy.facts(matching.iter().copied())?;
        // Bound retained input before encoding a second representation of it.
        let retained = events.iter().try_fold(0usize, |sum, event| {
            event
                .retained_heap_bytes()
                .and_then(|n| n.checked_add(4 * std::mem::size_of::<OutputEventEnvelope>()))
                .and_then(|n| sum.checked_add(n))
        });
        if retained.is_none_or(|n| n as u64 > capture.max_spool_bytes) {
            return Err(error(
                "invocation transcript exceeds its retained-memory bound",
            ));
        }
        let transcript_bytes = super::encode(&events)?;
        capture.check_events(events, &transcript_bytes)?;
        let output = output::verify(
            &self.request,
            provider,
            events,
            capture.max_transcript_payload_bytes as usize,
        )?;
        let mut accepted = false;
        for admission in matching {
            let facts = AdmissionFacts::for_admission(admission, policy.limits)?;
            if facts.check_events(events, &transcript_bytes).is_err() {
                continue;
            }
            let result = match admission {
                Admission::Compute { .. } => {
                    if output.is_success() {
                        compute::Plan::from_canonical_bytes(self.input.parameters.as_bytes())
                            .and_then(|plan| compute::validate_output(&plan, &output))
                    } else {
                        compute::validate_failed_output(&output, policy.limits.max_output_bytes)
                    }
                }
                Admission::Fetch {
                    admission: _admission,
                } => {
                    #[cfg(feature = "fetch")]
                    {
                        if output.is_success() {
                            super::fetch::validate_output(
                                self,
                                _admission,
                                policy.limits.max_output_bytes,
                                provider,
                                &output,
                            )
                        } else {
                            super::fetch::validate_failed_output(
                                _admission,
                                policy.limits.max_output_bytes,
                                &output,
                            )
                        }
                    }
                    #[cfg(not(feature = "fetch"))]
                    {
                        Err(error("Fetch support is disabled"))
                    }
                }
            };
            if result.is_ok() {
                accepted = true;
                break;
            }
        }
        if !accepted {
            return Err(error(
                "invocation result does not fit any applicable admission",
            ));
        }
        let output_id = output.content_id()?;
        let transcript = ContentRef::for_bytes(&transcript_bytes);
        Ok(VerifiedOutput {
            output,
            output_id,
            transcript,
            transcript_bytes,
        })
    }
}
