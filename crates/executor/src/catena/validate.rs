use std::collections::{BTreeMap, BTreeSet};

use catena_lang::runtime::{GeneratedFunction, RuntimeModule, ValueKind as NativeKind};
use hellas_channel::content::{ContentError, InvocationContent};
use hellas_rpc::{
    ContentRef,
    protocol::invocation::{Limits, compute::*},
};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid plan at call {call}, argument {index:?}: expected {expected}, got {actual}")]
pub struct InvalidPlan {
    pub call: usize,
    pub index: Option<usize>,
    pub expected: String,
    pub actual: String,
}

fn invalid(
    call: usize,
    index: Option<usize>,
    expected: impl ToString,
    actual: impl ToString,
) -> InvalidPlan {
    InvalidPlan {
        call,
        index,
        expected: expected.to_string(),
        actual: actual.to_string(),
    }
}

pub fn kind(kind: NativeKind) -> ValueKind {
    match kind {
        NativeKind::Bool => ValueKind::Bool,
        NativeKind::U16 => ValueKind::U16,
        NativeKind::U32 => ValueKind::U32,
        NativeKind::U64 => ValueKind::U64,
        NativeKind::F32 => ValueKind::F32,
        NativeKind::MemOwn => ValueKind::MemOwn,
        NativeKind::MemRef => ValueKind::MemRef,
    }
}

/// Check plan bounds and local have state without acquiring any missing content.
pub fn preflight(
    env: &Environment,
    inputs: &BTreeMap<String, ContentRef>,
    plan: &Plan,
    limits: &Limits,
    content: &InvocationContent,
) -> Result<(), InvalidPlan> {
    plan.validate_bounds(limits).map_err(|error| {
        invalid(
            plan.calls.len(),
            None,
            "plan within owner resource bounds",
            error,
        )
    })?;
    let source_bytes = env
        .sources
        .iter()
        .try_fold(0u64, |sum, s| sum.checked_add(s.bytes()));
    if source_bytes.is_none_or(|n| n > MAX_SOURCE_BYTES) {
        return Err(invalid(
            0,
            None,
            "source bytes <= 16 MiB",
            "source limit exceeded",
        ));
    }
    let mut objects = BTreeMap::new();
    let mut names = BTreeSet::new();
    for asset in &env.assets {
        if asset.name.is_empty() || !names.insert(&asset.name) {
            return Err(invalid(0, None, "unique nonempty asset name", &asset.name));
        }
    }
    for object in env
        .sources
        .iter()
        .chain(env.assets.iter().map(|a| &a.object))
        .chain(inputs.values())
    {
        if objects
            .insert(object.id(), object.bytes())
            .is_some_and(|bytes| bytes != object.bytes())
        {
            return Err(invalid(
                0,
                None,
                "one size per content identity",
                object.bytes(),
            ));
        }
    }
    let mut upload = Some(0u64);
    for (id, bytes) in objects {
        let held = if let Some(store) = content.retained_store() {
            store
                .open_verified(id.digest(), bytes)
                .map_err(|e| invalid(0, None, "verified local content", e))?
                .is_some()
        } else {
            match content.read(ContentRef::new(id, bytes)) {
                Ok(_) => true,
                Err(ContentError::Missing) => false,
                Err(error) => return Err(invalid(0, None, "verified RAM content", error)),
            }
        };
        if !held {
            upload = upload.and_then(|total| total.checked_add(bytes));
        }
    }
    if upload.is_none_or(|n| n > limits.max_upload_bytes) {
        return Err(invalid(
            0,
            None,
            format!("upload <= {}", limits.max_upload_bytes),
            "upload exceeds limit",
        ));
    }
    Ok(())
}

pub fn validate(
    module: &RuntimeModule,
    env: &Environment,
    inputs: &BTreeMap<String, ContentRef>,
    plan: &Plan,
    limits: &Limits,
    content: &InvocationContent,
) -> Result<(), InvalidPlan> {
    preflight(env, inputs, plan, limits, content)?;
    let mut slots = BTreeMap::new();
    for (i, call) in plan.calls.iter().enumerate() {
        check_call(
            module,
            env,
            inputs,
            i,
            &call.entry,
            &call.args.iter().collect::<Vec<_>>(),
            &call.bind,
            &mut slots,
            None,
        )?;
    }
    if let Some(step) = &plan.step {
        let i = plan.calls.len();
        check_call(
            module,
            env,
            inputs,
            i,
            &step.entry,
            &step.args.iter().map(|a| a.at(0)).collect::<Vec<_>>(),
            &step.bind,
            &mut slots,
            Some(0),
        )?;
        let first = slots.clone();
        // Validate the recurrent edge even for max_steps=1: a step template is a fixpoint.
        let rebound: BTreeSet<_> = step
            .bind
            .iter()
            .filter_map(|b| match b {
                Bind::Name(n) => Some(n),
                _ => None,
            })
            .collect();
        for (index, arg) in step.args.iter().enumerate() {
            if let Arg::Slot { name } = arg.at(1)
                && !rebound.contains(name)
            {
                return Err(invalid(i, Some(index), "slot rebound by step", name));
            }
        }
        check_call(
            module,
            env,
            inputs,
            i,
            &step.entry,
            &step.args.iter().map(|a| a.at(1)).collect::<Vec<_>>(),
            &step.bind,
            &mut slots,
            Some(step.stop.max_steps.saturating_sub(1)),
        )?;
        if first != slots {
            return Err(invalid(
                i,
                None,
                "stable step slot kinds",
                "slot flow is not a fixpoint",
            ));
        }
        if !matches!(
            slots.get(&step.emit),
            Some(ValueKind::U64 | ValueKind::MemOwn)
        ) {
            return Err(invalid(i, None, "emit U64 or MemOwn[8]", &step.emit));
        }
    }
    for d in &plan.outputs {
        let expected = match d.kind {
            OutputKind::Scalar(k) => k,
            OutputKind::Buffer { .. } => ValueKind::MemOwn,
        };
        if slots.get(&d.slot) != Some(&expected) {
            return Err(invalid(
                plan.calls.len(),
                None,
                format!("{expected:?}"),
                format!("slot {}: {:?}", d.slot, slots.get(&d.slot)),
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn check_call(
    module: &RuntimeModule,
    env: &Environment,
    inputs: &BTreeMap<String, ContentRef>,
    call: usize,
    entry: &str,
    args: &[&Arg],
    bind: &[Bind],
    slots: &mut BTreeMap<String, ValueKind>,
    step: Option<u64>,
) -> Result<(), InvalidPlan> {
    let signature: &GeneratedFunction = module
        .functions
        .iter()
        .find(|f| f.source_name == entry)
        .ok_or_else(|| invalid(call, None, "exported entry", entry))?;
    if signature.inputs.len() != args.len() {
        return Err(invalid(call, None, signature.inputs.len(), args.len()));
    }
    if signature.outputs.len() != bind.len() {
        return Err(invalid(
            call,
            None,
            format!("{} bindings", signature.outputs.len()),
            bind.len(),
        ));
    }
    let mut borrowed = BTreeSet::new();
    for (index, (arg, expected)) in args.iter().zip(&signature.inputs).enumerate() {
        let expected = kind(*expected);
        let memory = matches!(expected, ValueKind::MemRef | ValueKind::MemOwn);
        let valid = match arg {
            Arg::Bool(_) => expected == ValueKind::Bool,
            Arg::U16(_) => expected == ValueKind::U16,
            Arg::U32(_) => expected == ValueKind::U32,
            Arg::U64(_) => expected == ValueKind::U64,
            Arg::F32Bits(_) => expected == ValueKind::F32,
            Arg::Input { object } => memory && inputs.contains_key(object),
            Arg::Zeroed { .. } => memory,
            Arg::Asset {
                name,
                offset,
                bytes,
            } => {
                expected == ValueKind::MemRef
                    && env.assets.iter().any(|a| {
                        a.name == *name
                            && offset
                                .checked_add(*bytes)
                                .is_some_and(|end| end <= a.object.bytes())
                    })
            }
            Arg::Counter { base } => {
                expected == ValueKind::U64 && step.is_some_and(|i| base.checked_add(i).is_some())
            }
            Arg::Slot { name } => {
                let found = slots.get(name).copied();
                if expected == ValueKind::MemRef && found == Some(ValueKind::MemOwn) {
                    borrowed.insert(name.clone());
                    true
                } else if expected == ValueKind::MemOwn && found == Some(expected) {
                    if borrowed.contains(name) {
                        false
                    } else {
                        slots.remove(name);
                        true
                    }
                } else {
                    found == Some(expected)
                }
            }
        };
        if !valid {
            return Err(invalid(
                call,
                Some(index),
                format!("{expected:?}"),
                format!("{arg:?}"),
            ));
        }
    }
    let mut bound = BTreeSet::new();
    for (binding, output) in bind.iter().zip(&signature.outputs) {
        if let Bind::Name(name) = binding {
            if name.is_empty() || !bound.insert(name) {
                return Err(invalid(call, None, "unique nonempty binding", name));
            }
            slots.insert(name.clone(), kind(*output));
        }
    }
    Ok(())
}
