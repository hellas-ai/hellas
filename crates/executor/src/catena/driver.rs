use super::{
    assets::{Assets, Resident, upload},
    memory, validate,
};
use catena_lang::runtime::{RuntimeModule, Value, ValueKind};
use hellas_channel::content::InvocationContent;
use hellas_rpc::{
    ContentRef,
    protocol::invocation::{Limits, compute::*},
};
use std::{collections::BTreeMap, sync::Arc};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, thiserror::Error)]
pub(crate) enum Interruption {
    #[error("Catena execution cancelled")]
    Cancelled,
    #[error("Catena execution timed out")]
    TimedOut,
}

pub trait Device {
    fn load(&mut self, module: &RuntimeModule) -> Result<super::Cancellation>;
    fn call(&mut self, entry: &str, args: Vec<Value<'_>>) -> Result<Vec<Value<'static>>>;
}

#[derive(Debug)]
pub struct Completed {
    pub emitted: Vec<u64>,
    pub outputs: BTreeMap<String, Vec<u8>>,
    pub stop: Option<StopReason>,
    deadline: std::time::Instant,
    cancel: super::Cancellation,
}

/// `emit` publishes each step before its stop rule is evaluated.
#[allow(clippy::too_many_arguments)]
pub fn execute(
    device: &mut impl Device,
    module: &RuntimeModule,
    env: &Environment,
    inputs: &BTreeMap<String, Vec<u8>>,
    plan: &Plan,
    limits: &Limits,
    assets: &Assets,
    content: &InvocationContent,
    mut emit: impl FnMut(u64) -> Result<()>,
) -> Result<Completed> {
    let descriptors = inputs
        .iter()
        .map(|(name, bytes)| (name.clone(), ContentRef::for_bytes(bytes)))
        .collect();
    validate::validate(module, env, &descriptors, plan, limits, content)?;
    let cancel = device.load(module)?;
    let deadline = std::time::Instant::now()
        .checked_add(std::time::Duration::from_millis(
            limits.execution_timeout_ms,
        ))
        .ok_or("execution deadline overflow")?;
    let check_time = || -> Result<()> {
        if std::time::Instant::now() >= deadline || cancel.timed_out() {
            Err(Interruption::TimedOut.into())
        } else if cancel.is_cancelled() {
            Err(Interruption::Cancelled.into())
        } else {
            Ok(())
        }
    };
    let execution = (|| -> Result<Completed> {
        let mut resident = BTreeMap::new();
        for asset in &env.assets {
            resident.insert(
                asset.name.clone(),
                assets.pin_for_job(content, asset.object, &cancel, Some(deadline))?,
            );
        }
        let mut slots = BTreeMap::new();
        let mut uploads = BTreeMap::new();
        for call in &plan.calls {
            check_time()?;
            call_once(
                device,
                module,
                &call.entry,
                &call.args.iter().collect::<Vec<_>>(),
                &call.bind,
                &mut slots,
                &mut uploads,
                inputs,
                &resident,
                0,
            )?;
        }
        let mut emitted = Vec::new();
        let mut stop = None;
        if let Some(step) = &plan.step {
            for i in 0..step.stop.max_steps {
                check_time()?;
                call_once(
                    device,
                    module,
                    &step.entry,
                    &step.args.iter().map(|a| a.at(i)).collect::<Vec<_>>(),
                    &step.bind,
                    &mut slots,
                    &mut uploads,
                    inputs,
                    &resident,
                    i,
                )?;
                let value = match slots.get(&step.emit).ok_or("emit slot absent")? {
                    Value::U64(n) => *n,
                    Value::MemOwn(memory) if memory.byte_len() == 8 => memory.try_to_u64_vec()?[0],
                    _ => return Err("emit must contain exactly one u64".into()),
                };
                emit(value)?;
                check_time()?;
                emitted.push(value);
                if step.stop.any_of.contains(&value) {
                    stop = Some(StopReason::Matched(value));
                    break;
                }
            }
            if stop.is_none() {
                stop = Some(StopReason::MaxSteps);
            }
        }
        let mut outputs = BTreeMap::new();
        for d in &plan.outputs {
            let value = slots.get(&d.slot).ok_or("declared slot absent")?;
            let bytes = match (&d.kind, value) {
                (OutputKind::Buffer { max_bytes }, Value::MemOwn(memory))
                    if memory.byte_len() <= *max_bytes =>
                {
                    memory::download(memory)?
                }
                (OutputKind::Scalar(_), Value::Bool(n)) => vec![*n],
                (OutputKind::Scalar(_), Value::U16(n)) => n.to_le_bytes().to_vec(),
                (OutputKind::Scalar(_), Value::U32(n)) => n.to_le_bytes().to_vec(),
                (OutputKind::Scalar(_), Value::U64(n)) => n.to_le_bytes().to_vec(),
                (OutputKind::Scalar(_), Value::F32(n)) => n.to_bits().to_le_bytes().to_vec(),
                _ => return Err("declared output exceeds bound or has wrong kind".into()),
            };
            outputs.insert(d.slot.clone(), bytes);
        }
        check_time()?;
        Ok(Completed {
            emitted,
            outputs,
            stop,
            deadline,
            cancel: cancel.clone(),
        })
    })();
    match execution {
        Ok(completed) => Ok(completed),
        Err(error) => {
            // Watchdog cleanup may win the race with the next normal control
            // check. Cancellation/deadline explain that transport consequence.
            check_time()?;
            Err(error)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn call_once(
    device: &mut impl Device,
    module: &RuntimeModule,
    entry: &str,
    args: &[&Arg],
    bind: &[Bind],
    slots: &mut BTreeMap<String, Value<'static>>,
    uploads: &mut BTreeMap<String, catena_lang::runtime::MemOwn>,
    inputs: &BTreeMap<String, Vec<u8>>,
    assets: &BTreeMap<String, Arc<Resident>>,
    step: u64,
) -> Result<()> {
    let signature = module
        .functions
        .iter()
        .find(|f| f.source_name == entry)
        .ok_or("entry absent")?;
    let mut owned = Vec::new();
    for (arg, kind) in args.iter().zip(&signature.inputs) {
        let value = match arg {
            Arg::Slot { name } if *kind == ValueKind::MemOwn => {
                Some(slots.remove(name).ok_or("moved slot absent")?)
            }
            Arg::Input { object } if *kind == ValueKind::MemOwn => {
                Some(Value::MemOwn(upload(&inputs[object], module.dialect)?))
            }
            Arg::Input { object } => {
                if !uploads.contains_key(object) {
                    uploads.insert(object.clone(), upload(&inputs[object], module.dialect)?);
                }
                None
            }
            Arg::Zeroed { bytes } => Some(Value::MemOwn(memory::zeroed(*bytes, module.dialect)?)),
            _ => None,
        };
        owned.push(value);
    }
    let mut values = Vec::new();
    // All moves precede borrows. Validation rejects borrowing a slot also moved by this call.
    let borrowed_zeroes: Vec<_> = owned
        .iter_mut()
        .zip(&signature.inputs)
        .map(|(value, kind)| {
            if *kind == ValueKind::MemRef {
                value.take()
            } else {
                None
            }
        })
        .collect();
    for (i, (arg, kind)) in args.iter().zip(&signature.inputs).enumerate() {
        let value = if let Some(value) = owned[i].take() {
            value
        } else {
            match arg {
                Arg::Bool(n) => Value::from(*n),
                Arg::U16(n) => Value::from(*n),
                Arg::U32(n) => Value::from(*n),
                Arg::U64(n) => Value::from(*n),
                Arg::F32Bits(n) => Value::F32(f32::from_bits(*n)),
                Arg::Counter { base } => {
                    Value::U64(base.checked_add(step).ok_or("counter overflow")?)
                }
                Arg::Input { object } => Value::MemRef(uploads[object].as_ref()),
                Arg::Zeroed { .. } => match &borrowed_zeroes[i] {
                    Some(Value::MemOwn(m)) => Value::MemRef(m.as_ref()),
                    _ => return Err("zero allocation absent".into()),
                },
                Arg::Asset {
                    name,
                    offset,
                    bytes,
                } => Value::MemRef(assets[name].view(*offset, *bytes)?),
                Arg::Slot { name } => match &slots[name] {
                    Value::Bool(n) => Value::Bool(*n),
                    Value::U16(n) => Value::U16(*n),
                    Value::U32(n) => Value::U32(*n),
                    Value::U64(n) => Value::U64(*n),
                    Value::F32(n) => Value::F32(*n),
                    Value::MemOwn(m) if *kind == ValueKind::MemRef => Value::MemRef(m.as_ref()),
                    _ => return Err("slot kind mismatch".into()),
                },
            }
        };
        values.push(value);
    }
    let output = device.call(entry, values)?;
    if output.len() != signature.outputs.len()
        || output
            .iter()
            .zip(&signature.outputs)
            .any(|(v, k)| value_kind(v) != *k)
    {
        return Err("worker returned values that disagree with signature".into());
    }
    for (binding, value) in bind.iter().zip(output) {
        if let Bind::Name(name) = binding {
            slots.insert(name.clone(), value);
        }
    }
    Ok(())
}

fn value_kind(value: &Value<'_>) -> ValueKind {
    match value {
        Value::Bool(_) => ValueKind::Bool,
        Value::U16(_) => ValueKind::U16,
        Value::U32(_) => ValueKind::U32,
        Value::U64(_) => ValueKind::U64,
        Value::F32(_) => ValueKind::F32,
        Value::MemOwn(_) => ValueKind::MemOwn,
        Value::MemRef(_) => ValueKind::MemRef,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn execute_signed(
    device: &mut impl Device,
    program: &super::program::BoundProgram,
    prepared: &hellas_rpc::protocol::invocation::PreparedInvocation,
    limits: &Limits,
    assets: &Assets,
    content: &InvocationContent,
    key: &hellas_auth::ProducerSigningKey,
    publish: impl FnMut(hellas_rpc::OutputEventEnvelope) -> Result<()>,
) -> Result<(
    hellas_rpc::protocol::invocation::output::InvocationOutput,
    Vec<hellas_rpc::OutputEventEnvelope>,
)> {
    let stream = hellas_rpc::protocol::invocation::output::OutputStream::new(
        &prepared.request,
        key,
        hellas_rpc::protocol::invocation::MAX_INVOCATION_BYTES,
    )?;
    execute_signed_in(
        device, program, prepared, limits, assets, content, key, stream, publish,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_signed_in(
    device: &mut impl Device,
    program: &super::program::BoundProgram,
    prepared: &hellas_rpc::protocol::invocation::PreparedInvocation,
    limits: &Limits,
    assets: &Assets,
    content: &InvocationContent,
    key: &hellas_auth::ProducerSigningKey,
    mut stream: hellas_rpc::protocol::invocation::output::OutputStream<'_>,
    mut publish: impl FnMut(hellas_rpc::OutputEventEnvelope) -> Result<()>,
) -> Result<(
    hellas_rpc::protocol::invocation::output::InvocationOutput,
    Vec<hellas_rpc::OutputEventEnvelope>,
)> {
    let (plan, inputs) = program.input(prepared)?;
    let plan = &plan;
    let request = &prepared.request;
    use hellas_rpc::protocol::invocation::{
        Artifact,
        output::{FailureReason, InvocationOutput, Outcome, OutputError, OutputStream},
    };
    if request.retain != (content.retention() == hellas_rpc::Retention::Retain) {
        return Err("compute content retention differs from the signed request".into());
    }
    if request.runner_public_key != key.public_key() {
        return Err("runner key mismatch".into());
    }
    let mut offset = 0;
    let mut publish_error = None;
    let execution = execute(
        device,
        program.module(),
        program.environment(),
        &inputs,
        plan,
        limits,
        assets,
        content,
        |value| {
            let event = stream.push("emitted", "catena.u64le.v1", offset, &value.to_le_bytes())?;
            if let Err(error) = publish(event) {
                publish_error = Some(error);
                return Err("compute publication failed".into());
            }
            offset += 8;
            Ok(())
        },
    );
    let completed = match execution {
        Ok(completed) => completed,
        Err(error) => {
            if let Some(error) = publish_error {
                return Err(error);
            }
            if error.downcast_ref::<validate::InvalidPlan>().is_some() {
                return Err(error);
            }
            let reason = match error.downcast_ref::<Interruption>() {
                Some(Interruption::Cancelled) => FailureReason::Cancelled,
                Some(Interruption::TimedOut) => FailureReason::ExecutionTimeout,
                None if error
                    .downcast_ref::<OutputError>()
                    .is_some_and(|e| matches!(e, OutputError::Limit)) =>
                {
                    FailureReason::OutputLimit
                }
                None if error
                    .downcast_ref::<super::pool::SpawnError>()
                    .is_some_and(|e| matches!(e, super::pool::SpawnError::Cancelled)) =>
                {
                    FailureReason::Cancelled
                }
                None => FailureReason::Execution,
            };
            tracing::warn!(error = %error, "compute execution failed");
            let (output, events) = stream.fail(reason)?;
            publish(events.last().unwrap().clone())?;
            return Ok((output, events));
        }
    };
    let deadline = completed.deadline;
    let cancel = completed.cancel;
    let metadata = RunMetadata {
        steps: completed.emitted.len() as u64,
        stop: completed.stop,
    };
    let mut artifacts: Vec<_> = plan
        .outputs
        .iter()
        .map(|d| Artifact::new(&d.slot, d.kind.format(), completed.outputs[&d.slot].clone()))
        .collect();
    if plan.step.is_some() {
        artifacts.push(Artifact::new(
            "emitted",
            "catena.u64le.v1",
            completed
                .emitted
                .into_iter()
                .flat_map(u64::to_le_bytes)
                .collect(),
        ));
    }
    artifacts.sort_by(|a, b| a.name.cmp(&b.name));
    let output = InvocationOutput {
        outcome: Outcome::Succeeded,
        artifacts,
        metadata: hellas_rpc::JsonBytes(hellas_rpc::canonical_dag_cbor(&metadata)?),
    };
    if validate_output(plan, &output).is_err() {
        let (output, events) = stream.fail(FailureReason::Execution)?;
        publish(events.last().unwrap().clone())?;
        return Ok((output, events));
    }
    let maximum_payload_bytes = stream.maximum_payload_bytes();
    let (output, mut events) = stream.finish_or_fail(output, 64 << 10)?;
    let mut published = offset as usize / 8;
    while published < events.len() {
        let reason = if std::time::Instant::now() >= deadline || cancel.timed_out() {
            Some(FailureReason::ExecutionTimeout)
        } else if cancel.is_cancelled() {
            Some(FailureReason::Cancelled)
        } else {
            None
        };
        if let Some(reason) = reason {
            events.truncate(published);
            let (output, events) =
                OutputStream::resume(request, key, events, maximum_payload_bytes)?.fail(reason)?;
            publish(events.last().unwrap().clone())?;
            return Ok((output, events));
        }
        publish(events[published].clone())?;
        published += 1;
    }
    Ok((output, events))
}
