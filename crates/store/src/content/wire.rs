use super::*;
use hellas_auth::{Digest, authority::UnixMillis};
use hellas_rpc::{ContentId, ContentRef, pb::content as pb};

pub(crate) fn object(object: &pb::ContentRef) -> Result<ContentRef> {
    Ok(ContentRef::new(
        ContentId::from_slice(&object.id).map_err(|_| Error::Invalid("content id"))?,
        object.bytes,
    ))
}
pub(crate) fn target(target: &Target) -> pb::Target {
    pb::Target {
        object: Some(super::page::wire_ref(target.object())),
        tree: matches!(target, Target::Tree(_)),
    }
}
pub(crate) fn target_from(target: pb::Target) -> Result<Target> {
    let object = object(
        target
            .object
            .as_ref()
            .ok_or(Error::Invalid("missing reference"))?,
    )?;
    Ok(if target.tree {
        Target::Tree(object)
    } else {
        Target::Object(object)
    })
}
pub(crate) fn policy(policy: &PinPolicy) -> pb::PinPolicy {
    use pb::pin_policy::Kind;
    let (kind, channel_id) = match policy {
        PinPolicy::Owner => (Kind::Owner, vec![]),
        PinPolicy::Jobs => (Kind::Jobs, vec![]),
        PinPolicy::Channel(id) => (Kind::Channel, id.as_bytes().to_vec()),
        PinPolicy::Granted => (Kind::Granted, vec![]),
        PinPolicy::Public => (Kind::Public, vec![]),
    };
    pb::PinPolicy {
        kind: kind as i32,
        channel_id,
    }
}
pub(crate) fn policy_from(policy: pb::PinPolicy) -> Result<PinPolicy> {
    use pb::pin_policy::Kind;
    if policy.kind != Kind::Channel as i32 && !policy.channel_id.is_empty() {
        return Err(Error::Invalid("policy channel"));
    }
    Ok(
        match Kind::try_from(policy.kind).map_err(|_| Error::Invalid("pin policy"))? {
            Kind::Owner => PinPolicy::Owner,
            Kind::Jobs => PinPolicy::Jobs,
            Kind::Granted => PinPolicy::Granted,
            Kind::Public => PinPolicy::Public,
            Kind::Channel => PinPolicy::Channel(
                Digest::from_slice(&policy.channel_id).map_err(|_| Error::Invalid("channel id"))?,
            ),
            Kind::Unspecified => return Err(Error::Invalid("unspecified pin policy")),
        },
    )
}
pub(crate) fn pin_value(value: &PinValue) -> pb::PinValue {
    pb::PinValue {
        target: Some(target(&value.target)),
        policy: Some(policy(&value.policy)),
        expires_ms: value.expires.map(|time| time.0),
    }
}
pub(crate) fn value_from(value: pb::PinValue) -> Result<PinValue> {
    Ok(PinValue {
        target: target_from(value.target.ok_or(Error::Invalid("missing pin target"))?)?,
        policy: policy_from(value.policy.ok_or(Error::Invalid("missing pin policy"))?)?,
        expires: value.expires_ms.map(UnixMillis),
    })
}
pub(crate) fn pin(name: &PinName, value: &PinValue) -> pb::Pin {
    pb::Pin {
        name: name.as_str().into(),
        value: Some(pin_value(value)),
    }
}
pub(crate) fn pin_from(pin: pb::Pin) -> Result<(PinName, PinValue)> {
    Ok((
        PinName::new(pin.name)?,
        value_from(pin.value.ok_or(Error::Invalid("missing pin"))?)?,
    ))
}
pub(crate) fn cursor(cursor: Cursor) -> pb::Cursor {
    pb::Cursor {
        offset: cursor.offset,
        generation: cursor.generation,
        object: cursor.object.map(super::page::wire_ref),
    }
}
pub(crate) fn cursor_from(cursor: pb::Cursor) -> Result<Cursor> {
    Ok(Cursor {
        offset: cursor.offset,
        generation: cursor.generation,
        object: cursor.object.as_ref().map(object).transpose()?,
    })
}
pub(crate) fn path(path: &Path) -> pb::Path {
    pb::Path {
        pin: path.pin.as_str().into(),
        path: path.path.clone(),
    }
}

pub(crate) fn pin_target(pin: &PinTarget) -> pb::PinTarget {
    pb::PinTarget {
        name: pin.name.as_str().into(),
        policy: Some(policy(&pin.policy)),
    }
}

pub(crate) fn event(event: &PinEvent) -> pb::WatchPinsResponse {
    match event {
        PinEvent::Resync { cursor: c } => pb::WatchPinsResponse {
            cursor: Some(cursor(*c)),
            pin: None,
            removed: false,
            resync: true,
        },
        PinEvent::Set {
            cursor: c,
            name,
            value,
        } => pb::WatchPinsResponse {
            cursor: Some(cursor(*c)),
            pin: Some(pb::Pin {
                name: name.as_str().into(),
                value: value.as_ref().map(pin_value),
            }),
            removed: value.is_none(),
            resync: false,
        },
    }
}
pub(crate) fn event_from(event: pb::WatchPinsResponse) -> Result<PinEvent> {
    let cursor = cursor_from(event.cursor.ok_or(Error::Invalid("watch cursor"))?)?;
    if event.resync {
        return Ok(PinEvent::Resync { cursor });
    }
    let pin = event.pin.ok_or(Error::Invalid("watch pin"))?;
    let name = PinName::new(pin.name)?;
    let value = if event.removed {
        None
    } else {
        Some(value_from(pin.value.ok_or(Error::Invalid("watch value"))?)?)
    };
    Ok(PinEvent::Set {
        cursor,
        name,
        value,
    })
}
pub(crate) fn source(source: Source) -> pb::Source {
    use pb::source::Kind;
    pb::Source {
        kind: Some(match source {
            Source::Peer { node, at } => Kind::Peer(pb::Peer {
                node: node.to_vec(),
                at: Some(path(&at)),
            }),
            Source::Https { url, sha256, bytes } => Kind::Https(pb::Https {
                url: url.to_string(),
                sha256: sha256.map(|hash| hash.to_vec()),
                bytes,
            }),
            Source::HfXet { repo, commit, path } => Kind::HfXet(pb::HfXet {
                repo: repo.id,
                dataset: repo.kind == crate::hf::RepoKind::Dataset,
                commit,
                path,
            }),
        }),
    }
}

pub(crate) fn error(status: hellas_wire::WireStatus) -> Error {
    use hellas_wire::WireCode;
    match status.code {
        WireCode::PermissionDenied | WireCode::Unauthenticated => Error::Denied,
        WireCode::NotFound => Error::Missing,
        WireCode::Aborted => Error::Conflict,
        WireCode::ResourceExhausted => Error::Capacity,
        _ => Error::Invalid("remote content operation failed"),
    }
}
