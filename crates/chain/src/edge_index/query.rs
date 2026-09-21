//! One strict HTTP query mapping shared by native origin and Wasm consumers.
use super::types::*;
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Filters {
    pub(crate) s: String,
    pub(crate) k: Option<String>,
    pub(crate) p: Option<String>,
    pub(crate) r: String,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Cursor {
    pub(crate) v: u32,
    pub(crate) s: String,
    pub(crate) p: String,
    pub(crate) f: Filters,
    pub(crate) a: String,
    pub(crate) e: Option<String>,
    pub(crate) h: Option<u64>,
    pub(crate) t: Option<u32>,
}
pub fn cursor_scope(network_id: &str, genesis_sha256: &str, trust_sha256: &str) -> String {
    use commonware_cryptography::{Hasher as _, Sha256};
    #[derive(serde::Serialize)]
    struct Scope<'a> {
        network_id: &'a str,
        genesis_sha256: &'a str,
        trust_sha256: &'a str,
        schema_version: u32,
    }
    hex::encode(Sha256::hash(
        &serde_json::to_vec(&Scope {
            network_id,
            genesis_sha256,
            trust_sha256,
            schema_version: SCHEMA_VERSION,
        })
        .expect("fixed string scope serializes"),
    ))
}
pub(crate) fn decode_cursor(
    raw: &str,
    network_id: &str,
    genesis_sha256: &str,
    trust_sha256: &str,
) -> Result<Cursor, String> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    if raw.len() > 684 {
        return Err("cursor too large".into());
    }
    let bytes =
        Base64UrlUnpadded::decode_vec(raw).map_err(|_| "invalid cursor base64".to_owned())?;
    if bytes.len() > 512 || Base64UrlUnpadded::encode_string(&bytes) != raw {
        return Err("noncanonical cursor".into());
    }
    let value: Cursor =
        serde_json::from_slice(&bytes).map_err(|e| format!("invalid cursor: {e}"))?;
    if value.v != SCHEMA_VERSION
        || value.s != cursor_scope(network_id, genesis_sha256, trust_sha256)
    {
        return Err("cursor scope/version mismatch".into());
    }
    validate_id(&value.p).map_err(str::to_owned)?;
    validate_id(&value.a).map_err(str::to_owned)?;
    if !matches!(value.f.s.as_str(), "open" | "closed" | "all")
        || !matches!(
            value.f.k.as_deref(),
            None | Some("basic" | "work-payment" | "work-stake-bond")
        )
        || !matches!(value.f.r.as_str(), "any" | "maker" | "taker")
    {
        return Err("cursor contains unknown filters".into());
    }
    if let Some(party) = &value.f.p {
        let bytes = bs58::decode(party)
            .into_vec()
            .map_err(|_| "invalid cursor party".to_owned())?;
        if bytes.len() != hellas_kernel::Key::LENGTH || bs58::encode(bytes).into_string() != *party
        {
            return Err("cursor contains noncanonical party".into());
        }
    } else if value.f.r != "any" {
        return Err("cursor role requires party".into());
    }
    match (&value.e, value.h, value.t) {
        (None, None, None) => {}
        (Some(edge), Some(height), Some(_)) => {
            validate_id(edge).map_err(str::to_owned)?;
            if value.a != *edge
                || height == 0
                || value.f.s != "all"
                || value.f.k.is_some()
                || value.f.p.is_some()
                || value.f.r != "any"
            {
                return Err("invalid normalized event cursor".into());
            }
        }
        _ => return Err("incomplete cursor position".into()),
    }
    Ok(value)
}
/// Resolves a cursor's immutable snapshot and normalized filters before either transport
/// executes the query or a consumer compares the returned page to its request.
pub fn normalize_list_request(
    mut request: ListEdgesRequest,
    network_id: &str,
    genesis_sha256: &str,
    trust_sha256: &str,
) -> Result<ListEdgesRequest, String> {
    if let Some(raw) = &request.cursor {
        let cursor = decode_cursor(raw, network_id, genesis_sha256, trust_sha256)?;
        if cursor.e.is_some() {
            return Err("wrong cursor kind".into());
        }
        if request.payload.as_ref().is_some_and(|v| v != &cursor.p)
            || request.state.as_ref().is_some_and(|v| v != &cursor.f.s)
            || request
                .kind
                .as_ref()
                .is_some_and(|v| Some(v) != cursor.f.k.as_ref())
            || request.role.as_ref().is_some_and(|v| v != &cursor.f.r)
            || request
                .party
                .as_ref()
                .is_some_and(|v| Some(bs58::encode(v).into_string()) != cursor.f.p)
        {
            return Err("cursor contradicts request filters".into());
        }
        if request.role.is_some() && request.party.is_none() && cursor.f.p.is_none() {
            return Err("role requires party".into());
        }
        request.payload = Some(cursor.p);
        request.state = Some(cursor.f.s);
        request.kind = cursor.f.k;
        request.party = cursor
            .f
            .p
            .map(|p| bs58::decode(p).into_vec())
            .transpose()
            .map_err(|_| "invalid party".to_owned())?;
        request.role = request.party.as_ref().map(|_| cursor.f.r);
    }
    request.validate().map_err(str::to_owned)?;
    Ok(request)
}
pub fn normalize_events_request(
    mut request: ListEdgeEventsRequest,
    network_id: &str,
    genesis_sha256: &str,
    trust_sha256: &str,
) -> Result<ListEdgeEventsRequest, String> {
    if request.schema_version != SCHEMA_VERSION {
        return Err("unsupported schema version".into());
    }
    validate_id(&request.edge_id).map_err(str::to_owned)?;
    validate_limit(request.limit).map_err(str::to_owned)?;
    if let Some(payload) = &request.payload {
        validate_id(payload).map_err(str::to_owned)?;
    }
    if let Some(raw) = &request.cursor {
        let cursor = decode_cursor(raw, network_id, genesis_sha256, trust_sha256)?;
        if cursor.e.as_ref() != Some(&request.edge_id)
            || request.payload.as_ref().is_some_and(|v| v != &cursor.p)
        {
            return Err("event cursor mismatch".into());
        }
        request.payload = Some(cursor.p);
    }
    Ok(request)
}

#[derive(Clone, Debug)]
pub enum Request {
    List(ListEdgesRequest),
    Detail(GetEdgeDetailRequest),
    Events(ListEdgeEventsRequest),
    Channel(GetWorkChannelDetailRequest),
}
impl Request {
    pub fn payload(&self) -> Option<&str> {
        match self {
            Self::List(q) => q.payload.as_deref(),
            Self::Detail(q) => q.payload.as_deref(),
            Self::Events(q) => q.payload.as_deref(),
            Self::Channel(q) => q.payload.as_deref(),
        }
    }
}
/// Paths are canonical API paths. Duplicate, unknown and malformed parameters fail closed.
pub fn parse_request(path: &str, raw_query: Option<&str>) -> Result<Request, String> {
    let raw = raw_query.unwrap_or("");
    if raw.len() > 4096 {
        return Err("query exceeds supported size".into());
    }
    let bytes = raw.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            if at + 2 >= bytes.len()
                || !bytes[at + 1].is_ascii_hexdigit()
                || !bytes[at + 2].is_ascii_hexdigit()
            {
                return Err("malformed percent encoding".into());
            }
            at += 3;
        } else {
            at += 1;
        }
    }
    let mut params = BTreeMap::new();
    for (key, value) in url::form_urlencoded::parse(bytes) {
        if key.contains('\u{fffd}')
            || value.contains('\u{fffd}')
            || params
                .insert(key.into_owned(), value.into_owned())
                .is_some()
        {
            return Err("duplicate or invalid query parameter".into());
        }
    }
    let schema_version = params
        .remove("schema_version")
        .map(|v| number(&v))
        .transpose()?
        .unwrap_or(SCHEMA_VERSION);
    if schema_version != SCHEMA_VERSION {
        return Err("unsupported schema version".into());
    }
    let payload = params.remove("payload");
    if let Some(payload) = &payload {
        validate_id(payload).map_err(str::to_owned)?;
    }
    let result = if path == "/api/v1/edges" {
        let party = params
            .remove("party")
            .map(|value| -> Result<Vec<u8>, String> {
                let bytes = bs58::decode(&value)
                    .into_vec()
                    .map_err(|_| "invalid party".to_owned())?;
                if bytes.len() != hellas_kernel::Key::LENGTH
                    || bs58::encode(&bytes).into_string() != value
                {
                    return Err("noncanonical party".into());
                }
                Ok(bytes)
            })
            .transpose()?;
        let request = ListEdgesRequest {
            payload,
            cursor: params.remove("cursor"),
            limit: params.remove("limit").map(|v| number(&v)).transpose()?,
            state: params.remove("state"),
            kind: params.remove("kind"),
            party,
            role: params.remove("role"),
            schema_version,
        };
        // Full cursor/filter contradiction checks need the deployment scope and happen
        // in the shared index query. All independently checkable fields are checked here.
        let mut syntax = request.clone();
        if syntax.party.is_none() && syntax.cursor.is_some() {
            syntax.role = None;
        }
        syntax.validate().map_err(str::to_owned)?;
        Request::List(request)
    } else if let Some(tail) = path.strip_prefix("/api/v1/edges/") {
        let (id, suffix) = tail.split_once('/').unwrap_or((tail, ""));
        validate_id(id).map_err(str::to_owned)?;
        match suffix {
            "" | "evidence" => Request::Detail(GetEdgeDetailRequest {
                edge_id: id.into(),
                payload,
                schema_version,
            }),
            "events" => {
                let limit = params.remove("limit").map(|v| number(&v)).transpose()?;
                validate_limit(limit).map_err(str::to_owned)?;
                Request::Events(ListEdgeEventsRequest {
                    edge_id: id.into(),
                    payload,
                    cursor: params.remove("cursor"),
                    limit,
                    schema_version,
                })
            }
            _ => return Err("unknown edge route".into()),
        }
    } else if let Some(id) = path.strip_prefix("/api/v1/channels/") {
        validate_id(id).map_err(str::to_owned)?;
        let funding = params.remove("funding").map(|raw| FundingQuery {
            coins: if raw.is_empty() {
                Vec::new()
            } else {
                raw.split(',').map(str::to_owned).collect()
            },
        });
        if let Some(funding) = &funding {
            validate_funding(&funding.coins)?;
        }
        Request::Channel(GetWorkChannelDetailRequest {
            payment_edge_id: id.into(),
            payload,
            funding,
            schema_version,
        })
    } else {
        return Err("unknown edge index route".into());
    };
    if !params.is_empty() {
        return Err("unknown query parameter".into());
    }
    Ok(result)
}
fn number(raw: &str) -> Result<u32, String> {
    let value = raw
        .parse::<u32>()
        .map_err(|_| "invalid decimal number".to_owned())?;
    if value.to_string() != raw {
        return Err("noncanonical decimal number".into());
    }
    Ok(value)
}
pub fn validate_funding(coins: &[String]) -> Result<(), String> {
    if coins.len() > 2 * hellas_kernel::MAX_EDGE_INPUTS {
        return Err("funding set exceeds two kernel Opens".into());
    }
    for id in coins {
        validate_id(id).map_err(str::to_owned)?;
    }
    if coins.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("funding IDs must be unique and sorted".into());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_cursor_normalization_rejects_forged_shapes_and_filter_conflicts() {
        use base64ct::{Base64UrlUnpadded, Encoding};
        let genesis = "ab".repeat(32);
        let trust = "cd".repeat(32);
        let payload = "ef".repeat(32);
        let cursor = Cursor {
            v: SCHEMA_VERSION,
            s: cursor_scope("hellas-devnet-1", &genesis, &trust),
            p: payload.clone(),
            f: Filters {
                s: "open".into(),
                k: Some("work-payment".into()),
                p: None,
                r: "any".into(),
            },
            a: "01".repeat(32),
            e: None,
            h: None,
            t: None,
        };
        let encode = |cursor: &Cursor| {
            Base64UrlUnpadded::encode_string(&serde_json::to_vec(cursor).unwrap())
        };
        let request = ListEdgesRequest {
            schema_version: SCHEMA_VERSION,
            cursor: Some(encode(&cursor)),
            limit: Some(64),
            ..Default::default()
        };
        let normalized =
            normalize_list_request(request.clone(), "hellas-devnet-1", &genesis, &trust).unwrap();
        assert_eq!(normalized.payload, Some(payload));
        assert_eq!(normalized.kind, Some("work-payment".into()));
        assert_eq!(normalized.limit, Some(64));
        assert!(
            normalize_list_request(request.clone(), "another-network", &genesis, &trust).is_err()
        );
        let mut conflicting = request.clone();
        conflicting.state = Some("closed".into());
        assert!(normalize_list_request(conflicting, "hellas-devnet-1", &genesis, &trust).is_err());
        let mut role = request.clone();
        role.role = Some("any".into());
        assert!(normalize_list_request(role, "hellas-devnet-1", &genesis, &trust).is_err());
        for mutation in 0..5 {
            let mut forged = cursor.clone();
            match mutation {
                0 => forged.f.s = "unknown".into(),
                1 => forged.f.r = "maker".into(),
                2 => forged.f.p = Some("1".into()),
                3 => forged.h = Some(1),
                _ => forged.f.k = Some("unknown".into()),
            }
            assert!(decode_cursor(&encode(&forged), "hellas-devnet-1", &genesis, &trust).is_err());
        }
        let mut event = cursor;
        event.f = Filters {
            s: "all".into(),
            k: None,
            p: None,
            r: "any".into(),
        };
        event.e = Some(event.a.clone());
        event.h = Some(9);
        event.t = Some(0);
        let request = ListEdgeEventsRequest {
            schema_version: SCHEMA_VERSION,
            edge_id: event.a.clone(),
            cursor: Some(encode(&event)),
            ..Default::default()
        };
        assert!(normalize_events_request(request, "hellas-devnet-1", &genesis, &trust).is_ok());
        event.f.k = Some("basic".into());
        assert!(decode_cursor(&encode(&event), "hellas-devnet-1", &genesis, &trust).is_err());
    }

    #[test]
    fn strict_http_queries() {
        for query in [
            "limit=0",
            "limit=65",
            "limit=01",
            "state=invalid",
            "role=maker",
            "limit=1&limit=2",
            "unknown=1",
            "schema_version=1",
            "party=%GG",
        ] {
            assert!(
                parse_request("/api/v1/edges", Some(query)).is_err(),
                "{query}"
            );
        }
        assert!(parse_request("/api/v1/edges", Some("limit=32&state=open")).is_ok());
        let id = "ab".repeat(32);
        let Request::Channel(request) =
            parse_request(&format!("/api/v1/channels/{id}"), Some("funding=")).unwrap()
        else {
            panic!()
        };
        assert_eq!(request.funding.unwrap().coins, Vec::<String>::new());
    }
}
