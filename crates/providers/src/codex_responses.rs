//! Closed request and response lenses for the sealed Codex Responses Fetch
//! environment. This is intentionally separate from the OpenAI Responses
//! projector: the two endpoints expose different lifecycle contracts.

use super::stream::{project_events, push_sse};

use std::collections::{BTreeMap, BTreeSet};

use hellas_adaptors::{
    AdaptorEvent, CodexCompleted, CodexInputTokenDetails, CodexItemStatus, CodexMessageContent,
    CodexMessagePhase, CodexOutputTokenDetails, CodexReasoningContent, CodexReasoningSummary,
    CodexResponseItem, CodexResponsesEvent, CodexToolSearchArguments, CodexUsage,
    CodexUsageMetadata, OutputEvent, SseDecoder, StopReason, Usage, WireEventData, WireStreamEvent,
};
use hellas_executor::{
    FetchAdaptorError, FetchAdaptorSession, FetchCall, FetchProjector, FetchProviderResponseHead,
    FetchRequestView, PreparedFetchRequest, ProjectedFetch,
};
use hellas_rpc::JsonBytes;
use hellas_rpc::fetch::{MAX_FETCH_REQUEST_BODY_BYTES, encode_fetch_terminal_payload};
use serde::{
    Deserialize, Serialize,
    de::{DeserializeOwned, IgnoredAny},
};
use serde_json::{Map as JsonMap, Number as JsonNumber, Value as JsonValue};

const MAX_MODEL_BYTES: usize = 256;
const MAX_NAME_BYTES: usize = 256;
const MAX_PROMPT_CACHE_KEY_BYTES: usize = 1_024;
const MAX_CLIENT_METADATA_ENTRIES: usize = 64;
const MAX_CLIENT_METADATA_KEY_BYTES: usize = 128;
const MAX_CLIENT_METADATA_VALUE_BYTES: usize = 2_048;
const MAX_FAILURE_EXCERPT_CHARS: usize = 512;

pub(super) fn create_session(
    request: &FetchCall,
) -> Result<FetchAdaptorSession, FetchAdaptorError> {
    let prepared = prepare_request(request)?;
    let request_view = FetchRequestView {
        service: request.service.clone(),
        method: request.method.clone(),
        model: Some(prepared.model.clone()),
        // The current Codex request contract has no max_output_tokens field.
        // Signed Fetch event/byte limits remain independently mandatory.
        max_output_units: None,
    };
    Ok(FetchAdaptorSession {
        request_view,
        provider_request: PreparedFetchRequest::new(request, prepared.body),
        projector: Box::new(CodexProjector::new(prepared.contract)),
    })
}

struct PreparedCodexRequest {
    body: JsonBytes,
    model: String,
    contract: ProjectionContract,
}

fn prepare_request(request: &FetchCall) -> Result<PreparedCodexRequest, FetchAdaptorError> {
    let body = request.body.as_bytes();
    if body.len() > MAX_FETCH_REQUEST_BODY_BYTES {
        return Err(failed(format!(
            "signed Codex request exceeds the {MAX_FETCH_REQUEST_BODY_BYTES}-byte limit"
        )));
    }

    let mut trusted: CodexRequest = serde_json::from_slice(body)
        .map_err(|error| failed(format!("invalid sealed Codex request: {error}")))?;
    let contract = trusted.validate_and_rebuild()?;
    let model = trusted.model.clone();
    let rebuilt = serde_json::to_vec(&trusted)
        .map_err(|error| failed(format!("failed to rebuild Codex request: {error}")))?;
    if rebuilt.len() > MAX_FETCH_REQUEST_BODY_BYTES {
        return Err(failed(format!(
            "rebuilt Codex request exceeds the {MAX_FETCH_REQUEST_BODY_BYTES}-byte limit"
        )));
    }
    Ok(PreparedCodexRequest {
        body: JsonBytes::new(rebuilt),
        model,
        contract,
    })
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CodexRequest {
    model: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    instructions: String,
    input: Vec<CodexInputItem>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tools: Vec<CodexTool>,
    #[serde(default)]
    tool_choice: CodexToolChoice,
    #[serde(default = "default_parallel_tool_calls")]
    parallel_tool_calls: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reasoning: Option<CodexReasoning>,
    #[serde(default)]
    store: bool,
    #[serde(default = "default_stream")]
    stream: bool,
    #[serde(default = "default_include")]
    include: Vec<CodexInclude>,
    #[serde(
        default,
        deserialize_with = "present_optional_string",
        skip_serializing_if = "Option::is_none"
    )]
    prompt_cache_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    text: Option<CodexTextControls>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    client_metadata: Option<BTreeMap<String, String>>,
    #[serde(
        default,
        rename = "safety_buffering",
        deserialize_with = "reject_safety_buffering",
        skip_serializing
    )]
    _safety_buffering: (),
}

impl CodexRequest {
    fn validate_and_rebuild(&mut self) -> Result<ProjectionContract, FetchAdaptorError> {
        nonempty_bounded("model", &self.model, MAX_MODEL_BYTES)?;
        if self.store {
            return Err(failed("sealed Codex Fetch requires store=false"));
        }
        if !self.stream {
            return Err(failed("sealed Codex Fetch requires stream=true"));
        }
        if self.include != [CodexInclude::ReasoningEncryptedContent] {
            return Err(failed(
                "sealed Codex Fetch requires include=[\"reasoning.encrypted_content\"]",
            ));
        }
        if let Some(key) = &self.prompt_cache_key {
            nonempty_bounded("prompt_cache_key", key, MAX_PROMPT_CACHE_KEY_BYTES)?;
        }
        if let Some(format) = self.text.as_ref().and_then(|text| text.format.as_ref()) {
            nonempty_bounded("text format name", &format.name, MAX_NAME_BYTES)?;
            require_object("text format schema", &format.schema)?;
        }
        validate_client_metadata(self.client_metadata.as_ref())?;
        // Client metadata is local trace material (and commonly contains local
        // paths). It is admitted for compatibility but never crosses egress.
        self.client_metadata = None;

        let mut functions = BTreeSet::new();
        let mut customs = BTreeSet::new();
        let mut deferred_functions = BTreeSet::new();
        let mut deferred_customs = BTreeSet::new();
        let mut has_tool_search = false;
        let mut rebuilt_tools = Vec::with_capacity(self.tools.len());
        for tool in std::mem::take(&mut self.tools) {
            match &tool {
                CodexTool::Function {
                    name,
                    parameters,
                    output_schema,
                    defer_loading,
                    ..
                } => {
                    validate_tool_name(name)?;
                    require_object("function parameters", parameters)?;
                    if let Some(schema) = output_schema {
                        require_object("function output_schema", schema)?;
                    }
                    if functions.contains(name)
                        || customs.contains(name)
                        || deferred_functions.contains(name)
                        || deferred_customs.contains(name)
                    {
                        return Err(failed(format!("duplicate Codex tool name `{name}`")));
                    }
                    if defer_loading.unwrap_or(false) {
                        deferred_functions.insert(name.clone());
                    } else {
                        functions.insert(name.clone());
                    }
                    rebuilt_tools.push(tool);
                }
                CodexTool::Custom {
                    name,
                    format,
                    defer_loading,
                    ..
                } => {
                    validate_tool_name(name)?;
                    format.validate()?;
                    if functions.contains(name)
                        || customs.contains(name)
                        || deferred_functions.contains(name)
                        || deferred_customs.contains(name)
                    {
                        return Err(failed(format!("duplicate Codex tool name `{name}`")));
                    }
                    if defer_loading.unwrap_or(false) {
                        deferred_customs.insert(name.clone());
                    } else {
                        customs.insert(name.clone());
                    }
                    rebuilt_tools.push(tool);
                }
                CodexTool::ToolSearch {
                    execution,
                    parameters,
                    ..
                } => {
                    if execution != "client" || has_tool_search {
                        return Err(failed(
                            "tool_search must be a single client-executed declaration",
                        ));
                    }
                    require_object("tool_search parameters", parameters)?;
                    has_tool_search = true;
                    rebuilt_tools.push(tool);
                }
                CodexTool::WebSearch {
                    external_web_access,
                } => {
                    if *external_web_access {
                        return Err(failed("provider-hosted web search is forbidden"));
                    }
                    // Even cached web_search is provider-executed. Current
                    // Codex sends the disabled declaration, so admit but omit
                    // it rather than silently granting a capability.
                }
            }
        }
        self.tools = rebuilt_tools;
        let contract = ProjectionContract {
            functions,
            customs,
            deferred_functions,
            deferred_customs,
            has_tool_search,
            tool_choice: self.tool_choice,
            parallel_tool_calls: self.parallel_tool_calls,
            reasoning: self.reasoning.is_some(),
            prior_call_ids: BTreeSet::new(),
        };
        let contract = validate_input_history(&self.input, contract)?;
        if contract.tool_choice == CodexToolChoice::Required
            && contract.functions.is_empty()
            && contract.customs.is_empty()
            && !contract.has_tool_search
        {
            return Err(failed("tool_choice=required needs an admitted local tool"));
        }
        Ok(contract)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
enum CodexInclude {
    #[serde(rename = "reasoning.encrypted_content")]
    ReasoningEncryptedContent,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum CodexToolChoice {
    #[default]
    Auto,
    None,
    Required,
}

fn default_parallel_tool_calls() -> bool {
    true
}

fn default_stream() -> bool {
    true
}

fn default_include() -> Vec<CodexInclude> {
    vec![CodexInclude::ReasoningEncryptedContent]
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum CodexTool {
    #[serde(rename = "function")]
    Function {
        name: String,
        description: String,
        strict: bool,
        #[serde(
            default,
            rename = "namespace",
            deserialize_with = "reject_namespace",
            skip_serializing
        )]
        _namespace: (),
        #[serde(default, skip_serializing_if = "Option::is_none")]
        defer_loading: Option<bool>,
        parameters: JsonValue,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        output_schema: Option<JsonValue>,
    },
    #[serde(rename = "custom")]
    Custom {
        name: String,
        description: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        defer_loading: Option<bool>,
        format: CodexCustomFormat,
    },
    #[serde(rename = "tool_search")]
    ToolSearch {
        execution: String,
        description: String,
        parameters: JsonValue,
    },
    #[serde(rename = "web_search")]
    WebSearch { external_web_access: bool },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CodexCustomFormat {
    #[serde(rename = "type")]
    kind: CodexCustomFormatKind,
    syntax: CodexCustomSyntax,
    definition: String,
}

impl CodexCustomFormat {
    fn validate(&self) -> Result<(), FetchAdaptorError> {
        if self.definition.is_empty() {
            Err(failed("custom tool grammar must not be empty"))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
enum CodexCustomFormatKind {
    #[serde(rename = "grammar")]
    Grammar,
}

#[derive(Debug, Deserialize, Serialize)]
enum CodexCustomSyntax {
    #[serde(rename = "lark")]
    Lark,
    #[serde(rename = "regex")]
    Regex,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CodexReasoning {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    effort: Option<CodexReasoningEffort>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    summary: Option<CodexReasoningSummaryMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    context: Option<CodexReasoningContext>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum CodexReasoningEffort {
    None,
    Minimal,
    Low,
    Medium,
    High,
    Xhigh,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum CodexReasoningSummaryMode {
    Auto,
    Concise,
    Detailed,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum CodexReasoningContext {
    Auto,
    CurrentTurn,
    AllTurns,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CodexTextControls {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verbosity: Option<CodexVerbosity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    format: Option<CodexTextFormat>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum CodexVerbosity {
    Low,
    Medium,
    High,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CodexTextFormat {
    #[serde(rename = "type")]
    kind: CodexTextFormatKind,
    strict: bool,
    schema: JsonValue,
    name: String,
}

#[derive(Debug, Deserialize, Serialize)]
enum CodexTextFormatKind {
    #[serde(rename = "json_schema")]
    JsonSchema,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum CodexInputItem {
    #[serde(rename = "message")]
    Message {
        #[serde(
            default,
            deserialize_with = "present_optional_string",
            skip_serializing_if = "Option::is_none"
        )]
        id: Option<String>,
        role: String,
        content: Vec<CodexInputContent>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        phase: Option<CodexMessagePhaseWire>,
    },
    #[serde(rename = "reasoning")]
    Reasoning {
        #[serde(
            default,
            deserialize_with = "present_optional_string",
            skip_serializing_if = "Option::is_none"
        )]
        id: Option<String>,
        summary: Vec<CodexSummaryWire>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        content: Option<Vec<CodexReasoningWire>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        encrypted_content: Option<String>,
    },
    #[serde(rename = "function_call")]
    FunctionCall {
        #[serde(
            default,
            deserialize_with = "present_optional_string",
            skip_serializing_if = "Option::is_none"
        )]
        id: Option<String>,
        name: String,
        arguments: String,
        call_id: String,
        #[serde(
            default,
            rename = "namespace",
            deserialize_with = "reject_namespace",
            skip_serializing
        )]
        _namespace: (),
    },
    #[serde(rename = "function_call_output")]
    FunctionCallOutput {
        #[serde(
            default,
            deserialize_with = "present_optional_string",
            skip_serializing_if = "Option::is_none"
        )]
        id: Option<String>,
        call_id: String,
        output: CodexToolOutput,
    },
    #[serde(rename = "custom_tool_call")]
    CustomToolCall {
        #[serde(
            default,
            deserialize_with = "present_optional_string",
            skip_serializing_if = "Option::is_none"
        )]
        id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        status: Option<CodexItemStatusWire>,
        call_id: String,
        name: String,
        input: String,
    },
    #[serde(rename = "custom_tool_call_output")]
    CustomToolCallOutput {
        #[serde(
            default,
            deserialize_with = "present_optional_string",
            skip_serializing_if = "Option::is_none"
        )]
        id: Option<String>,
        call_id: String,
        #[serde(
            default,
            deserialize_with = "present_optional_string",
            skip_serializing_if = "Option::is_none"
        )]
        name: Option<String>,
        output: CodexToolOutput,
    },
    #[serde(rename = "tool_search_call")]
    ToolSearchCall {
        #[serde(
            default,
            deserialize_with = "present_optional_string",
            skip_serializing_if = "Option::is_none"
        )]
        id: Option<String>,
        call_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        status: Option<CodexItemStatusWire>,
        execution: String,
        arguments: CodexSearchArgumentsWire,
    },
    #[serde(rename = "tool_search_output")]
    ToolSearchOutput {
        #[serde(
            default,
            deserialize_with = "present_optional_string",
            skip_serializing_if = "Option::is_none"
        )]
        id: Option<String>,
        call_id: String,
        status: CodexItemStatusWire,
        execution: String,
        tools: Vec<CodexDiscoveredTool>,
    },
}

impl CodexInputItem {
    fn id(&self) -> Option<&str> {
        match self {
            Self::Message { id, .. }
            | Self::Reasoning { id, .. }
            | Self::FunctionCall { id, .. }
            | Self::FunctionCallOutput { id, .. }
            | Self::CustomToolCall { id, .. }
            | Self::CustomToolCallOutput { id, .. }
            | Self::ToolSearchCall { id, .. }
            | Self::ToolSearchOutput { id, .. } => id.as_deref(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum CodexResponseWireItem {
    #[serde(rename = "message")]
    Message {
        #[serde(default, deserialize_with = "present_optional_string")]
        id: Option<String>,
        role: String,
        content: Vec<CodexResponseContent>,
        #[serde(default)]
        phase: Option<CodexMessagePhaseWire>,
        #[serde(default, rename = "status")]
        _status: Option<CodexItemStatusWire>,
    },
    #[serde(rename = "reasoning")]
    Reasoning {
        #[serde(default, deserialize_with = "present_optional_string")]
        id: Option<String>,
        summary: Vec<CodexSummaryWire>,
        #[serde(default)]
        content: Option<Vec<CodexReasoningWire>>,
        #[serde(default)]
        encrypted_content: Option<String>,
        #[serde(default, rename = "status")]
        _status: Option<CodexItemStatusWire>,
    },
    #[serde(rename = "function_call")]
    FunctionCall {
        #[serde(default, deserialize_with = "present_optional_string")]
        id: Option<String>,
        name: String,
        arguments: String,
        call_id: String,
        #[serde(default, rename = "status")]
        _status: Option<CodexItemStatusWire>,
    },
    #[serde(rename = "custom_tool_call")]
    CustomToolCall {
        #[serde(default, deserialize_with = "present_optional_string")]
        id: Option<String>,
        #[serde(default)]
        status: Option<CodexItemStatusWire>,
        call_id: String,
        name: String,
        input: String,
    },
    #[serde(rename = "tool_search_call")]
    ToolSearchCall {
        #[serde(default, deserialize_with = "present_optional_string")]
        id: Option<String>,
        call_id: String,
        #[serde(default)]
        status: Option<CodexItemStatusWire>,
        execution: String,
        arguments: CodexSearchArgumentsWire,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum CodexResponseContent {
    #[serde(rename = "output_text")]
    OutputText {
        text: String,
        #[serde(default, rename = "annotations")]
        _annotations: Option<IgnoredAny>,
        #[serde(default, rename = "logprobs")]
        _logprobs: Option<IgnoredAny>,
    },
}

impl CodexResponseWireItem {
    fn into_protocol(self) -> Result<CodexResponseItem, FetchAdaptorError> {
        Ok(match self {
            Self::Message {
                id,
                role,
                content,
                phase,
                ..
            } => {
                if role != "assistant" {
                    return Err(failed("Codex output message requires role=assistant"));
                }
                CodexResponseItem::Message {
                    id: validate_optional_id(id)?,
                    content: content
                        .into_iter()
                        .map(|part| match part {
                            CodexResponseContent::OutputText { text, .. } => {
                                Ok(CodexMessageContent::OutputText { text })
                            }
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                    phase: phase.map(Into::into),
                }
            }
            Self::Reasoning {
                id,
                summary,
                content,
                encrypted_content,
                ..
            } => CodexResponseItem::Reasoning {
                id: validate_optional_id(id)?,
                summary: summary
                    .into_iter()
                    .map(|part| CodexReasoningSummary { text: part.text })
                    .collect(),
                content: content.map(|content| {
                    content
                        .into_iter()
                        .map(|part| CodexReasoningContent { text: part.text })
                        .collect()
                }),
                encrypted_content,
            },
            Self::FunctionCall {
                id,
                call_id,
                name,
                arguments,
                ..
            } => {
                nonempty_bounded("call_id", &call_id, MAX_NAME_BYTES)?;
                validate_tool_name(&name)?;
                validate_json_arguments(&arguments)?;
                CodexResponseItem::FunctionCall {
                    id: validate_optional_id(id)?,
                    call_id,
                    name,
                    arguments,
                }
            }
            Self::CustomToolCall {
                id,
                status,
                call_id,
                name,
                input,
            } => {
                nonempty_bounded("call_id", &call_id, MAX_NAME_BYTES)?;
                validate_tool_name(&name)?;
                CodexResponseItem::CustomToolCall {
                    id: validate_optional_id(id)?,
                    status: status.map(Into::into),
                    call_id,
                    name,
                    input,
                }
            }
            Self::ToolSearchCall {
                id,
                call_id,
                status,
                execution,
                arguments,
            } => {
                nonempty_bounded("call_id", &call_id, MAX_NAME_BYTES)?;
                if execution != "client" || arguments.query.is_empty() {
                    return Err(failed("malformed provider tool_search call"));
                }
                CodexResponseItem::ToolSearchCall {
                    id: validate_optional_id(id)?,
                    call_id,
                    status: status.map(Into::into),
                    arguments: CodexToolSearchArguments {
                        query: arguments.query,
                        limit: arguments.limit,
                    },
                }
            }
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum CodexInputContent {
    #[serde(rename = "input_text")]
    InputText { text: String },
    #[serde(rename = "output_text")]
    OutputText { text: String },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum CodexToolOutput {
    Text(String),
    Content(Vec<CodexToolOutputContent>),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum CodexToolOutputContent {
    #[serde(rename = "input_text")]
    InputText { text: String },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum CodexDiscoveredTool {
    #[serde(rename = "function")]
    Function {
        name: String,
        description: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        strict: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        defer_loading: Option<bool>,
        parameters: JsonValue,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        output_schema: Option<JsonValue>,
    },
    #[serde(rename = "custom")]
    Custom {
        name: String,
        description: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        defer_loading: Option<bool>,
        format: CodexCustomFormat,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CodexMessagePhaseWire {
    Commentary,
    FinalAnswer,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CodexItemStatusWire {
    InProgress,
    Completed,
    Incomplete,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CodexSearchArgumentsWire {
    query: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    limit: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CodexSummaryWire {
    #[serde(rename = "type")]
    kind: SummaryKind,
    text: String,
}

#[derive(Debug, Deserialize, Serialize)]
enum SummaryKind {
    #[serde(rename = "summary_text")]
    SummaryText,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CodexReasoningWire {
    #[serde(rename = "type")]
    kind: ReasoningKind,
    text: String,
}

#[derive(Debug, Deserialize, Serialize)]
enum ReasoningKind {
    #[serde(rename = "reasoning_text")]
    ReasoningText,
}

struct ProjectionContract {
    functions: BTreeSet<String>,
    customs: BTreeSet<String>,
    deferred_functions: BTreeSet<String>,
    deferred_customs: BTreeSet<String>,
    has_tool_search: bool,
    tool_choice: CodexToolChoice,
    parallel_tool_calls: bool,
    reasoning: bool,
    prior_call_ids: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CallKind {
    Function,
    Custom,
    ToolSearch,
}

fn validate_input_history(
    input: &[CodexInputItem],
    mut contract: ProjectionContract,
) -> Result<ProjectionContract, FetchAdaptorError> {
    let mut calls: BTreeMap<&str, (CallKind, Option<&str>)> = BTreeMap::new();
    let mut outputs = BTreeSet::new();
    for item in input {
        if let Some(id) = item.id() {
            nonempty_bounded("history item id", id, MAX_NAME_BYTES)?;
        }
        match item {
            CodexInputItem::Message {
                role,
                content,
                phase,
                ..
            } => {
                if !matches!(role.as_str(), "developer" | "system" | "user" | "assistant") {
                    return Err(failed(format!("unsupported Codex message role `{role}`")));
                }
                if content.is_empty() {
                    return Err(failed("Codex message content must not be empty"));
                }
                let assistant = role == "assistant";
                if content
                    .iter()
                    .any(|part| matches!(part, CodexInputContent::OutputText { .. }) != assistant)
                {
                    return Err(failed(
                        "Codex assistant history requires output_text and prompts require input_text",
                    ));
                }
                if phase.is_some() && !assistant {
                    return Err(failed(
                        "Codex message phase is only valid for assistant history",
                    ));
                }
            }
            CodexInputItem::Reasoning { .. } => {}
            CodexInputItem::FunctionCall {
                call_id,
                name,
                arguments,
                ..
            } => {
                validate_tool_name(name)?;
                validate_json_arguments(arguments)?;
                insert_history_call(&mut calls, call_id, CallKind::Function, Some(name))?;
                contract.prior_call_ids.insert(call_id.clone());
            }
            CodexInputItem::CustomToolCall {
                call_id,
                name,
                status,
                ..
            } => {
                if status.is_some_and(|status| status != CodexItemStatusWire::Completed) {
                    return Err(failed("malformed custom tool history call status"));
                }
                validate_tool_name(name)?;
                insert_history_call(&mut calls, call_id, CallKind::Custom, Some(name))?;
                contract.prior_call_ids.insert(call_id.clone());
            }
            CodexInputItem::ToolSearchCall {
                call_id,
                status,
                execution,
                arguments,
                ..
            } => {
                if execution != "client"
                    || arguments.query.is_empty()
                    || status.is_some_and(|status| status != CodexItemStatusWire::Completed)
                {
                    return Err(failed("unauthorized or malformed tool_search history call"));
                }
                insert_history_call(&mut calls, call_id, CallKind::ToolSearch, None)?;
                contract.prior_call_ids.insert(call_id.clone());
            }
            CodexInputItem::FunctionCallOutput { call_id, .. } => {
                validate_history_output(&calls, &mut outputs, call_id, CallKind::Function, None)?;
            }
            CodexInputItem::CustomToolCallOutput { call_id, name, .. } => {
                validate_history_output(
                    &calls,
                    &mut outputs,
                    call_id,
                    CallKind::Custom,
                    name.as_deref(),
                )?;
            }
            CodexInputItem::ToolSearchOutput {
                call_id,
                status,
                execution,
                tools,
                ..
            } => {
                if *status != CodexItemStatusWire::Completed || execution != "client" {
                    return Err(failed("malformed tool_search output history"));
                }
                validate_history_output(&calls, &mut outputs, call_id, CallKind::ToolSearch, None)?;
                for tool in tools {
                    match tool {
                        CodexDiscoveredTool::Function {
                            name,
                            parameters,
                            output_schema,
                            ..
                        } => {
                            validate_tool_name(name)?;
                            require_object("discovered function parameters", parameters)?;
                            if let Some(schema) = output_schema {
                                require_object("discovered function output_schema", schema)?;
                            }
                            if contract.customs.contains(name)
                                || contract.deferred_customs.contains(name)
                            {
                                return Err(failed(format!(
                                    "tool_search changed `{name}` from custom to function"
                                )));
                            }
                            if !contract.deferred_functions.remove(name) {
                                return Err(failed(format!(
                                    "tool_search discovered undeclared or already callable function `{name}`"
                                )));
                            }
                            contract.functions.insert(name.clone());
                        }
                        CodexDiscoveredTool::Custom { name, format, .. } => {
                            validate_tool_name(name)?;
                            format.validate()?;
                            if contract.functions.contains(name)
                                || contract.deferred_functions.contains(name)
                            {
                                return Err(failed(format!(
                                    "tool_search changed `{name}` from function to custom"
                                )));
                            }
                            if !contract.deferred_customs.remove(name) {
                                return Err(failed(format!(
                                    "tool_search discovered undeclared or already callable custom `{name}`"
                                )));
                            }
                            contract.customs.insert(name.clone());
                        }
                    }
                }
            }
        }
    }
    Ok(contract)
}

fn insert_history_call<'a>(
    calls: &mut BTreeMap<&'a str, (CallKind, Option<&'a str>)>,
    call_id: &'a str,
    kind: CallKind,
    name: Option<&'a str>,
) -> Result<(), FetchAdaptorError> {
    nonempty_bounded("call_id", call_id, MAX_NAME_BYTES)?;
    if calls.insert(call_id, (kind, name)).is_some() {
        return Err(failed(format!("duplicate history call_id `{call_id}`")));
    }
    Ok(())
}

fn validate_history_output(
    calls: &BTreeMap<&str, (CallKind, Option<&str>)>,
    outputs: &mut BTreeSet<String>,
    call_id: &str,
    kind: CallKind,
    name: Option<&str>,
) -> Result<(), FetchAdaptorError> {
    let Some((expected_kind, expected_name)) = calls.get(call_id) else {
        return Err(failed(format!(
            "output references unknown call_id `{call_id}`"
        )));
    };
    if *expected_kind != kind || name.is_some_and(|name| Some(name) != *expected_name) {
        return Err(failed(format!("output contradicts call_id `{call_id}`")));
    }
    if !outputs.insert(call_id.to_string()) {
        return Err(failed(format!("duplicate output for call_id `{call_id}`")));
    }
    Ok(())
}

fn validate_client_metadata(
    metadata: Option<&BTreeMap<String, String>>,
) -> Result<(), FetchAdaptorError> {
    let Some(metadata) = metadata else {
        return Ok(());
    };
    if metadata.len() > MAX_CLIENT_METADATA_ENTRIES {
        return Err(failed("too many Codex client_metadata entries"));
    }
    for (key, value) in metadata {
        nonempty_bounded("client_metadata key", key, MAX_CLIENT_METADATA_KEY_BYTES)?;
        if value.len() > MAX_CLIENT_METADATA_VALUE_BYTES {
            return Err(failed("Codex client_metadata value is too large"));
        }
    }
    Ok(())
}

fn validate_tool_name(name: &str) -> Result<(), FetchAdaptorError> {
    nonempty_bounded("tool name", name, MAX_NAME_BYTES)
}

fn validate_json_arguments(arguments: &str) -> Result<(), FetchAdaptorError> {
    serde_json::from_str::<JsonValue>(arguments)
        .map(|_| ())
        .map_err(|error| failed(format!("function arguments are not valid JSON: {error}")))
}

fn require_object(label: &str, value: &JsonValue) -> Result<(), FetchAdaptorError> {
    if value.is_object() {
        Ok(())
    } else {
        Err(failed(format!("{label} must be an object")))
    }
}

fn nonempty_bounded(label: &str, value: &str, maximum: usize) -> Result<(), FetchAdaptorError> {
    if value.is_empty() || value.len() > maximum {
        Err(failed(format!(
            "{label} must contain 1..={maximum} UTF-8 bytes"
        )))
    } else {
        Ok(())
    }
}

fn validate_declared_call(
    contract: &ProjectionContract,
    kind: CallKind,
    name: &str,
) -> Result<(), FetchAdaptorError> {
    let declared = permits_call_kind(contract, kind)
        && match kind {
            CallKind::Function => contract.functions.contains(name),
            CallKind::Custom => contract.customs.contains(name),
            CallKind::ToolSearch => contract.has_tool_search,
        };
    if !declared {
        return Err(failed(format!(
            "provider emitted unauthorized tool call `{name}`"
        )));
    }
    Ok(())
}

fn permits_call_kind(contract: &ProjectionContract, kind: CallKind) -> bool {
    contract.tool_choice != CodexToolChoice::None
        && match kind {
            CallKind::Function => !contract.functions.is_empty(),
            CallKind::Custom => !contract.customs.is_empty(),
            CallKind::ToolSearch => contract.has_tool_search,
        }
}

impl From<CodexItemStatusWire> for CodexItemStatus {
    fn from(value: CodexItemStatusWire) -> Self {
        match value {
            CodexItemStatusWire::InProgress => Self::InProgress,
            CodexItemStatusWire::Completed => Self::Completed,
            CodexItemStatusWire::Incomplete => Self::Incomplete,
        }
    }
}

impl From<CodexMessagePhaseWire> for CodexMessagePhase {
    fn from(value: CodexMessagePhaseWire) -> Self {
        match value {
            CodexMessagePhaseWire::Commentary => Self::Commentary,
            CodexMessagePhaseWire::FinalAnswer => Self::FinalAnswer,
        }
    }
}

fn validate_optional_id(id: Option<String>) -> Result<Option<String>, FetchAdaptorError> {
    if let Some(id) = &id {
        nonempty_bounded("output item id", id, MAX_NAME_BYTES)?;
    }
    Ok(id)
}

#[derive(Default)]
struct DeltaState {
    output_text: BTreeMap<DeltaTarget, String>,
    custom_inputs: BTreeMap<String, String>,
    function_arguments: BTreeMap<String, String>,
    reasoning_summary: BTreeMap<(String, u64, u64), String>,
    reasoning_content: BTreeMap<(String, u64, u64), String>,
}

#[derive(Clone, Debug, Ord, PartialOrd, PartialEq, Eq)]
struct DeltaTarget {
    item_id: String,
    output_index: u64,
    content_index: u64,
}

#[derive(Clone)]
struct PendingItem {
    item: CodexResponseItem,
    output_index: Option<u64>,
}

impl PendingItem {
    fn matches(&self, item: &CodexResponseItem) -> bool {
        item_kind_name(&self.item) == item_kind_name(item)
            && item.id().is_none_or(|id| self.item.id() == Some(id))
            && item
                .call_id()
                .is_none_or(|call_id| self.item.call_id() == Some(call_id))
    }

    fn shares_identity(&self, item: &CodexResponseItem) -> bool {
        item_kind_name(&self.item) == item_kind_name(item)
            && (item.id().is_some_and(|id| self.item.id() == Some(id))
                || item
                    .call_id()
                    .is_some_and(|call_id| self.item.call_id() == Some(call_id)))
    }
}

struct CodexProjector {
    contract: ProjectionContract,
    decoder: SseDecoder,
    sequence_mode: Option<bool>,
    next_sequence: u64,
    created: bool,
    response_id: Option<String>,
    server_model: Option<String>,
    pending_items: Vec<PendingItem>,
    done_item_ids: BTreeSet<String>,
    seen_call_ids: BTreeSet<String>,
    completed_calls: usize,
    deltas: DeltaState,
    terminal: Option<(Usage, StopReason)>,
    finished: bool,
}

impl CodexProjector {
    fn new(contract: ProjectionContract) -> Self {
        let seen_call_ids = contract.prior_call_ids.clone();
        Self {
            contract,
            decoder: SseDecoder::new(),
            sequence_mode: None,
            next_sequence: 0,
            created: false,
            response_id: None,
            server_model: None,
            pending_items: Vec::new(),
            done_item_ids: BTreeSet::new(),
            seen_call_ids,
            completed_calls: 0,
            deltas: DeltaState::default(),
            terminal: None,
            finished: false,
        }
    }

    fn decode_frames(
        &mut self,
        frames: Vec<WireStreamEvent>,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        let mut output = Vec::new();
        for frame in frames {
            if self.terminal.is_some() {
                return Err(failed("Codex stream contained an event after completion"));
            }
            output.extend(self.decode_frame(frame)?);
        }
        Ok(output)
    }

    fn decode_frame(
        &mut self,
        frame: WireStreamEvent,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        let data = match frame.data {
            WireEventData::Text(text) => serde_json::from_str(&text),
            WireEventData::Json(value) => Ok(value),
            WireEventData::Bytes(bytes) => serde_json::from_slice(&bytes),
        }
        .map_err(|error| failed(format!("invalid Codex SSE JSON: {error}")))?;
        let mut object = data
            .as_object()
            .cloned()
            .ok_or_else(|| failed("Codex SSE data must be a JSON object"))?;
        let kind = object
            .remove("type")
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or_else(|| failed("Codex SSE event requires string type"))?;
        if frame.name.as_deref() != Some(kind.as_str()) {
            return Err(failed("Codex SSE event name must exactly match its type"));
        }
        self.validate_sequence(object.remove("sequence_number"))?;
        if !matches!(
            kind.as_str(),
            "response.created" | "response.failed" | "response.incomplete" | "error"
        ) {
            self.require_created()?;
        }

        match kind.as_str() {
            "response.created" => self.created(event_payload(object)?),
            "response.in_progress" => self.in_progress(event_payload(object)?),
            "response.output_item.added" => self.output_item(event_payload(object)?, false),
            "response.output_item.done" => self.output_item(event_payload(object)?, true),
            "response.output_text.delta" => self.output_text_delta(event_payload(object)?),
            "response.output_text.done" => self.output_text_done(event_payload(object)?),
            "response.custom_tool_call_input.delta" => {
                self.custom_input_delta(event_payload(object)?)
            }
            "response.custom_tool_call_input.done" => {
                self.custom_input_done(event_payload(object)?)
            }
            "response.function_call_arguments.delta" => {
                self.function_arguments_delta(event_payload(object)?)
            }
            "response.function_call_arguments.done" => {
                self.function_arguments_done(event_payload(object)?)
            }
            "response.reasoning_summary_part.added" => {
                self.reasoning_part_added(event_payload(object)?)
            }
            "response.reasoning_summary_part.done" => {
                self.redundant_reasoning_part(event_payload(object)?)
            }
            "response.reasoning_summary_text.delta" => {
                self.reasoning_summary_delta(event_payload(object)?)
            }
            "response.reasoning_summary_text.done" => {
                self.reasoning_summary_done(event_payload(object)?)
            }
            "response.reasoning_text.delta" => self.reasoning_content_delta(event_payload(object)?),
            "response.content_part.added" => self.content_part(event_payload(object)?, false),
            "response.content_part.done" => self.content_part(event_payload(object)?, true),
            "response.completed" => self.completed(event_payload(object)?),
            "response.failed" => Err(provider_failure(event_payload(object)?)),
            "response.incomplete" => Err(failed("Codex upstream returned an incomplete response")),
            "error" => Err(provider_error(event_payload(object)?)),
            other => Err(failed(format!(
                "unsupported sealed Codex SSE event `{other}`"
            ))),
        }
    }

    fn validate_sequence(&mut self, value: Option<JsonValue>) -> Result<(), FetchAdaptorError> {
        let present = value.is_some();
        if self.sequence_mode.is_some_and(|mode| mode != present) {
            return Err(failed("Codex SSE mixed sequenced and unsequenced events"));
        }
        self.sequence_mode.get_or_insert(present);
        if let Some(value) = value {
            let sequence = value
                .as_u64()
                .ok_or_else(|| failed("Codex sequence_number must be an integer"))?;
            if sequence != self.next_sequence {
                return Err(failed(format!(
                    "Codex sequence_number {sequence} is not expected {}",
                    self.next_sequence
                )));
            }
            self.next_sequence = sequence
                .checked_add(1)
                .ok_or_else(|| failed("Codex sequence_number overflow"))?;
        }
        Ok(())
    }

    fn require_created(&self) -> Result<(), FetchAdaptorError> {
        if self.created {
            Ok(())
        } else {
            Err(failed(
                "Codex semantic event arrived before response.created",
            ))
        }
    }

    fn created(
        &mut self,
        payload: LifecyclePayload,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        if self.created {
            return Err(failed("duplicate response.created"));
        }
        let lifecycle = payload.response.validate("in_progress", None)?;
        self.observe_server_model(lifecycle.model)?;
        let id = lifecycle.id;
        self.created = true;
        self.response_id.clone_from(&id);
        Ok(vec![codex(CodexResponsesEvent::Created {
            response_id: id,
        })])
    }

    fn in_progress(
        &mut self,
        payload: LifecyclePayload,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        let lifecycle = payload
            .response
            .validate("in_progress", self.response_id.as_deref())?;
        self.observe_server_model(lifecycle.model)?;
        let id = lifecycle.id;
        if self.response_id.is_none() {
            self.response_id = id;
        }
        Ok(Vec::new())
    }

    fn output_item(
        &mut self,
        payload: ItemPayload,
        done: bool,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        let output_index = payload.output_index;
        let item = payload.item.into_protocol()?;
        self.authorize_item(&item, done)?;
        let expected_status = if done {
            CodexItemStatus::Completed
        } else {
            CodexItemStatus::InProgress
        };
        if item_status(&item).is_some_and(|status| status != expected_status) {
            return Err(failed(
                "Codex output item status contradicted its lifecycle event",
            ));
        }
        if done {
            if let Some(id) = item.id()
                && self.done_item_ids.contains(id)
            {
                return Err(failed(format!("duplicate Codex output item id `{id}`")));
            }
            let mut matches = self
                .pending_items
                .iter()
                .enumerate()
                .filter_map(|(index, pending)| pending.matches(&item).then_some(index));
            let pending_index = matches.next();
            if matches.next().is_some() {
                return Err(failed(
                    "output_item.done ambiguously matched multiple output_item.added events",
                ));
            }
            if let Some(index) = pending_index {
                let pending = self.pending_items.remove(index);
                if output_index.is_some() && output_index != pending.output_index {
                    return Err(failed("output_item.done contradicted output_index"));
                }
                validate_paired_item(&pending.item, &item)?;
                self.cross_check_done(&pending.item, &item, pending.output_index)?;
            } else if self.pending_items.iter().any(|pending| {
                pending.shares_identity(&item)
                    || (item_kind_name(&pending.item) == item_kind_name(&item)
                        && (item.id().is_some() || item.call_id().is_some()))
            }) {
                return Err(failed("output_item.done contradicted output_item.added"));
            }
            if let Some(id) = item.id() {
                self.done_item_ids.insert(id.to_string());
            }
            Ok(vec![codex(CodexResponsesEvent::OutputItemDone(item))])
        } else {
            if item_key(&item).is_none() {
                return Err(failed(
                    "output_item.added requires an id or call_id for later correlation",
                ));
            }
            if self.pending_items.iter().any(|pending| {
                item.id().is_some_and(|id| pending.item.id() == Some(id))
                    || item
                        .call_id()
                        .is_some_and(|call_id| pending.item.call_id() == Some(call_id))
            }) {
                return Err(failed("duplicate response.output_item.added"));
            }
            self.pending_items.push(PendingItem {
                item: item.clone(),
                output_index,
            });
            Ok(vec![codex(CodexResponsesEvent::OutputItemAdded(item))])
        }
    }

    fn authorize_item(
        &mut self,
        item: &CodexResponseItem,
        done: bool,
    ) -> Result<(), FetchAdaptorError> {
        match item {
            CodexResponseItem::Reasoning { .. } if !self.contract.reasoning => {
                return Err(failed(
                    "provider emitted reasoning not authorized by request",
                ));
            }
            CodexResponseItem::FunctionCall {
                call_id,
                name,
                arguments,
                ..
            } => {
                validate_declared_call(&self.contract, CallKind::Function, name)?;
                validate_json_arguments(arguments)?;
                self.authorize_call_id(call_id, done)?;
            }
            CodexResponseItem::CustomToolCall { call_id, name, .. } => {
                validate_declared_call(&self.contract, CallKind::Custom, name)?;
                self.authorize_call_id(call_id, done)?;
            }
            CodexResponseItem::ToolSearchCall { call_id, .. } => {
                validate_declared_call(&self.contract, CallKind::ToolSearch, "tool_search")?;
                self.authorize_call_id(call_id, done)?;
            }
            CodexResponseItem::Message { .. } | CodexResponseItem::Reasoning { .. } => {}
        }
        Ok(())
    }

    fn authorize_call_id(&mut self, call_id: &str, done: bool) -> Result<(), FetchAdaptorError> {
        if done {
            // An added item reserves a call ID only until its matching done
            // event commits it. A standalone done item commits it directly.
            if !self.seen_call_ids.insert(call_id.to_string()) {
                return Err(failed(format!("duplicate provider call_id `{call_id}`")));
            }
            self.completed_calls = self
                .completed_calls
                .checked_add(1)
                .ok_or_else(|| failed("too many Codex tool calls"))?;
            if !self.contract.parallel_tool_calls && self.completed_calls > 1 {
                return Err(failed(
                    "provider emitted parallel calls when parallel_tool_calls=false",
                ));
            }
        } else if self.seen_call_ids.contains(call_id)
            || self
                .pending_items
                .iter()
                .any(|pending| pending.item.call_id() == Some(call_id))
        {
            return Err(failed(format!("duplicate provider call_id `{call_id}`")));
        }
        Ok(())
    }

    fn pending_message(&self, target: &DeltaTarget) -> Result<(), FetchAdaptorError> {
        let found = self.pending_items.iter().any(|pending| {
            matches!(pending.item, CodexResponseItem::Message { .. })
                && pending.item.id() == Some(target.item_id.as_str())
                && pending.output_index == Some(target.output_index)
        });
        if found {
            Ok(())
        } else {
            Err(failed(
                "output text delta did not match a pending message identity",
            ))
        }
    }

    fn pending_reasoning(&self, item_id: &str, output_index: u64) -> Result<(), FetchAdaptorError> {
        let found = self.pending_items.iter().any(|pending| {
            matches!(pending.item, CodexResponseItem::Reasoning { .. })
                && pending.item.id() == Some(item_id)
                && pending.output_index == Some(output_index)
        });
        if found {
            Ok(())
        } else {
            Err(failed(
                "reasoning event did not match a pending reasoning identity",
            ))
        }
    }

    fn pending_reasoning_optional(
        &self,
        item_id: &str,
        output_index: Option<u64>,
    ) -> Result<(), FetchAdaptorError> {
        let found = self.pending_items.iter().any(|pending| {
            matches!(pending.item, CodexResponseItem::Reasoning { .. })
                && pending.item.id() == Some(item_id)
                && output_index.is_none_or(|index| pending.output_index == Some(index))
        });
        if found {
            Ok(())
        } else {
            Err(failed(
                "reasoning event did not match a pending reasoning identity",
            ))
        }
    }

    fn pending_call(
        &self,
        item_id: &str,
        kind: CallKind,
        call_id: &str,
        name: Option<&str>,
    ) -> Result<(), FetchAdaptorError> {
        let found = self
            .pending_items
            .iter()
            .any(|pending| match (&pending.item, kind) {
                (
                    CodexResponseItem::FunctionCall {
                        id,
                        name: pending_name,
                        ..
                    },
                    CallKind::Function,
                ) => id.as_deref() == Some(item_id) && name.is_none_or(|name| name == pending_name),
                (
                    CodexResponseItem::CustomToolCall {
                        id,
                        call_id: pending_call_id,
                        name: pending_name,
                        ..
                    },
                    CallKind::Custom,
                ) => {
                    id.as_deref() == Some(item_id)
                        && pending_call_id == call_id
                        && name.is_none_or(|name| name == pending_name)
                }
                _ => false,
            });
        if found {
            Ok(())
        } else {
            Err(failed("tool delta did not match its pending item identity"))
        }
    }

    fn pending_call_by_item(
        &self,
        item_id: &str,
        kind: CallKind,
        name: Option<&str>,
    ) -> Result<(), FetchAdaptorError> {
        let found = self
            .pending_items
            .iter()
            .any(|pending| match (&pending.item, kind) {
                (
                    CodexResponseItem::FunctionCall {
                        id,
                        name: pending_name,
                        ..
                    },
                    CallKind::Function,
                ) => id.as_deref() == Some(item_id) && name.is_none_or(|name| name == pending_name),
                (
                    CodexResponseItem::CustomToolCall {
                        id,
                        name: pending_name,
                        ..
                    },
                    CallKind::Custom,
                ) => id.as_deref() == Some(item_id) && name.is_none_or(|name| name == pending_name),
                _ => false,
            });
        if found {
            Ok(())
        } else {
            Err(failed("tool delta did not match its pending item identity"))
        }
    }

    fn cross_check_done(
        &mut self,
        identity: &CodexResponseItem,
        item: &CodexResponseItem,
        output_index: Option<u64>,
    ) -> Result<(), FetchAdaptorError> {
        match item {
            CodexResponseItem::Message { content, .. } => {
                let item_id = identity
                    .id()
                    .ok_or_else(|| failed("message item lost its id"))?;
                let keys = self
                    .deltas
                    .output_text
                    .keys()
                    .filter(|target| {
                        target.item_id == item_id && output_index == Some(target.output_index)
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                for target in keys {
                    let text = self
                        .deltas
                        .output_text
                        .get(&target)
                        .expect("output-text target came from map");
                    let content_index = usize::try_from(target.content_index)
                        .map_err(|_| failed("output text content index is too large"))?;
                    let Some(CodexMessageContent::OutputText { text: done }) =
                        content.get(content_index)
                    else {
                        return Err(failed(
                            "output text delta named a missing message content part",
                        ));
                    };
                    if done != text {
                        return Err(failed("output_text deltas contradicted message item"));
                    }
                    self.deltas.output_text.remove(&target);
                }
            }
            CodexResponseItem::Reasoning {
                summary, content, ..
            } => {
                let item_id = identity
                    .id()
                    .ok_or_else(|| failed("reasoning item lost its id"))?;
                let summary_keys = self
                    .deltas
                    .reasoning_summary
                    .keys()
                    .filter(|(delta_item_id, delta_output_index, _)| {
                        delta_item_id == item_id && output_index == Some(*delta_output_index)
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                for (delta_item_id, delta_output_index, index) in summary_keys {
                    let delta = self
                        .deltas
                        .reasoning_summary
                        .remove(&(delta_item_id, delta_output_index, index))
                        .expect("reasoning summary key came from map");
                    let index = usize::try_from(index)
                        .map_err(|_| failed("reasoning summary index is too large"))?;
                    if summary.get(index).map(|part| part.text.as_str()) != Some(delta.as_str()) {
                        return Err(failed("reasoning summary deltas contradicted done item"));
                    }
                }
                let content_keys = self
                    .deltas
                    .reasoning_content
                    .keys()
                    .filter(|(delta_item_id, delta_output_index, _)| {
                        delta_item_id == item_id && output_index == Some(*delta_output_index)
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                for (delta_item_id, delta_output_index, index) in content_keys {
                    let delta = self
                        .deltas
                        .reasoning_content
                        .remove(&(delta_item_id, delta_output_index, index))
                        .expect("reasoning content key came from map");
                    let index = usize::try_from(index)
                        .map_err(|_| failed("reasoning content index is too large"))?;
                    if content
                        .as_ref()
                        .and_then(|parts| parts.get(index))
                        .map(|part| part.text.as_str())
                        != Some(delta.as_str())
                    {
                        return Err(failed("reasoning content deltas contradicted done item"));
                    }
                }
            }
            CodexResponseItem::FunctionCall { arguments, .. } => {
                if let Some(id) = identity.id()
                    && let Some(delta) = self.deltas.function_arguments.remove(id)
                    && delta != *arguments
                {
                    return Err(failed("function argument deltas contradicted done item"));
                }
            }
            CodexResponseItem::CustomToolCall { input, .. } => {
                if let Some(id) = identity.id()
                    && let Some(delta) = self.deltas.custom_inputs.remove(id)
                    && delta != *input
                {
                    return Err(failed("custom input deltas contradicted done item"));
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn output_text_delta(
        &mut self,
        payload: TextDeltaPayload,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        let target = DeltaTarget {
            item_id: payload.item_id.clone(),
            output_index: payload.output_index,
            content_index: payload.content_index,
        };
        self.pending_message(&target)?;
        self.deltas
            .output_text
            .entry(target)
            .or_default()
            .push_str(&payload.delta);
        Ok(vec![codex(CodexResponsesEvent::OutputTextDelta {
            delta: payload.delta,
        })])
    }

    fn output_text_done(
        &mut self,
        payload: TextDonePayload,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        let target = DeltaTarget {
            item_id: payload.item_id,
            output_index: payload.output_index,
            content_index: payload.content_index,
        };
        self.pending_message(&target)?;
        if self.deltas.output_text.get(&target) != Some(&payload.text) {
            return Err(failed("response.output_text.done contradicted deltas"));
        }
        Ok(Vec::new())
    }

    fn custom_input_delta(
        &mut self,
        payload: ToolDeltaPayload,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        if !permits_call_kind(&self.contract, CallKind::Custom) {
            return Err(failed("unauthorized custom tool delta"));
        }
        nonempty_bounded("custom tool item_id", &payload.item_id, MAX_NAME_BYTES)?;
        let call_id = payload
            .call_id
            .as_deref()
            .ok_or_else(|| failed("custom tool delta requires call_id for exact correlation"))?;
        nonempty_bounded("custom tool call_id", call_id, MAX_NAME_BYTES)?;
        self.pending_call(&payload.item_id, CallKind::Custom, call_id, None)?;
        self.deltas
            .custom_inputs
            .entry(payload.item_id.clone())
            .or_default()
            .push_str(&payload.delta);
        Ok(vec![codex(CodexResponsesEvent::CustomToolCallInputDelta {
            item_id: payload.item_id,
            call_id: payload.call_id,
            delta: payload.delta,
        })])
    }

    fn custom_input_done(
        &mut self,
        payload: ToolDonePayload,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        if !permits_call_kind(&self.contract, CallKind::Custom) {
            return Err(failed("unauthorized custom tool completion"));
        }
        nonempty_bounded("custom tool item_id", &payload.item_id, MAX_NAME_BYTES)?;
        if let Some(call_id) = payload.call_id.as_deref() {
            nonempty_bounded("custom tool call_id", call_id, MAX_NAME_BYTES)?;
            self.pending_call(&payload.item_id, CallKind::Custom, call_id, None)?;
        } else {
            self.pending_call_by_item(&payload.item_id, CallKind::Custom, None)?;
        }
        if let Some(input) = payload.value
            && self
                .deltas
                .custom_inputs
                .get(&payload.item_id)
                .is_some_and(|delta| delta != &input)
        {
            return Err(failed("custom input done contradicted deltas"));
        }
        Ok(Vec::new())
    }

    fn function_arguments_delta(
        &mut self,
        payload: FunctionDeltaPayload,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        if !permits_call_kind(&self.contract, CallKind::Function) {
            return Err(failed("unauthorized function argument delta"));
        }
        nonempty_bounded("function item_id", &payload.item_id, MAX_NAME_BYTES)?;
        self.pending_call(&payload.item_id, CallKind::Function, "", None)?;
        self.deltas
            .function_arguments
            .entry(payload.item_id)
            .or_default()
            .push_str(&payload.delta);
        Ok(Vec::new())
    }

    fn function_arguments_done(
        &mut self,
        payload: FunctionDonePayload,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        if !permits_call_kind(&self.contract, CallKind::Function) {
            return Err(failed("unauthorized function argument completion"));
        }
        nonempty_bounded("function item_id", &payload.item_id, MAX_NAME_BYTES)?;
        self.pending_call_by_item(
            &payload.item_id,
            CallKind::Function,
            payload.name.as_deref(),
        )?;
        validate_json_arguments(&payload.arguments)?;
        if self
            .deltas
            .function_arguments
            .get(&payload.item_id)
            .is_some_and(|delta| delta != &payload.arguments)
        {
            return Err(failed("function arguments done contradicted deltas"));
        }
        Ok(Vec::new())
    }

    fn reasoning_part_added(
        &mut self,
        payload: ReasoningPartPayload,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        if !self.contract.reasoning {
            return Err(failed("unauthorized reasoning event"));
        }
        if let (Some(item_id), Some(output_index)) =
            (payload.item_id.as_deref(), payload.output_index)
        {
            self.pending_reasoning(item_id, output_index)?;
        }
        Ok(vec![codex(
            CodexResponsesEvent::ReasoningSummaryPartAdded {
                summary_index: payload.summary_index,
            },
        )])
    }

    fn redundant_reasoning_part(
        &mut self,
        payload: ReasoningPartPayload,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        if !self.contract.reasoning {
            Err(failed("unauthorized reasoning event"))
        } else {
            if let (Some(item_id), Some(output_index)) =
                (payload.item_id.as_deref(), payload.output_index)
            {
                self.pending_reasoning(item_id, output_index)?;
            }
            Ok(Vec::new())
        }
    }

    fn reasoning_summary_delta(
        &mut self,
        payload: ReasoningDeltaPayload,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        if !self.contract.reasoning {
            return Err(failed("unauthorized reasoning event"));
        }
        self.pending_reasoning(&payload.item_id, payload.output_index)?;
        self.deltas
            .reasoning_summary
            .entry((payload.item_id.clone(), payload.output_index, payload.index))
            .or_default()
            .push_str(&payload.delta);
        Ok(vec![codex(CodexResponsesEvent::ReasoningSummaryDelta {
            delta: payload.delta,
            summary_index: payload.index,
        })])
    }

    fn reasoning_summary_done(
        &mut self,
        payload: ReasoningDonePayload,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        if !self.contract.reasoning {
            return Err(failed("unauthorized reasoning event"));
        }
        self.pending_reasoning_optional(&payload.item_id, payload.output_index)?;
        if let Some(output_index) = payload.output_index {
            if self
                .deltas
                .reasoning_summary
                .get(&(payload.item_id.clone(), output_index, payload.summary_index))
                .is_some_and(|delta| delta != &payload.text)
            {
                return Err(failed("reasoning summary done contradicted deltas"));
            }
        } else if self
            .deltas
            .reasoning_summary
            .keys()
            .any(|(item_id, _, index)| {
                item_id == &payload.item_id && *index == payload.summary_index
            })
        {
            return Err(failed(
                "reasoning summary done requires output_index to correlate deltas",
            ));
        }
        Ok(vec![codex(CodexResponsesEvent::ReasoningSummaryDone {
            item_id: payload.item_id,
            text: payload.text,
            summary_index: payload.summary_index,
        })])
    }

    fn reasoning_content_delta(
        &mut self,
        payload: ReasoningDeltaPayload,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        if !self.contract.reasoning {
            return Err(failed("unauthorized reasoning event"));
        }
        self.pending_reasoning(&payload.item_id, payload.output_index)?;
        self.deltas
            .reasoning_content
            .entry((payload.item_id.clone(), payload.output_index, payload.index))
            .or_default()
            .push_str(&payload.delta);
        Ok(vec![codex(CodexResponsesEvent::ReasoningContentDelta {
            delta: payload.delta,
            content_index: payload.index,
        })])
    }

    fn content_part(
        &mut self,
        payload: ContentPartPayload,
        done: bool,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        let target = DeltaTarget {
            item_id: payload.item_id,
            output_index: payload.output_index.ok_or_else(|| {
                failed("content part requires output_index for exact correlation")
            })?,
            content_index: payload.content_index,
        };
        self.pending_message(&target)?;
        if done && self.deltas.output_text.get(&target) != Some(&payload.part.text) {
            return Err(failed("content part contradicted output text deltas"));
        }
        Ok(Vec::new())
    }

    fn completed(
        &mut self,
        payload: CompletedPayload,
    ) -> Result<Vec<OutputEvent>, FetchAdaptorError> {
        if !self.pending_items.is_empty()
            || !self.deltas.output_text.is_empty()
            || !self.deltas.custom_inputs.is_empty()
            || !self.deltas.function_arguments.is_empty()
            || !self.deltas.reasoning_summary.is_empty()
            || !self.deltas.reasoning_content.is_empty()
        {
            return Err(failed("Codex completed with unfinished semantic output"));
        }
        if self.contract.tool_choice == CodexToolChoice::Required && self.completed_calls == 0 {
            return Err(failed("provider completed without the required tool call"));
        }
        let (mut completed, lifecycle_model) = payload
            .response
            .into_completed(self.response_id.as_deref())?;
        self.observe_server_model(lifecycle_model)?;
        completed.server_model = self.server_model.clone();
        let usage = Usage {
            input_tokens: Some(completed.usage.input_tokens),
            output_tokens: Some(completed.usage.output_tokens),
            total_tokens: Some(completed.usage.total_tokens),
        };
        let stop_reason = if self.completed_calls == 0 {
            StopReason::EndOfText
        } else {
            StopReason::ToolCall
        };
        self.terminal = Some((usage, stop_reason));
        Ok(vec![codex(CodexResponsesEvent::Completed(completed))])
    }

    fn observe_server_model(&mut self, model: Option<String>) -> Result<(), FetchAdaptorError> {
        let Some(model) = model else {
            return Ok(());
        };
        nonempty_bounded("effective server model", &model, MAX_MODEL_BYTES)?;
        if self
            .server_model
            .as_deref()
            .is_some_and(|known| known != model)
        {
            return Err(failed("Codex server model claims contradicted each other"));
        }
        self.server_model = Some(model);
        Ok(())
    }
}

impl FetchProjector for CodexProjector {
    fn begin(
        &mut self,
        head: FetchProviderResponseHead,
    ) -> Result<Vec<ProjectedFetch>, FetchAdaptorError> {
        if self.created || self.finished {
            return Err(failed("Codex projector response head arrived out of order"));
        }
        self.observe_server_model(head.effective_model)?;
        Ok(Vec::new())
    }

    fn project(&mut self, bytes: &[u8]) -> Result<Vec<ProjectedFetch>, FetchAdaptorError> {
        if self.finished {
            return Err(failed("Codex projector received bytes after EOF"));
        }
        if self.terminal.is_some() && !bytes.is_empty() {
            return Err(failed("Codex stream contained bytes after completion"));
        }
        let frames = push_sse(&mut self.decoder, bytes, "Codex").map_err(failed)?;
        let events = self.decode_frames(frames)?;
        if self.terminal.is_some() && !self.decoder.pending_bytes().is_empty() {
            return Err(failed("Codex stream contained bytes after completion"));
        }
        project_events(&events).map_err(payload_error)
    }

    fn finish(&mut self) -> Result<Vec<ProjectedFetch>, FetchAdaptorError> {
        if self.finished {
            return Err(failed("Codex projector was finished twice"));
        }
        if !self.decoder.pending_bytes().is_empty() {
            return Err(failed(
                "Codex SSE stream ended without a blank-line frame delimiter",
            ));
        }
        // Complete frames were consumed by project(); an empty buffer has no tail to decode.
        let (usage, stop_reason) = self
            .terminal
            .take()
            .ok_or_else(|| failed("Codex stream ended without response.completed"))?;
        let projected = ProjectedFetch::Terminal(
            encode_fetch_terminal_payload(&OutputEvent::Finished {
                stop_reason,
                usage: Some(usage),
            })
            .map_err(payload_error)?,
        );
        self.finished = true;
        Ok(vec![projected])
    }
}

fn codex(event: CodexResponsesEvent) -> OutputEvent {
    OutputEvent::Adaptor(AdaptorEvent::CodexResponses(event))
}

fn event_payload<T: DeserializeOwned>(
    object: JsonMap<String, JsonValue>,
) -> Result<T, FetchAdaptorError> {
    serde_json::from_value(JsonValue::Object(object))
        .map_err(|error| failed(format!("malformed Codex SSE event: {error}")))
}

fn item_key(item: &CodexResponseItem) -> Option<String> {
    item.id().or_else(|| item.call_id()).map(str::to_owned)
}

fn item_kind_name(item: &CodexResponseItem) -> &'static str {
    match item {
        CodexResponseItem::Message { .. } => "message",
        CodexResponseItem::Reasoning { .. } => "reasoning",
        CodexResponseItem::FunctionCall { .. } => "function_call",
        CodexResponseItem::CustomToolCall { .. } => "custom_tool_call",
        CodexResponseItem::ToolSearchCall { .. } => "tool_search_call",
    }
}

fn item_status(item: &CodexResponseItem) -> Option<CodexItemStatus> {
    match item {
        CodexResponseItem::CustomToolCall { status, .. }
        | CodexResponseItem::ToolSearchCall { status, .. } => *status,
        CodexResponseItem::Message { .. }
        | CodexResponseItem::Reasoning { .. }
        | CodexResponseItem::FunctionCall { .. } => None,
    }
}

fn validate_paired_item(
    added: &CodexResponseItem,
    done: &CodexResponseItem,
) -> Result<(), FetchAdaptorError> {
    if item_kind_name(added) != item_kind_name(done)
        || added
            .id()
            .zip(done.id())
            .is_some_and(|(left, right)| left != right)
        || added
            .call_id()
            .zip(done.call_id())
            .is_some_and(|(left, right)| left != right)
    {
        return Err(failed("output_item.done contradicted output_item.added"));
    }
    match (added, done) {
        (
            CodexResponseItem::FunctionCall {
                name: added_name, ..
            },
            CodexResponseItem::FunctionCall {
                name: done_name, ..
            },
        )
        | (
            CodexResponseItem::CustomToolCall {
                name: added_name, ..
            },
            CodexResponseItem::CustomToolCall {
                name: done_name, ..
            },
        ) if added_name == done_name => Ok(()),
        (
            CodexResponseItem::ToolSearchCall {
                arguments: added, ..
            },
            CodexResponseItem::ToolSearchCall {
                arguments: done, ..
            },
        ) if added == done => Ok(()),
        (CodexResponseItem::Message { .. }, CodexResponseItem::Message { .. })
        | (CodexResponseItem::Reasoning { .. }, CodexResponseItem::Reasoning { .. }) => Ok(()),
        _ => Err(failed("output_item.done contradicted output_item.added")),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecyclePayload {
    response: LifecycleResponse,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleResponse {
    #[serde(default, deserialize_with = "present_optional_json")]
    id: Option<JsonValue>,
    #[serde(default, deserialize_with = "present_optional_json")]
    object: Option<JsonValue>,
    #[serde(default, deserialize_with = "present_optional_json")]
    created_at: Option<JsonValue>,
    #[serde(default, deserialize_with = "present_optional_json")]
    status: Option<JsonValue>,
    #[serde(default, deserialize_with = "present_optional_json")]
    model: Option<JsonValue>,
    #[serde(default, rename = "output")]
    _output: Option<IgnoredAny>,
    #[serde(default, rename = "usage")]
    _usage: Option<IgnoredAny>,
    #[serde(default, rename = "background")]
    _background: Option<IgnoredAny>,
    #[serde(default, rename = "completed_at")]
    _completed_at: Option<IgnoredAny>,
    #[serde(default, rename = "error")]
    _error: Option<IgnoredAny>,
    #[serde(default, rename = "frequency_penalty")]
    _frequency_penalty: Option<IgnoredAny>,
    #[serde(default, rename = "incomplete_details")]
    _incomplete_details: Option<IgnoredAny>,
    #[serde(default, rename = "instructions")]
    _instructions: Option<IgnoredAny>,
    #[serde(default, rename = "max_output_tokens")]
    _max_output_tokens: Option<IgnoredAny>,
    #[serde(default, rename = "parallel_tool_calls")]
    _parallel_tool_calls: Option<IgnoredAny>,
    #[serde(default, rename = "presence_penalty")]
    _presence_penalty: Option<IgnoredAny>,
    #[serde(default, rename = "previous_response_id")]
    _previous_response_id: Option<IgnoredAny>,
    #[serde(default, rename = "prompt_cache_key")]
    _prompt_cache_key: Option<IgnoredAny>,
    #[serde(default, rename = "prompt_cache_retention")]
    _prompt_cache_retention: Option<IgnoredAny>,
    #[serde(default, rename = "reasoning")]
    _reasoning: Option<IgnoredAny>,
    #[serde(default, rename = "safety_identifier")]
    _safety_identifier: Option<IgnoredAny>,
    #[serde(default, rename = "service_tier")]
    _service_tier: Option<IgnoredAny>,
    #[serde(default, rename = "store")]
    _store: Option<IgnoredAny>,
    #[serde(default, rename = "temperature")]
    _temperature: Option<IgnoredAny>,
    #[serde(default, rename = "text")]
    _text: Option<IgnoredAny>,
    #[serde(default, rename = "tool_choice")]
    _tool_choice: Option<IgnoredAny>,
    #[serde(default, rename = "tools")]
    _tools: Option<IgnoredAny>,
    #[serde(default, rename = "top_logprobs")]
    _top_logprobs: Option<IgnoredAny>,
    #[serde(default, rename = "top_p")]
    _top_p: Option<IgnoredAny>,
    #[serde(default, rename = "truncation")]
    _truncation: Option<IgnoredAny>,
    #[serde(default, rename = "user")]
    _user: Option<IgnoredAny>,
    #[serde(default, rename = "metadata")]
    _metadata: Option<IgnoredAny>,
}

struct LifecycleIdentity {
    id: Option<String>,
    model: Option<String>,
}

impl LifecycleResponse {
    fn validate(
        self,
        expected_status: &str,
        expected_id: Option<&str>,
    ) -> Result<LifecycleIdentity, FetchAdaptorError> {
        validate_lifecycle_identity(
            self.id,
            self.object,
            self.created_at,
            self.status,
            self.model,
            expected_status,
            expected_id,
        )
    }
}

fn validate_lifecycle_identity(
    id: Option<JsonValue>,
    object: Option<JsonValue>,
    created_at: Option<JsonValue>,
    status: Option<JsonValue>,
    model: Option<JsonValue>,
    expected_status: &str,
    expected_id: Option<&str>,
) -> Result<LifecycleIdentity, FetchAdaptorError> {
    let id = optional_present_string(id, "response.id")?;
    if let Some(id) = &id {
        nonempty_bounded("response.id", id, MAX_NAME_BYTES)?;
    }
    if expected_id.is_some() && id.as_deref().is_some_and(|id| Some(id) != expected_id) {
        return Err(failed("Codex response id changed"));
    }
    if let Some(object) = optional_present_string(object, "response.object")?
        && object != "response"
    {
        return Err(failed("present response.object must equal response"));
    }
    if let Some(status) = optional_present_string(status, "response.status")?
        && status != expected_status
    {
        return Err(failed("present response.status is contradictory"));
    }
    if created_at.is_some_and(|value| value.as_i64().is_none() && value.as_u64().is_none()) {
        return Err(failed("present response.created_at must be an integer"));
    }
    let model = optional_present_string(model, "response.model")?;
    if let Some(model) = &model {
        nonempty_bounded("response.model", model, MAX_MODEL_BYTES)?;
    }
    Ok(LifecycleIdentity { id, model })
}

fn optional_present_string(
    value: Option<JsonValue>,
    field: &str,
) -> Result<Option<String>, FetchAdaptorError> {
    value
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| failed(format!("present {field} must be a string")))
        })
        .transpose()
}

fn present_optional_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Some)
}

fn present_optional_json<'de, D>(deserializer: D) -> Result<Option<JsonValue>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = JsonValue::deserialize(deserializer)?;
    if value.is_null() {
        Err(serde::de::Error::custom("present field must not be null"))
    } else {
        Ok(Some(value))
    }
}

fn reject_safety_buffering<'de, D>(deserializer: D) -> Result<(), D::Error>
where
    D: serde::Deserializer<'de>,
{
    let _ = JsonValue::deserialize(deserializer)?;
    Err(serde::de::Error::custom(
        "sealed Codex v0 rejects safety_buffering",
    ))
}

fn reject_namespace<'de, D>(deserializer: D) -> Result<(), D::Error>
where
    D: serde::Deserializer<'de>,
{
    let _ = JsonValue::deserialize(deserializer)?;
    Err(serde::de::Error::custom(
        "sealed Codex v0 rejects namespace",
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ItemPayload {
    #[serde(default)]
    output_index: Option<u64>,
    item: CodexResponseWireItem,
    #[serde(
        default,
        rename = "safety_buffering",
        deserialize_with = "reject_safety_buffering"
    )]
    _safety_buffering: (),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TextDeltaPayload {
    delta: String,
    item_id: String,
    output_index: u64,
    content_index: u64,
    #[serde(default, rename = "logprobs")]
    _logprobs: Option<Vec<JsonValue>>,
    #[serde(default, rename = "obfuscation")]
    _obfuscation: Option<IgnoredAny>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TextDonePayload {
    text: String,
    item_id: String,
    output_index: u64,
    content_index: u64,
    #[serde(default, rename = "logprobs")]
    _logprobs: Option<Vec<JsonValue>>,
    #[serde(default, rename = "obfuscation")]
    _obfuscation: Option<IgnoredAny>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolDeltaPayload {
    item_id: String,
    #[serde(default, deserialize_with = "present_optional_string")]
    call_id: Option<String>,
    delta: String,
    #[serde(default, rename = "output_index")]
    _output_index: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolDonePayload {
    item_id: String,
    #[serde(default, deserialize_with = "present_optional_string")]
    call_id: Option<String>,
    #[serde(default, rename = "input")]
    value: Option<String>,
    #[serde(default, rename = "output_index")]
    _output_index: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FunctionDeltaPayload {
    item_id: String,
    delta: String,
    #[serde(default, rename = "output_index")]
    _output_index: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FunctionDonePayload {
    item_id: String,
    arguments: String,
    #[serde(default, deserialize_with = "present_optional_string")]
    name: Option<String>,
    #[serde(default, rename = "output_index")]
    _output_index: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReasoningPartPayload {
    summary_index: u64,
    #[serde(default, deserialize_with = "present_optional_string")]
    item_id: Option<String>,
    #[serde(default)]
    output_index: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReasoningDeltaPayload {
    delta: String,
    item_id: String,
    output_index: u64,
    #[serde(alias = "summary_index", alias = "content_index")]
    index: u64,
    #[serde(default, rename = "obfuscation")]
    _obfuscation: Option<IgnoredAny>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReasoningDonePayload {
    item_id: String,
    text: String,
    summary_index: u64,
    #[serde(default)]
    output_index: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContentPartPayload {
    item_id: String,
    #[serde(default)]
    output_index: Option<u64>,
    content_index: u64,
    part: ContentPartWire,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContentPartWire {
    #[serde(rename = "type")]
    _kind: ContentPartKind,
    text: String,
    #[serde(default, rename = "annotations")]
    _annotations: Option<IgnoredAny>,
    #[serde(default, rename = "logprobs")]
    _logprobs: Option<IgnoredAny>,
}

#[derive(Debug, Deserialize)]
enum ContentPartKind {
    #[serde(rename = "output_text")]
    OutputText,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletedPayload {
    response: CompletedResponse,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletedResponse {
    id: JsonValue,
    usage: JsonValue,
    #[serde(default)]
    usage_metadata: Option<JsonValue>,
    #[serde(default)]
    end_turn: Option<JsonValue>,
    #[serde(default, deserialize_with = "present_optional_json")]
    object: Option<JsonValue>,
    #[serde(default, deserialize_with = "present_optional_json")]
    created_at: Option<JsonValue>,
    #[serde(default, deserialize_with = "present_optional_json")]
    status: Option<JsonValue>,
    #[serde(default, deserialize_with = "present_optional_json")]
    model: Option<JsonValue>,
    #[serde(default, rename = "output")]
    _output: Option<IgnoredAny>,
    #[serde(default, rename = "background")]
    _background: Option<IgnoredAny>,
    #[serde(default, rename = "completed_at")]
    _completed_at: Option<IgnoredAny>,
    #[serde(default, rename = "error")]
    _error: Option<IgnoredAny>,
    #[serde(default, rename = "frequency_penalty")]
    _frequency_penalty: Option<IgnoredAny>,
    #[serde(default, rename = "incomplete_details")]
    _incomplete_details: Option<IgnoredAny>,
    #[serde(default, rename = "instructions")]
    _instructions: Option<IgnoredAny>,
    #[serde(default, rename = "max_output_tokens")]
    _max_output_tokens: Option<IgnoredAny>,
    #[serde(default, rename = "parallel_tool_calls")]
    _parallel_tool_calls: Option<IgnoredAny>,
    #[serde(default, rename = "presence_penalty")]
    _presence_penalty: Option<IgnoredAny>,
    #[serde(default, rename = "previous_response_id")]
    _previous_response_id: Option<IgnoredAny>,
    #[serde(default, rename = "prompt_cache_key")]
    _prompt_cache_key: Option<IgnoredAny>,
    #[serde(default, rename = "prompt_cache_retention")]
    _prompt_cache_retention: Option<IgnoredAny>,
    #[serde(default, rename = "reasoning")]
    _reasoning: Option<IgnoredAny>,
    #[serde(default, rename = "safety_identifier")]
    _safety_identifier: Option<IgnoredAny>,
    #[serde(default, rename = "service_tier")]
    _service_tier: Option<IgnoredAny>,
    #[serde(default, rename = "store")]
    _store: Option<IgnoredAny>,
    #[serde(default, rename = "temperature")]
    _temperature: Option<IgnoredAny>,
    #[serde(default, rename = "text")]
    _text: Option<IgnoredAny>,
    #[serde(default, rename = "tool_choice")]
    _tool_choice: Option<IgnoredAny>,
    #[serde(default, rename = "tools")]
    _tools: Option<IgnoredAny>,
    #[serde(default, rename = "top_logprobs")]
    _top_logprobs: Option<IgnoredAny>,
    #[serde(default, rename = "top_p")]
    _top_p: Option<IgnoredAny>,
    #[serde(default, rename = "truncation")]
    _truncation: Option<IgnoredAny>,
    #[serde(default, rename = "user")]
    _user: Option<IgnoredAny>,
    #[serde(default, rename = "metadata")]
    _metadata: Option<IgnoredAny>,
}

impl CompletedResponse {
    fn into_completed(
        self,
        expected_id: Option<&str>,
    ) -> Result<(CodexCompleted, Option<String>), FetchAdaptorError> {
        let id = self
            .id
            .as_str()
            .ok_or_else(|| failed("completed response.id must be a non-empty string"))?
            .to_string();
        nonempty_bounded("completed response.id", &id, MAX_NAME_BYTES)?;
        if expected_id.is_some_and(|expected| expected != id) {
            return Err(failed(
                "completed response.id contradicted response.created",
            ));
        }
        let identity = validate_lifecycle_identity(
            Some(JsonValue::String(id.clone())),
            self.object,
            self.created_at,
            self.status,
            self.model,
            "completed",
            Some(&id),
        )?;
        let usage = parse_codex_usage(self.usage)?;
        let usage_metadata = self.usage_metadata.map(parse_usage_metadata).transpose()?;
        let end_turn = self
            .end_turn
            .map(|value| {
                value
                    .as_bool()
                    .ok_or_else(|| failed("completed end_turn must be boolean"))
            })
            .transpose()?;
        Ok((
            CodexCompleted {
                response_id: id,
                server_model: None,
                usage,
                usage_metadata,
                end_turn,
            },
            identity.model,
        ))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UsageWire {
    input_tokens: u64,
    #[serde(default)]
    input_tokens_details: Option<InputTokenDetailsWire>,
    output_tokens: u64,
    #[serde(default)]
    output_tokens_details: Option<OutputTokenDetailsWire>,
    total_tokens: u64,
    #[serde(default)]
    codex_rollout_budget_units: Option<JsonNumber>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InputTokenDetailsWire {
    #[serde(default)]
    cached_tokens: u64,
    #[serde(default)]
    cache_write_tokens: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputTokenDetailsWire {
    #[serde(default)]
    reasoning_tokens: u64,
}

fn parse_codex_usage(value: JsonValue) -> Result<CodexUsage, FetchAdaptorError> {
    let usage: UsageWire = serde_json::from_value(value)
        .map_err(|error| failed(format!("malformed Codex terminal usage: {error}")))?;
    if usage.input_tokens.checked_add(usage.output_tokens) != Some(usage.total_tokens) {
        return Err(failed(
            "Codex usage total_tokens contradicted input + output",
        ));
    }
    if let Some(number) = &usage.codex_rollout_budget_units {
        let encoded = number.to_string();
        if encoded.len() > 64 || encoded.starts_with('-') {
            return Err(failed(
                "codex_rollout_budget_units must be a bounded non-negative number",
            ));
        }
    }
    Ok(CodexUsage {
        input_tokens: usage.input_tokens,
        input_tokens_details: usage
            .input_tokens_details
            .map(|details| CodexInputTokenDetails {
                cached_tokens: details.cached_tokens,
                cache_write_tokens: details.cache_write_tokens,
            }),
        output_tokens: usage.output_tokens,
        output_tokens_details: usage
            .output_tokens_details
            .map(|details| CodexOutputTokenDetails {
                reasoning_tokens: details.reasoning_tokens,
            }),
        total_tokens: usage.total_tokens,
        codex_rollout_budget_units: usage.codex_rollout_budget_units,
    })
}

fn parse_usage_metadata(value: JsonValue) -> Result<CodexUsageMetadata, FetchAdaptorError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Wire {
        amount: Option<String>,
    }
    let wire: Wire = serde_json::from_value(value)
        .map_err(|error| failed(format!("malformed Codex usage_metadata: {error}")))?;
    if wire
        .amount
        .as_ref()
        .is_some_and(|amount| amount.len() > 256)
    {
        return Err(failed("Codex usage_metadata amount is too large"));
    }
    Ok(CodexUsageMetadata {
        amount: wire.amount,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FailurePayload {
    response: FailureResponse,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FailureResponse {
    error: FailureDetail,
    #[serde(default, rename = "id")]
    _id: Option<JsonValue>,
    #[serde(default, rename = "object")]
    _object: Option<JsonValue>,
    #[serde(default, rename = "created_at")]
    _created_at: Option<JsonValue>,
    #[serde(default, rename = "status")]
    _status: Option<JsonValue>,
    #[serde(default, rename = "usage")]
    _usage: Option<JsonValue>,
    #[serde(default, rename = "metadata")]
    _metadata: Option<JsonValue>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FailureDetail {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default, rename = "type")]
    _kind: Option<String>,
    #[serde(default, rename = "param")]
    _param: Option<String>,
}

fn provider_failure(payload: FailurePayload) -> FetchAdaptorError {
    let code = payload.response.error.code.as_deref().unwrap_or("unknown");
    let message = payload.response.error.message.as_deref().unwrap_or("");
    failed(format!(
        "Codex upstream failed ({}){}",
        sanitize_excerpt(code, 64),
        failure_suffix(message)
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorPayload {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default, rename = "param")]
    _param: Option<String>,
}

fn provider_error(payload: ErrorPayload) -> FetchAdaptorError {
    let code = payload.code.as_deref().unwrap_or("unknown");
    let message = payload.message.as_deref().unwrap_or("");
    failed(format!(
        "Codex upstream error ({}){}",
        sanitize_excerpt(code, 64),
        failure_suffix(message)
    ))
}

fn failure_suffix(message: &str) -> String {
    let excerpt = sanitize_excerpt(message, MAX_FAILURE_EXCERPT_CHARS);
    if excerpt.is_empty() {
        String::new()
    } else {
        format!(": {excerpt}")
    }
}

fn sanitize_excerpt(value: &str, maximum_chars: usize) -> String {
    value
        .chars()
        .take(maximum_chars)
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn payload_error(error: impl std::fmt::Display) -> FetchAdaptorError {
    failed(format!("Codex fetch payload encoding failed: {error}"))
}

fn failed(message: impl Into<String>) -> FetchAdaptorError {
    FetchAdaptorError::failed(message.into())
}

#[cfg(test)]
mod tests;
