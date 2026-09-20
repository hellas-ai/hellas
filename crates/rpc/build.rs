//! Build script for `hellas-rpc`.
//!
//! Pipeline:
//!
//! 1. Parse all `.proto` files at the workspace `proto/` root with `protox`
//!    (pure-Rust, no `protoc` dependency).
//! 2. Walk the resulting `FileDescriptorSet` to build an in-memory schema
//!    table, extract the service surface, and derive per-method 32-bit IDs
//!    via `hellas_wire::MethodSchema::method_id()`.
//! 3. Hand the same `FileDescriptorSet` to `prost-build::Config::compile_fds`
//!    to emit the prost message types (messages only — services are
//!    rendered by this script).
//! 4. Render the typed service / method markers and client/server code
//!    speaking the `hellas_wire` API as `quote!` token streams, validated
//!    with `syn` and formatted with `prettyplease`.
//!
//! All output goes to `OUT_DIR`. The library `include!()`s the per-package
//! files from `src/pb/`.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use hellas_wire::schema::{
    FieldSchema, MessageSchema, MethodSchema, PrimKind, ServiceSchema, TypeSchema,
};
use proc_macro2::{Ident, Literal, TokenStream};
use prost_types::field_descriptor_proto::{Label, Type as FieldType};
use prost_types::{DescriptorProto, EnumDescriptorProto, FieldDescriptorProto, FileDescriptorSet};
use quote::{format_ident, quote};

fn main() {
    emit_git_rev();
    regenerate();
}

fn emit_git_rev() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let rev = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(&manifest_dir)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    if let Some(rev) = rev {
        println!("cargo:rustc-env=GIT_REV={rev}");
    } else if let Ok(rev) = std::env::var("GIT_REV") {
        println!("cargo:rustc-env=GIT_REV={rev}");
    }
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs");
}

// =============================================================================
// Pipeline
// =============================================================================

fn regenerate() {
    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo"),
    );
    let proto_root = manifest_dir.join("../../proto");
    let mut protos = Vec::new();
    collect_proto_files(&proto_root.join("hellas"), &mut protos);
    protos.sort();

    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto.display());
    }

    // 1. Parse with protox.
    let fds: FileDescriptorSet = protox::compile(&protos, [&proto_root])
        .expect("protox failed to parse hellas .proto files");

    // 2. Build a schema table so we can resolve `.package.Name` references
    //    into `MessageSchema` (or `EnumRef`) and derive method IDs.
    let schema_index = SchemaIndex::build(&fds);

    let services = collect_services(&fds);

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is set by cargo"));

    // 3. Run prost-build for the message types only; the service surface
    //    is rendered by this script, so no prost service_generator is
    //    installed and prost skips `service` blocks entirely.
    let mut config = prost_build::Config::new();
    // NB: prost's `bytes(["."])` (decode `bytes` fields as `bytes::Bytes`
    // for zero-copy) is disabled because current call sites produce `Vec<u8>`.
    config.out_dir(&out_dir);
    config.enum_attribute(
        "hellas.v1.WorkEvent.kind",
        "#[allow(clippy::large_enum_variant)]",
    );
    config
        .compile_fds(fds)
        .expect("prost-build failed to emit message types");

    // 4. Render and write the service / marker / client / server modules,
    //    keyed off the collected `RpcService` list and the schema index.
    let body = render_generated(&services, &schema_index);
    let out_path = out_dir.join("hellas_rpc_services.rs");
    fs::write(&out_path, body).expect("failed to write hellas_rpc_services.rs");
}

fn collect_proto_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_proto_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "proto") {
            out.push(path);
        }
    }
}

// =============================================================================
// Service collection
// =============================================================================

/// The service surface the renderer needs, straight from the descriptors.
struct RpcService {
    /// `hellas.courtesy.v1`.
    package: String,
    /// `Courtesy`.
    proto_name: String,
    methods: Vec<RpcMethod>,
}

struct RpcMethod {
    /// `QuoteTokens` (as it appears in the .proto).
    proto_name: String,
    /// Fully-qualified proto request type with a leading dot, e.g.
    /// `.hellas.courtesy.v1.QuoteTokensRequest` — matching `SchemaIndex` keys.
    request_proto_type: String,
    /// Fully-qualified proto response type with a leading dot.
    response_proto_type: String,
    request_streaming: bool,
    response_streaming: bool,
}

/// Extract every `service` block from the `FileDescriptorSet`, in file
/// order. The same FDS drives prost message generation, so there is no
/// second source of truth to keep aligned.
fn collect_services(fds: &FileDescriptorSet) -> Vec<RpcService> {
    let mut services = Vec::new();
    for file in &fds.file {
        let package = file.package();
        for svc in &file.service {
            let methods = svc
                .method
                .iter()
                .map(|m| {
                    // The hellas wire protocol has no client-streaming unary
                    // shape. Reject at codegen time instead of emitting stubs
                    // that fail every call at runtime.
                    if m.client_streaming() && !m.server_streaming() {
                        panic!(
                            "{package}.{}/{} is client-streaming unary, which hellas-rpc \
                             does not support; make the response `stream` (bidi) instead",
                            svc.name(),
                            m.name()
                        );
                    }
                    RpcMethod {
                        proto_name: m.name().to_string(),
                        request_proto_type: m.input_type().to_string(),
                        response_proto_type: m.output_type().to_string(),
                        request_streaming: m.client_streaming(),
                        response_streaming: m.server_streaming(),
                    }
                })
                .collect();
            services.push(RpcService {
                package: package.to_string(),
                proto_name: svc.name().to_string(),
                methods,
            });
        }
    }
    services
}

// =============================================================================
// Schema index — walks the FileDescriptorSet to resolve message refs.
// =============================================================================

/// Owns the in-memory representation of every proto message and enum the
/// build script sees. The keys are fully-qualified names with a leading
/// dot (matching descriptor `input_type` / `output_type` references).
struct SchemaIndex {
    messages: HashMap<String, IndexedMessage>,
    enums: HashMap<String, IndexedEnum>,
}

#[derive(Clone, Debug)]
struct IndexedMessage {
    /// Short proto name (`QuoteTokensRequest`).
    short_name: String,
    fields: Vec<IndexedField>,
}

#[derive(Clone, Debug)]
struct IndexedField {
    number: u32,
    label: Label,
    ty: IndexedFieldType,
}

#[derive(Clone, Debug)]
enum IndexedFieldType {
    Primitive(PrimKind),
    Message(String), // FQN with leading dot
    Enum(String),    // FQN with leading dot
}

#[derive(Clone, Debug)]
struct IndexedEnum {
    short_name: String,
    variants: Vec<i32>,
}

impl SchemaIndex {
    fn build(fds: &FileDescriptorSet) -> Self {
        let mut messages = HashMap::new();
        let mut enums = HashMap::new();
        for file in &fds.file {
            let package = file.package.as_deref().unwrap_or("");
            for msg in &file.message_type {
                Self::index_message(package, "", msg, &mut messages, &mut enums);
            }
            for en in &file.enum_type {
                Self::index_enum(package, "", en, &mut enums);
            }
        }
        Self { messages, enums }
    }

    fn index_message(
        package: &str,
        parent_path: &str,
        msg: &DescriptorProto,
        messages: &mut HashMap<String, IndexedMessage>,
        enums: &mut HashMap<String, IndexedEnum>,
    ) {
        let short = msg.name.as_deref().unwrap_or_default();
        let fqn = compose_fqn(package, parent_path, short);
        let nested_path = if parent_path.is_empty() {
            short.to_string()
        } else {
            format!("{parent_path}.{short}")
        };
        let fields = msg
            .field
            .iter()
            .map(|f: &FieldDescriptorProto| IndexedField {
                number: f.number.unwrap_or_default() as u32,
                label: f
                    .label
                    .and_then(|v| Label::try_from(v).ok())
                    .unwrap_or(Label::Optional),
                ty: classify_field(f),
            })
            .collect();
        messages.insert(
            fqn.clone(),
            IndexedMessage {
                short_name: short.to_string(),
                fields,
            },
        );
        for nested in &msg.nested_type {
            Self::index_message(package, &nested_path, nested, messages, enums);
        }
        for nested_en in &msg.enum_type {
            Self::index_enum(package, &nested_path, nested_en, enums);
        }
    }

    fn index_enum(
        package: &str,
        parent_path: &str,
        en: &EnumDescriptorProto,
        enums: &mut HashMap<String, IndexedEnum>,
    ) {
        let short = en.name.as_deref().unwrap_or_default();
        let fqn = compose_fqn(package, parent_path, short);
        let variants = en
            .value
            .iter()
            .map(|v| v.number.unwrap_or_default())
            .collect();
        enums.insert(
            fqn,
            IndexedEnum {
                short_name: short.to_string(),
                variants,
            },
        );
    }

    /// Resolve a fully-qualified type reference (e.g. `.hellas.v1.Ticket`)
    /// into a `MessageSchema` recursively, owning all referenced strings.
    fn message_schema(&self, fqn: &str) -> MessageSchema {
        let msg = self
            .messages
            .get(fqn)
            .unwrap_or_else(|| panic!("missing message in schema index: {fqn}"));
        let mut visiting: Vec<String> = Vec::new();
        self.message_schema_inner(fqn, msg, &mut visiting)
    }

    fn message_schema_inner(
        &self,
        fqn: &str,
        msg: &IndexedMessage,
        visiting: &mut Vec<String>,
    ) -> MessageSchema {
        // Method-id derivation requires acyclic service-facing message trees.
        // Panic at the cycle boundary instead of recursing until stack overflow.
        if visiting.contains(&fqn.to_string()) {
            panic!("cyclic message schema at {fqn}; method-id derivation requires acyclic trees");
        }
        visiting.push(fqn.to_string());
        let fields = msg
            .fields
            .iter()
            .map(|f| FieldSchema {
                number: f.number,
                ty: self.field_schema(&f.ty, f.label, visiting),
            })
            .collect();
        visiting.pop();
        MessageSchema {
            name: msg.short_name.clone(),
            fields,
        }
    }

    /// Proto `map<k, v>` fields never reach here as `TypeSchema::Map`:
    /// the descriptor represents them as a repeated synthetic MapEntry
    /// message, which is also their actual wire form. Likewise proto3
    /// `optional` does not change the wire form, so no field produces
    /// `TypeSchema::Optional`.
    fn field_schema(
        &self,
        ty: &IndexedFieldType,
        label: Label,
        visiting: &mut Vec<String>,
    ) -> TypeSchema {
        let base = match ty {
            IndexedFieldType::Primitive(p) => TypeSchema::Primitive(*p),
            IndexedFieldType::Message(fqn) => {
                let msg = self
                    .messages
                    .get(fqn)
                    .unwrap_or_else(|| panic!("missing message in schema index: {fqn}"));
                TypeSchema::Message(self.message_schema_inner(fqn, msg, visiting))
            }
            IndexedFieldType::Enum(fqn) => {
                let en = self
                    .enums
                    .get(fqn)
                    .unwrap_or_else(|| panic!("missing enum in schema index: {fqn}"));
                TypeSchema::EnumRef {
                    name: en.short_name.clone(),
                    variants: en.variants.clone(),
                }
            }
        };
        match label {
            Label::Repeated => TypeSchema::Repeated(Box::new(base)),
            _ => base,
        }
    }
}

fn compose_fqn(package: &str, parent_path: &str, short: &str) -> String {
    let mut out = String::with_capacity(package.len() + parent_path.len() + short.len() + 3);
    out.push('.');
    if !package.is_empty() {
        out.push_str(package);
        out.push('.');
    }
    if !parent_path.is_empty() {
        out.push_str(parent_path);
        out.push('.');
    }
    out.push_str(short);
    out
}

fn classify_field(f: &FieldDescriptorProto) -> IndexedFieldType {
    let ty = f
        .r#type
        .and_then(|v| FieldType::try_from(v).ok())
        .expect("field has a type");
    match ty {
        FieldType::Double => IndexedFieldType::Primitive(PrimKind::Double),
        FieldType::Float => IndexedFieldType::Primitive(PrimKind::Float),
        FieldType::Int64 => IndexedFieldType::Primitive(PrimKind::I64),
        FieldType::Uint64 => IndexedFieldType::Primitive(PrimKind::U64),
        FieldType::Int32 => IndexedFieldType::Primitive(PrimKind::I32),
        FieldType::Fixed64 => IndexedFieldType::Primitive(PrimKind::Fixed64),
        FieldType::Fixed32 => IndexedFieldType::Primitive(PrimKind::Fixed32),
        FieldType::Bool => IndexedFieldType::Primitive(PrimKind::Bool),
        FieldType::String => IndexedFieldType::Primitive(PrimKind::String),
        FieldType::Bytes => IndexedFieldType::Primitive(PrimKind::Bytes),
        FieldType::Uint32 => IndexedFieldType::Primitive(PrimKind::U32),
        FieldType::Sfixed32 => IndexedFieldType::Primitive(PrimKind::Sfixed32),
        FieldType::Sfixed64 => IndexedFieldType::Primitive(PrimKind::Sfixed64),
        FieldType::Sint32 => IndexedFieldType::Primitive(PrimKind::Sint32),
        FieldType::Sint64 => IndexedFieldType::Primitive(PrimKind::Sint64),
        FieldType::Enum => {
            IndexedFieldType::Enum(f.type_name.clone().expect("enum field carries a type_name"))
        }
        FieldType::Message | FieldType::Group => IndexedFieldType::Message(
            f.type_name
                .clone()
                .expect("message field carries a type_name"),
        ),
    }
}

// =============================================================================
// Render plan — everything the token templates need, computed once.
// =============================================================================

/// Per-method render inputs.
struct MethodPlan {
    /// Marker type ident (`QuoteTokens`).
    marker: Ident,
    /// Client / handler method ident (`quote_prompt`).
    fn_name: Ident,
    /// Method name as spelled in the .proto.
    name: String,
    method_id: u32,
    /// Absolute Rust path of the prost request type.
    request: syn::Path,
    /// Absolute Rust path of the prost response type.
    response: syn::Path,
    shape: Shape,
    /// Whether the handler is handed the connection's own context.
    connection_bound: bool,
    /// Whether this is the bounded general transaction submission method.
    bounded_submit_tx: bool,
    /// Whether this is the separately bounded work-response method.
    bounded_work_response: bool,
}

/// The RPC shapes the hellas wire protocol supports. Client-streaming
/// unary is rejected in `collect_services`.
#[derive(Clone, Copy, PartialEq)]
enum Shape {
    Unary,
    ServerStreaming,
    BidiStreaming,
}

/// Per-service render inputs.
struct ServicePlan {
    feature: &'static str,
    module: Ident,
    /// Service marker ident (`Courtesy`).
    service: Ident,
    fqn: String,
    alpn: String,
    service_id: u32,
    handler: Ident,
    client: Ident,
    server: Ident,
    methods: Vec<MethodPlan>,
}

fn plan_service(service: &RpcService, index: &SchemaIndex) -> ServicePlan {
    let fqn = format!("{}.{}", service.package, service.proto_name);

    // One schema resolution per method feeds both the METHOD_ID constants
    // and the ServiceSchema digest behind SERVICE_ID.
    let schemas: Vec<MethodSchema> = service
        .methods
        .iter()
        .map(|m| build_method_schema(&fqn, m, index))
        .collect();
    let method_ids: Vec<u32> = schemas.iter().map(MethodSchema::method_id).collect();
    let service_id = ServiceSchema {
        fqn: fqn.clone(),
        methods: schemas,
    }
    .service_id();

    let methods = service
        .methods
        .iter()
        .zip(method_ids)
        .map(|(m, method_id)| {
            let shape = match (m.request_streaming, m.response_streaming) {
                (false, false) => Shape::Unary,
                (false, true) => Shape::ServerStreaming,
                (true, true) => Shape::BidiStreaming,
                (true, false) => {
                    unreachable!("client-streaming unary methods are rejected at collection time")
                }
            };
            MethodPlan {
                marker: format_ident!("{}", m.proto_name),
                fn_name: format_ident!("{}", to_snake_case(&m.proto_name)),
                name: m.proto_name.clone(),
                method_id,
                request: rust_path(&m.request_proto_type),
                response: rust_path(&m.response_proto_type),
                shape,
                connection_bound: connection_bound(&service.package),
                bounded_submit_tx: service.package == "hellas.chain.v1"
                    && service.proto_name == "LightClient"
                    && m.proto_name == "SubmitTx",
                bounded_work_response: service.package == "hellas.chain.v1"
                    && service.proto_name == "LightClient"
                    && m.proto_name == "SubmitWorkResponse",
            }
        })
        .collect();

    let alpn = format!("/{fqn}/2.0");
    ServicePlan {
        feature: feature_for_package(&service.package),
        module: format_ident!("{}", to_snake_case(&service.proto_name)),
        service: format_ident!("{}", service.proto_name),
        alpn,
        service_id,
        handler: format_ident!("{}Handler", service.proto_name),
        client: format_ident!("{}ClientImpl", service.proto_name),
        server: format_ident!("{}Server", service.proto_name),
        methods,
        fqn,
    }
}

/// Whether a service's handlers are handed the transport's own context.
///
/// One package needs it, and it is not a convenience. `hellas.work.v1`
/// releases paid plaintext and debits a client's credit for it, so its
/// caller must prove on *this* connection that it is the client the
/// channel names — and the value that proves it is the connection's TLS
/// exporter, which no request field may carry because a request field
/// is exactly what an attacker chooses.
///
/// Every other package authenticates what it is asked, not who is
/// asking, and a context those handlers ignored would be a parameter
/// that looked like a check.
fn connection_bound(package: &str) -> bool {
    package == "hellas.work.v1"
}

fn build_method_schema(service_fqn: &str, method: &RpcMethod, index: &SchemaIndex) -> MethodSchema {
    let request_msg = index.message_schema(&method.request_proto_type);
    let response_msg = index.message_schema(&method.response_proto_type);
    MethodSchema {
        // FQN matches the generated service directory convention.
        fqn: format!("{service_fqn}/{}", method.proto_name),
        request: TypeSchema::Message(request_msg),
        response: TypeSchema::Message(response_msg),
        request_streaming: method.request_streaming,
        response_streaming: method.response_streaming,
    }
}

// =============================================================================
// Code generation
// =============================================================================

const GENERATED_HEADER: &str = "// @generated by `hellas-rpc` build.rs. Do not edit by hand.\n\
     //\n\
     // Service / method markers, typed client traits, and server\n\
     // dispatchers. The wrapping module sets allow-lints.\n\n";

fn render_generated(services: &[RpcService], index: &SchemaIndex) -> String {
    let plans: Vec<ServicePlan> = services.iter().map(|s| plan_service(s, index)).collect();

    // Inventory: every service regardless of feature gating, so
    // transport-layer code iterates these without re-declaring names.
    let entries = plans.iter().map(|p| {
        let name = &p.fqn;
        let alpn = &p.alpn;
        quote! { KnownService { name: #name, alpn: #alpn } }
    });
    let blocks = plans.iter().map(render_service_block);

    let tokens = quote! {
        /// A protocol-level service entry — its FQN and the wire ALPN.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct KnownService {
            pub name: &'static str,
            pub alpn: &'static str,
        }

        /// Catalogue of every service this crate knows about.
        pub const KNOWN_SERVICES: &[KnownService] = &[#(#entries),*];

        #(#blocks)*
    };

    // parse2 validates that the emitted tokens are well-formed Rust items
    // (a template bug fails here, not at some rustc error pointing into
    // OUT_DIR) and feeds prettyplease so the emitted file stays readable.
    let file: syn::File = syn::parse2(tokens).expect("generated service code parses as Rust");
    format!("{GENERATED_HEADER}{}", prettyplease::unparse(&file))
}

fn render_service_block(plan: &ServicePlan) -> TokenStream {
    let ServicePlan {
        feature,
        module,
        service,
        fqn,
        alpn,
        handler,
        client,
        server,
        ..
    } = plan;
    let service_id = hex_u32(plan.service_id);

    let markers = plan.methods.iter().map(|m| {
        let MethodPlan {
            marker,
            name,
            request,
            response,
            ..
        } = m;
        let method_id = hex_u32(m.method_id);
        let request_streaming = m.shape == Shape::BidiStreaming;
        let response_streaming = m.shape != Shape::Unary;
        quote! {
            pub struct #marker;

            impl MethodMarker for #marker {
                type Service = #service;
                type Request = #request;
                type Response = #response;
                const NAME: &'static str = #name;
                const METHOD_ID: u32 = #method_id;
                const REQUEST_STREAMING: bool = #request_streaming;
                const RESPONSE_STREAMING: bool = #response_streaming;
            }
        }
    });

    let handler_methods = plan.methods.iter().map(handler_signature);
    let client_methods = plan.methods.iter().map(client_method);
    let dispatch_arms = plan.methods.iter().map(dispatch_arm);

    let handler_doc = doc_lines(&[
        "Server-side handler trait. Concrete servers implement".to_string(),
        format!("this; the generated `{server}` dispatcher routes inbound"),
        "frames to the matching handler.".to_string(),
    ]);
    let server_doc = doc_lines(&[
        format!("Wraps a `{handler}` and routes inbound streams to it"),
        "by `method_id`. For unary methods the dispatch decodes the".to_string(),
        "request, invokes the handler, encodes the response, and".to_string(),
        "emits a terminal trailer. Streaming methods are routed".to_string(),
        "through the matching stream helper.".to_string(),
    ]);
    let server_definition = if plan.fqn == "hellas.chain.v1.LightClient" {
        quote! {
            pub struct #server<H>(
                pub H,
                pub ::std::sync::Arc<crate::call::WorkResponseRoute>,
                pub ::std::sync::Arc<crate::call::GeneralSubmitRoute>,
            );
        }
    } else {
        quote! {
            pub struct #server<H>(pub H);
        }
    };

    quote! {
        #[cfg(feature = #feature)]
        pub mod #module {
            use ::hellas_wire::{MethodMarker, ServiceMarker};

            pub struct #service;

            impl ServiceMarker for #service {
                const NAME: &'static str = #fqn;
                const ALPN: &'static str = #alpn;
                const SERVICE_ID: u32 = #service_id;
            }

            #(#markers)*

            #handler_doc
            pub trait #handler: Send + Sync + 'static {
                #(#handler_methods)*
            }

            /// Generic client over any `StreamTransport`. Wraps a transport
            /// handle by reference; clone to share. Uses the prost-aware
            /// helpers in `crate::call`.
            #[derive(Clone, Debug)]
            pub struct #client<T> {
                transport: T,
            }

            impl<T> #client<T>
            where
                T: ::hellas_wire::StreamTransport + Sync,
                T::Error: ::std::error::Error + Send + Sync + 'static,
                T::Stream: 'static,
            {
                pub fn new(transport: T) -> Self {
                    Self { transport }
                }

                #(#client_methods)*
            }

            #server_doc
            #server_definition

            impl<T, H> ::hellas_wire::Dispatcher<T> for #server<H>
            where
                T: ::hellas_wire::StreamTransport + Send + Sync,
                <T::Stream as ::hellas_wire::Stream>::RecvHalf: 'static,
                <T::Stream as ::hellas_wire::Stream>::SendHalf: 'static,
                H: #handler,
            {
                type Error = ::hellas_wire::TransportError;

                async fn dispatch(
                    &self,
                    inbound: ::hellas_wire::Inbound<T::Stream>,
                ) -> ::core::result::Result<(), Self::Error> {
                    match inbound.method_id {
                        #(#dispatch_arms)*
                        other => Err(::hellas_wire::TransportError::Protocol(
                            format!("unknown method_id 0x{:08x}", other),
                        )),
                    }
                }
            }
        }
    }
}

fn handler_signature(m: &MethodPlan) -> TokenStream {
    let MethodPlan {
        fn_name,
        request,
        response,
        ..
    } = m;
    let request_ty = match m.shape {
        Shape::BidiStreaming => boxed_stream(request),
        _ => quote! { #request },
    };
    let context = if m.connection_bound || (m.bounded_submit_tx && m.shape == Shape::Unary) {
        quote! { , context: ::hellas_wire::TransportContext }
    } else {
        quote! {}
    };
    // Unary handlers may return the bare response or `WithTrailer<R>`
    // (which carries response-side metadata like provenance); streaming
    // handlers return their response stream.
    let output = match m.shape {
        Shape::Unary => quote! { impl Into<crate::call::WithTrailer<#response>> + Send },
        _ => boxed_stream(response),
    };
    quote! {
        fn #fn_name(
            &self,
            request: #request_ty
            #context,
        ) -> impl ::core::future::Future<
            Output = ::core::result::Result<#output, ::hellas_wire::WireStatus>,
        > + Send;
    }
}

fn client_method(m: &MethodPlan) -> TokenStream {
    let MethodPlan {
        marker,
        fn_name,
        request,
        response,
        ..
    } = m;
    let (params, output, body) = match m.shape {
        Shape::Unary => (
            quote! { &self, request: #request },
            quote! { #response },
            quote! {
                crate::call::unary::<T, #marker>(
                    &self.transport, request, ::hellas_wire::Metadata::new()).await
            },
        ),
        Shape::ServerStreaming => (
            quote! { &self, request: #request },
            quote! { crate::call::StreamingCall<#response> },
            quote! {
                crate::call::server_streaming::<T, #marker>(
                    &self.transport, request, ::hellas_wire::Metadata::new()).await
            },
        ),
        // Bidi takes no request parameter: the request stream is driven
        // through the returned call handle.
        Shape::BidiStreaming => (
            quote! { &self },
            quote! { crate::call::BidiStreamingCall<#request, #response> },
            quote! {
                crate::call::bidi_streaming::<T, #marker>(
                    &self.transport, ::hellas_wire::Metadata::new()).await
            },
        ),
    };
    quote! {
        pub fn #fn_name(
            #params,
        ) -> impl ::core::future::Future<
            Output = ::core::result::Result<#output, ::hellas_wire::WireStatus>,
        > + Send {
            async move { #body }
        }
    }
}

fn dispatch_arm(m: &MethodPlan) -> TokenStream {
    let MethodPlan {
        marker, fn_name, ..
    } = m;
    if m.connection_bound && m.shape == Shape::Unary {
        return quote! {
            <#marker as ::hellas_wire::MethodMarker>::METHOD_ID => {
                crate::call::dispatch_unary_with_context::<T, #marker, _, _, _>(
                    inbound,
                    |req, context| {
                        let h = &self.0;
                        async move { h.#fn_name(req, context).await }
                    },
                )
                .await
            }
        };
    }
    if m.connection_bound && m.shape == Shape::ServerStreaming {
        return quote! {
            <#marker as ::hellas_wire::MethodMarker>::METHOD_ID => {
                let context = inbound.context.clone();
                crate::call::dispatch_server_streaming::<T, #marker, _, _, _>(inbound, |req| {
                    let h = &self.0;
                    async move { h.#fn_name(req, context).await }
                }).await
            }
        };
    }
    if m.bounded_submit_tx {
        assert!(m.shape == Shape::Unary, "raw request limits are unary-only");
        return quote! {
            <#marker as ::hellas_wire::MethodMarker>::METHOD_ID => {
                crate::call::dispatch_general_submit_bounded::<T, #marker, _, _, _>(
                    inbound,
                    &self.2,
                    crate::MAX_SUBMIT_TX_PROTO_BYTES,
                    |req, context| {
                        let h = &self.0;
                        async move { h.#fn_name(req, context).await }
                    },
                )
                .await
            }
        };
    }
    if m.bounded_work_response {
        assert!(m.shape == Shape::Unary, "raw request limits are unary-only");
        return quote! {
            <#marker as ::hellas_wire::MethodMarker>::METHOD_ID => {
                crate::call::dispatch_work_response_bounded::<T, #marker, _, _, _>(
                    inbound,
                    &self.1,
                    crate::MAX_SUBMIT_WORK_RESPONSE_PROTO_BYTES,
                    |req| {
                        let h = &self.0;
                        async move { h.#fn_name(req).await }
                    },
                )
                .await
            }
        };
    }
    let helper = match m.shape {
        Shape::Unary => quote! { dispatch_unary },
        Shape::ServerStreaming => quote! { dispatch_server_streaming },
        Shape::BidiStreaming => quote! { dispatch_bidi_streaming },
    };
    let req_expr = match m.shape {
        Shape::BidiStreaming => quote! { ::std::boxed::Box::pin(req) },
        _ => quote! { req },
    };
    quote! {
        <#marker as ::hellas_wire::MethodMarker>::METHOD_ID => {
            crate::call::#helper::<T, #marker, _, _, _>(inbound, |req| {
                let h = &self.0;
                async move { h.#fn_name(#req_expr).await }
            })
            .await
        }
    }
}

/// Boxed request/response stream type as it appears in handler signatures.
fn boxed_stream(item: &syn::Path) -> TokenStream {
    quote! {
        ::std::pin::Pin<Box<dyn ::futures_core::Stream<
            Item = ::core::result::Result<#item, ::hellas_wire::WireStatus>,
        > + Send>>
    }
}

/// One `#[doc = "..."]` attribute per line; prettyplease renders them as
/// `///` doc comments.
fn doc_lines(lines: &[String]) -> TokenStream {
    let lines = lines.iter().map(|l| format!(" {l}"));
    quote! { #(#[doc = #lines])* }
}

/// Hex-formatted u32 literal so IDs stay grep-able in the emitted file.
fn hex_u32(v: u32) -> Literal {
    Literal::from_str(&format!("0x{v:08x}")).expect("hex u32 literal")
}

fn rust_path(proto_fqn: &str) -> syn::Path {
    let path = proto_fqn_to_rust_path(proto_fqn);
    syn::parse_str(&path).unwrap_or_else(|e| panic!("invalid Rust path `{path}`: {e}"))
}

fn feature_for_package(package: &str) -> &'static str {
    match package {
        "hellas.v1" => "execute",
        "hellas.courtesy.v1" => "courtesy",
        "hellas.fetch.v1" => "fetch",
        "hellas.swarm.v1" => "swarm",
        "hellas.evaluate.v1" => "evaluate",
        "hellas.chain.v1" => "chain",
        "hellas.work.v1" => "work",
        "hellas.host.v1" => "host-control",
        _ => panic!("no rpc-crate feature defined for protobuf package {package}"),
    }
}

fn to_snake_case(input: &str) -> String {
    let mut output = String::new();
    let mut prev_lower_or_digit = false;
    for ch in input.chars() {
        if ch.is_ascii_uppercase() {
            if prev_lower_or_digit {
                output.push('_');
            }
            output.push(ch.to_ascii_lowercase());
            prev_lower_or_digit = false;
        } else {
            output.push(ch);
            prev_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        }
    }
    output
}

/// Translate a fully-qualified proto type (e.g. `.hellas.swarm.v1.GetNodeInfoResponse`)
/// into an absolute Rust path under `crate::pb::hellas::...`, usable from
/// the centralized `pb::services` module.
///
/// Nested message types (`.pkg.Parent.Child`) come through as Parent.child
/// in proto naming — translated as `parent::Child` in Rust by prost's own
/// scheme. We don't currently have nested message types in any hellas
/// .proto, so a flat translation is enough; if that ever changes, extend
/// the lowercase rule below.
fn proto_fqn_to_rust_path(proto_fqn: &str) -> String {
    // Strip leading dot.
    let stripped = proto_fqn.strip_prefix('.').unwrap_or(proto_fqn);
    // Split into segments. The last segment is the type name (PascalCase);
    // every preceding segment is a module (snake_case in the .proto, which
    // already lowercase).
    let mut segments: Vec<&str> = stripped.split('.').collect();
    let type_name = segments.pop().expect("proto fqn has at least one segment");
    let mut path = String::from("crate::pb");
    for seg in segments {
        path.push_str("::");
        path.push_str(seg);
    }
    path.push_str("::");
    path.push_str(type_name);
    path
}
