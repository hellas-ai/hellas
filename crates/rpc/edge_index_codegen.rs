//! Generate the EdgeIndex Rust/JSON contract from its one protobuf schema.
use prost_types::{
    FileDescriptorSet,
    field_descriptor_proto::{Label, Type},
};
use std::path::Path;

pub fn configure(config: &mut prost_build::Config, fds: &mut FileDescriptorSet, out: &Path) {
    let file = fds
        .file
        .iter_mut()
        .find(|f| f.name() == "hellas/chain/v1/edge_index.proto")
        .expect("EdgeIndex schema");
    let mut aliases = String::new();
    for message in &mut file.message_type {
        let name = message.name().to_owned();
        let path = format!(".hellas.chain.v1.{name}");
        let short = name
            .strip_prefix("EdgeIndex")
            .expect("EdgeIndex message prefix");
        aliases.push_str(&format!("pub use crate::pb::chain::{name} as {short};\n"));
        config.message_attribute(&path, "#[derive(::serde::Serialize, ::serde::Deserialize)]");
        let is_response = short.ends_with("Response");
        let has_oneof = message
            .oneof_decl
            .iter()
            .any(|o| !o.name().starts_with('_'));
        if !is_response && !has_oneof {
            config.message_attribute(&path, "#[serde(deny_unknown_fields)]");
        }
        // ProofBundle's existing public JSON routes use integers and byte arrays.
        // The explicit EdgeIndex mapping is attached at the containing proof field.
        if short == "ProofBundle" {
            continue;
        }
        for field in &mut message.field {
            let field_path = format!("{path}.{}", field.name());
            let explicit_optional = field.proto3_optional.unwrap_or(false);
            let oneof = field.oneof_index.is_some() && !explicit_optional;
            if oneof {
                continue;
            }
            // Proto3 spells required message members without `optional`; the previous
            // hand-written Rust contract already required these members. Preserve that
            // decoding behavior without repeating their field list or wire tags.
            // Service IDs are calculated from the original descriptor before this pass.
            if field.r#type() == Type::Message
                && field.label() != Label::Repeated
                && !explicit_optional
            {
                field.label = Some(Label::Required as i32);
            }
            if explicit_optional {
                config.field_attribute(
                    &field_path,
                    "#[serde(default, skip_serializing_if = \"Option::is_none\")]",
                );
            }
            let adapter = match field.r#type() {
                Type::Uint64 => Some("decimal_u64"),
                Type::Bytes => Some(match (field.name(), explicit_optional) {
                    ("maker" | "taker" | "owner" | "party", false) => "base58_address",
                    ("maker" | "taker" | "owner" | "party", true) => "optional_base58_address",
                    (_, false) => "base64_bytes",
                    (_, true) => "optional_base64_bytes",
                }),
                Type::Message if field.type_name().ends_with(".EdgeIndexProofBundle") => {
                    Some(if field.label() == Label::Repeated {
                        "proofs_json"
                    } else {
                        "proof_json"
                    })
                }
                _ => None,
            };
            if let Some(adapter) = adapter {
                config.field_attribute(
                    &field_path,
                    format!("#[serde(with = \"crate::edge_index::{adapter}\")]"),
                );
            }
            if is_response && field.name() == "envelope" {
                config.field_attribute(&field_path, "#[serde(flatten)]");
            }
        }
        for oneof in &message.oneof_decl {
            if oneof.name().starts_with('_') {
                continue;
            }
            let path = format!("{path}.{}", oneof.name());
            config.field_attribute(&path, "#[serde(flatten)]");
            let (tag, alias) = match short {
                "ObjectAnswer" => ("state", "ObjectState"),
                "PublicTerms" => ("kind", "TermsKind"),
                "LeaseAnswer" => ("state", "LeaseState"),
                "PendingAnswer" => ("state", "PendingState"),
                _ => panic!("unmapped EdgeIndex JSON oneof {short}"),
            };
            config.enum_attribute(&path, format!("#[derive(::serde::Serialize, ::serde::Deserialize)] #[serde(tag = \"{tag}\", rename_all = \"kebab-case\")]"));
            let module = super::to_snake_case(&name);
            let variant = if oneof.name() == "terms" {
                "Terms"
            } else {
                "Answer"
            };
            aliases.push_str(&format!(
                "pub use crate::pb::chain::{module}::{variant} as {alias};\n"
            ));
        }
    }
    std::fs::write(out.join("hellas_edge_index_aliases.rs"), aliases)
        .expect("write EdgeIndex aliases");
}

/// Prost's field-path matching also attaches oneof field attributes to its variants.
/// Serde flatten belongs only on the containing field. Remove it from generated enum
/// variants using the Rust AST; no message fields or wire definitions are synthesized here.
pub fn finish(out: &Path) {
    fn ensure_eq(attrs: &mut Vec<syn::Attribute>) {
        let has_eq = attrs
            .iter()
            .filter(|a| a.path().is_ident("derive"))
            .any(|a| {
                a.parse_args_with(
                    syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
                )
                .is_ok_and(|paths| paths.iter().any(|path| path.is_ident("Eq")))
            });
        if !has_eq {
            attrs.push(syn::parse_quote!(#[derive(Eq)]));
        }
    }
    fn visit(items: &mut [syn::Item], edge_index: bool) {
        for item in items {
            match item {
                syn::Item::Mod(module) => {
                    if let Some((_, items)) = &mut module.content {
                        visit(items, module.ident.to_string().starts_with("edge_index_"));
                    }
                }
                syn::Item::Struct(structure)
                    if structure.ident.to_string().starts_with("EdgeIndex") =>
                {
                    ensure_eq(&mut structure.attrs);
                }
                syn::Item::Enum(enumeration) if edge_index => {
                    ensure_eq(&mut enumeration.attrs);
                    for variant in &mut enumeration.variants {
                        variant.attrs.retain(|attr| {
                            !(attr.path().is_ident("serde")
                                && attr
                                    .parse_args::<syn::Ident>()
                                    .is_ok_and(|id| id == "flatten"))
                        });
                    }
                }
                _ => {}
            }
        }
    }
    let path = out.join("hellas.chain.v1.rs");
    let mut source =
        syn::parse_file(&std::fs::read_to_string(&path).expect("generated chain messages"))
            .expect("parse generated chain messages");
    visit(&mut source.items, false);
    std::fs::write(path, prettyplease::unparse(&source)).expect("write generated chain messages");
}
