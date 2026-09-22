use super::SchemaError;
use anyhow::{Context, Result, ensure};
use hellas_adaptors::ToolSpec;
use std::collections::HashMap;

/// Offered function schemas, shared by rendering and incremental decoding.
pub struct ToolDirectory {
    specs: Vec<ToolSpec>,
    validators: HashMap<String, jsonschema::Validator>,
}

impl ToolDirectory {
    pub fn new(specs: Vec<ToolSpec>) -> Result<Self> {
        let mut validators = HashMap::new();
        for spec in &specs {
            ensure!(!spec.name.is_empty(), "tool name must not be empty");
            ensure!(
                !validators.contains_key(&spec.name),
                "duplicate tool name: {}",
                spec.name
            );
            let validator = jsonschema::validator_for(&spec.parameters)
                .with_context(|| format!("invalid schema for tool {}", spec.name))?;
            validators.insert(spec.name.clone(), validator);
        }
        Ok(Self { specs, validators })
    }

    pub fn lookup(&self, name: &str) -> Option<(&ToolSpec, &jsonschema::Validator)> {
        Some((
            self.specs.iter().find(|spec| spec.name == name)?,
            self.validators.get(name)?,
        ))
    }

    pub fn validate_args(&self, name: &str, args: &serde_json::Value) -> Vec<SchemaError> {
        self.validators
            .get(name)
            .map(|validator| {
                validator
                    .iter_errors(args)
                    .map(|error| SchemaError {
                        path: error.instance_path.to_string(),
                        message: error.to_string(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}
