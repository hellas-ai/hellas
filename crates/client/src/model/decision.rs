//! d1 decisions: each question is one complete prompt whose final logits
//! score the answer options. Prompts and readout stay on the caller's side of
//! Compute; the provider only prefills token ids and returns logits.
use super::{ModelPackage, ModelRequest, ModelResponse};
use anyhow::{Result, bail};
pub use catena_models::systemone::InvalidRequest;
use catena_models::systemone::{Decisions, Prepared, Request};
use serde_json::Value;
use std::path::Path;

/// The request format and readout embedded in a decision model's GGUF.
pub struct Decision {
    decisions: Decisions,
}

/// One validated request with a prompt per question.
pub struct DecisionRequest {
    request: Request,
    prepared: Vec<Prepared>,
    prompts: Vec<Vec<u64>>,
}

impl DecisionRequest {
    /// The model the request names, if any.
    pub fn model(&self) -> Option<&str> {
        self.request.model()
    }
    pub fn job(&self) -> ModelRequest<'_> {
        ModelRequest::Decision {
            prompts: &self.prompts,
        }
    }
}

impl Decision {
    /// Local file I/O only: a decision GGUF or its descriptor directory.
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            decisions: Decisions::read(&ModelPackage::gguf_path(path)?, usize::MAX)?,
        })
    }

    /// Parse and expand a request body. Failures caused by the body are
    /// [`InvalidRequest`]s.
    pub fn prepare(&self, body: Value) -> Result<DecisionRequest> {
        let request = Request::parse(body)?;
        if request.has_images() {
            return Err(InvalidRequest(
                "decision requests are text only: images and files are not supported".into(),
            )
            .into());
        }
        let prepared = self.decisions.prepare(&request)?;
        let prompts = prepared.iter().map(|p| p.tokens.clone()).collect();
        Ok(DecisionRequest {
            request,
            prepared,
            prompts,
        })
    }

    /// The response envelope for the logits a decision job returned.
    pub fn respond(
        &self,
        model: &str,
        request: &DecisionRequest,
        response: ModelResponse,
    ) -> Result<Value> {
        let ModelResponse::Logits(logits) = response else {
            bail!("expected decision logits");
        };
        self.decisions
            .respond(model, &request.request, &request.prepared, &logits)
    }
}

#[cfg(test)]
mod tests;
