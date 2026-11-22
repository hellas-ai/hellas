//! d1 decisions: each question is one complete prompt whose final logits
//! score the answer options. Prompts and readout stay on the caller's side of
//! Compute; the provider only prefills token ids and returns logits.
use super::{ModelPackage, ModelRequest, ModelResponse};
use anyhow::{Result, bail};
pub use catena_models::systemone::InvalidRequest;
use catena_models::systemone::{Prepared, Request};
use serde_json::Value;

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

impl ModelPackage {
    /// Parse and expand a decision request body with the format embedded in
    /// the model. Failures caused by the body are [`InvalidRequest`]s.
    pub fn decision_request(&self, body: Value) -> Result<DecisionRequest> {
        let decisions = self.decisions()?;
        let request = Request::parse(body)?;
        if request.has_images() {
            return Err(InvalidRequest(
                "decision requests are text only: images and files are not supported".into(),
            )
            .into());
        }
        let prepared = decisions.prepare(&request)?;
        let prompts = prepared.iter().map(|p| p.tokens.clone()).collect();
        Ok(DecisionRequest {
            request,
            prepared,
            prompts,
        })
    }

    /// The response envelope, under the name `model`, for the logits a
    /// decision job returned.
    pub fn decision_response(
        &self,
        model: &str,
        request: &DecisionRequest,
        response: ModelResponse,
    ) -> Result<Value> {
        let ModelResponse::Logits(logits) = response else {
            bail!("expected decision logits");
        };
        self.decisions()?
            .respond(model, &request.request, &request.prepared, &logits)
    }
}

#[cfg(test)]
mod tests;
