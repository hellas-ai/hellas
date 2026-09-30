use crate::fetch_projection::FetchRequestView;
use std::collections::BTreeSet;
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FetchRoute {
    pub service: String,
    pub method: String,
}

impl FetchRoute {
    pub fn new(service: impl Into<String>, method: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            method: method.into(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FetchRoutePolicy {
    pub allowed_models: Option<BTreeSet<String>>,
    pub max_output_units: Option<u64>,
}

impl FetchRoutePolicy {
    /// The policy admitting exactly what both `self` and `other` admit:
    /// model allowlists intersect when both are set (otherwise the one that
    /// is set applies), and output limits take the minimum.
    pub fn intersect(&self, other: &Self) -> Self {
        Self {
            allowed_models: match (&self.allowed_models, &other.allowed_models) {
                (Some(a), Some(b)) => Some(a.intersection(b).cloned().collect()),
                (Some(a), None) => Some(a.clone()),
                (None, b) => b.clone(),
            },
            max_output_units: match (self.max_output_units, other.max_output_units) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            },
        }
    }

    pub(crate) fn validate(&self, request: &FetchRequestView) -> Result<(), FetchAccessError> {
        if let Some(models) = &self.allowed_models {
            let Some(model) = &request.model else {
                return Err(FetchAccessError::Denied(
                    "fetch request model is required for this route".to_string(),
                ));
            };
            if !models.contains(model) {
                return Err(FetchAccessError::Denied(format!(
                    "fetch model {model} is not authorized for this route"
                )));
            }
        }
        if let Some(max_output_units) = self.max_output_units {
            let requested = request.max_output_units.ok_or_else(|| {
                FetchAccessError::Denied(
                    "fetch request must set max output units for this route".to_string(),
                )
            })?;
            if requested > max_output_units {
                return Err(FetchAccessError::Denied(format!(
                    "fetch request max output units {requested} exceed route limit {max_output_units}"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FetchAccessError {
    #[error("fetch route denied: {0}")]
    Denied(String),
}
