use std::error::Error as StdError;

use hellas_rpc::fetch::FetchProtocolError;
use hellas_wire::WireStatus;
use thiserror::Error;

pub type ClientResult<T> = Result<T, ClientError>;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("owner execution requires a grant; select a payment-funded Work channel")]
    OwnerGrantRequired,
    #[error("{0}")]
    Protocol(String),
    #[error("{context}: {source}")]
    Source {
        context: String,
        #[source]
        source: Box<dyn StdError + Send + Sync + 'static>,
    },
    #[error("{context}: {source}")]
    Wire {
        context: String,
        #[source]
        source: WireStatus,
    },
    #[error(transparent)]
    External(Box<dyn StdError + Send + Sync + 'static>),
    #[cfg(feature = "evaluate")]
    #[error("evaluate transcript verification failed: {source}")]
    EvaluateTranscript {
        #[source]
        source: hellas_rpc::evaluate::EvaluateProtocolError,
    },
    #[error("fetch stream envelope decode failed: {source}")]
    FetchStreamEnvelope {
        #[source]
        source: hellas_rpc::stream::StreamEnvelopeError,
    },
    #[error("fetch transcript verification failed: {source}")]
    FetchTranscript {
        #[source]
        source: FetchProtocolError,
    },
}

impl ClientError {
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol(message.into())
    }

    pub fn source(
        context: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self::Source {
            context: context.into(),
            source: Box::new(source),
        }
    }

    pub fn wire(context: impl Into<String>, source: WireStatus) -> Self {
        Self::Wire {
            context: context.into(),
            source,
        }
    }

    pub fn external(source: impl StdError + Send + Sync + 'static) -> Self {
        Self::External(Box::new(source))
    }
}

#[cfg(feature = "iroh")]
pub(crate) trait ClientContext<T> {
    fn client_context(self, context: impl Into<String>) -> ClientResult<T>;
}

#[cfg(feature = "iroh")]
impl<T, E> ClientContext<T> for Result<T, E>
where
    E: StdError + Send + Sync + 'static,
{
    fn client_context(self, context: impl Into<String>) -> ClientResult<T> {
        self.map_err(|source| ClientError::source(context, source))
    }
}
