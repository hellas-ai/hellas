use crate::{
    AdaptorResult, ExecutionRequest, ExecutionResult, OutputEvent, Provenance, RawRequest,
    RenderContext, WireResponse, WireStreamEvent,
};

pub trait WireAdaptor {
    type ParsedRequest;
    type StreamState;

    fn parse(&self, raw: RawRequest) -> AdaptorResult<Self::ParsedRequest>;

    fn to_execution_request(
        &self,
        request: &Self::ParsedRequest,
    ) -> AdaptorResult<ExecutionRequest>;

    fn initial_state(
        &self,
        request: &Self::ParsedRequest,
        context: RenderContext,
    ) -> Self::StreamState;

    fn render_response(
        &self,
        request: &Self::ParsedRequest,
        result: ExecutionResult,
        context: RenderContext,
    ) -> AdaptorResult<WireResponse>;

    fn render_stream_start(
        &self,
        _request: &Self::ParsedRequest,
        _state: &mut Self::StreamState,
    ) -> AdaptorResult<Vec<WireStreamEvent>> {
        Ok(Vec::new())
    }

    fn render_stream_event(
        &self,
        request: &Self::ParsedRequest,
        state: &mut Self::StreamState,
        event: OutputEvent,
    ) -> AdaptorResult<Vec<WireStreamEvent>>;

    /// Record provenance for the job; events rendered after it carry it.
    /// The fields it names replace those recorded before.
    fn attest(&self, state: &mut Self::StreamState, provenance: Provenance);

    /// A refusal or failure with HTTP `status`, in this wire format. Streams
    /// carry the same body as their `error` event.
    fn render_error(&self, status: u16, message: String) -> WireResponse {
        crate::openai::render_error(status, message)
    }

    /// The code a stream's error event carries for a failure that would
    /// have had HTTP `status` before the stream began, if the format names
    /// one, so that a client classifies both alike.
    fn error_code(&self, _status: u16) -> Option<String> {
        None
    }
}
