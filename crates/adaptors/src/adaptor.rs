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
}

pub trait WireIngress: WireAdaptor {
    type IngressState;

    fn decode_response(
        &self,
        request: &Self::ParsedRequest,
        bytes: &[u8],
    ) -> AdaptorResult<ExecutionResult>;

    fn initial_ingress_state(&self, request: &Self::ParsedRequest) -> Self::IngressState;

    fn decode_stream_event(
        &self,
        request: &Self::ParsedRequest,
        state: &mut Self::IngressState,
        event: WireStreamEvent,
    ) -> AdaptorResult<Vec<OutputEvent>>;
}
