use futures::Stream;
use hellas_executor::FetchProviderError;
use tracing::Span;

pub(crate) struct Request {
    pub span: Span,
}
impl Request {
    pub fn new(_: &reqwest::Url) -> Self {
        Self { span: Span::none() }
    }
    pub fn for_method(_: &reqwest::Url, _: &str) -> Self {
        Self { span: Span::none() }
    }
    pub async fn send(
        &self,
        request: reqwest::RequestBuilder,
    ) -> reqwest::Result<reqwest::Response> {
        request.send().await
    }
    pub fn status(&self, _: u16) {}
    pub fn fail(&mut self, _: &'static str) {}
    pub fn stream<S>(self, stream: S) -> S
    where
        S: Stream<Item = Result<Vec<u8>, FetchProviderError>> + Send + 'static,
    {
        stream
    }
}
