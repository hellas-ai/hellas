use crate::{
    BackendInfo, Presentation, Route, WorkExecutionBackend,
    route::RouteExecution,
    routing::{Routing, Selection},
};
use std::sync::Arc;

pub fn backend(evaluator: Option<String>) -> Vec<BackendInfo> {
    vec![BackendInfo {
        id: "test".into(),
        evaluator,
        max_in_flight: 4,
        in_flight: 0,
        down: false,
    }]
}
pub fn route(presentation: Presentation) -> Route {
    Route {
        backends: vec!["test".into()],
        presentation,
    }
}
pub fn selection(work: Arc<dyn WorkExecutionBackend>) -> Selection {
    let routing = Routing::new(
        vec![route(Presentation::Responses {
            service: "test".into(),
            method: "test".into(),
            models: vec![],
            overrides: Default::default(),
        })],
        work,
        Default::default(),
    )
    .unwrap();
    routing
        .select(
            crate::responses_fetch::PATH,
            "POST",
            Default::default(),
            None,
            crate::test_support::job(),
        )
        .unwrap()
        .1
}
pub async fn execution(
    work: Arc<dyn WorkExecutionBackend>,
    presentation: Presentation,
) -> Arc<RouteExecution> {
    RouteExecution::open(&route(presentation), work)
        .await
        .unwrap()
}

pub fn job() -> Arc<crate::jobs::Job> {
    Arc::new(crate::jobs::Jobs::default())
        .admit(&crate::jobs::Request {
            origin: crate::jobs::Origin::Local,
            method: "POST".into(),
            path: "/test".into(),
        })
        .unwrap()
}

pub(crate) mod server;
