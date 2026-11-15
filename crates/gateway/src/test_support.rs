use crate::{
    BackendInfo, Presentation, Route, WorkExecutionBackend,
    route::RouteExecution,
    routing::{Routing, Selection},
};
use std::sync::Arc;

pub fn backend(evaluator: Option<String>) -> Vec<BackendInfo> {
    vec![BackendInfo {
        instance: 1,
        id: "test".into(),
        evaluator,
        max_in_flight: 4,
        in_flight: 0,
        down: false,
        error: None,
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
    let packages = match &presentation {
        Presentation::Model { package, .. } => hellas_client::model::ModelPackage::open_many(
            package,
            work.backends()
                .into_iter()
                .filter_map(|backend| backend.evaluator),
            None,
        )
        .await
        .unwrap(),
        _ => Default::default(),
    };
    Arc::new(RouteExecution { work, packages })
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

pub(crate) use crate::test_server as server;
