use super::*;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

type Hook = Arc<dyn Fn(&[u8]) -> futures::future::BoxFuture<'static, ()> + Send + Sync>;
static APPEND_HOOKS: OnceLock<Mutex<BTreeMap<PathBuf, Hook>>> = OnceLock::new();

/// A directory-scoped delay at the durable append boundary. Other tests' journals
/// are unaffected. Dropping this guard removes the hook, including on panic.
pub struct AppendHook(PathBuf);
impl AppendHook {
    /// Run after the real SQL commit, before the caller may acknowledge it.
    /// The hook receives the actual frame so tests can select transitions rather
    /// than depending on how many intervening clock writes happen to coalesce.
    pub fn new(
        directory: &Path,
        hook: impl Fn(&[u8]) -> futures::future::BoxFuture<'static, ()> + Send + Sync + 'static,
    ) -> Self {
        let path = directory.to_path_buf();
        let previous = APPEND_HOOKS
            .get_or_init(Default::default)
            .lock()
            .unwrap()
            .insert(path.clone(), Arc::new(hook));
        assert!(previous.is_none(), "journal hook already installed");
        Self(path)
    }
}
impl Drop for AppendHook {
    fn drop(&mut self) {
        APPEND_HOOKS.get().unwrap().lock().unwrap().remove(&self.0);
    }
}
pub(super) async fn after_append(path: &Path, payload: &[u8]) {
    let hook = APPEND_HOOKS.get().and_then(|hooks| {
        hooks
            .lock()
            .unwrap()
            .iter()
            .find(|(directory, _)| path.starts_with(directory))
            .map(|(_, hook)| hook.clone())
    });
    if let Some(hook) = hook {
        hook(payload).await;
    }
}

impl Journal {
    /// Pause the next statement on SQLite's worker until the sender is dropped.
    /// Tokio's blocking pool does not control sqlx's dedicated SQLite thread.
    pub async fn pause_next_statement(
        &mut self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let mut entered = Some(entered);
        self.connection
            .as_mut()
            .unwrap()
            .lock_handle()
            .await
            .unwrap()
            .set_progress_handler(1, move || {
                if let Some(entered) = entered.take() {
                    let _ = entered.send(());
                    let _ = blocked.recv();
                }
                true
            });
        (started, release)
    }

    /// Release the paused statement and remove its one-shot test hook.
    pub async fn resume_statements(&mut self, release: std::sync::mpsc::Sender<()>) {
        drop(release);
        self.connection
            .as_mut()
            .unwrap()
            .lock_handle()
            .await
            .unwrap()
            .remove_progress_handler();
    }

    /// Makes the database itself refuse every `operation` on `table`,
    /// the way a full disk or an I/O error would.
    pub async fn refuse(&mut self, operation: &str, table: &str) {
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "CREATE TEMP TRIGGER refuse_{operation}_{table} BEFORE {operation} ON {table} \
             BEGIN SELECT RAISE(ABORT, 'refused'); END"
        )))
        .execute(self.connection.as_mut().unwrap())
        .await
        .unwrap();
    }
}
