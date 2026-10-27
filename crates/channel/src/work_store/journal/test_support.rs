use super::*;

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
