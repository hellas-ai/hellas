//! A server without paid configuration cannot recover a previously paid upper.
use hellas_auth::Digest;
use hellas_rpc::ContentRef;
use hellas_store::content::*;

const CANARY: &[u8] = b"paid private input before its journal pin";
const CRASH_UPPER: &str = "HELLAS_TEST_CRASH_UPPER";

#[tokio::test]
async fn no_paid_serve_refuses_a_work_owned_upper_before_any_cleanup() {
    if let Some(root) = std::env::var_os(CRASH_UPPER) {
        let store = DiskStore::open(
            hellas_private::StoreLocation::for_test(std::path::Path::new(&root)),
            vec![],
            IndexMode::Resume,
            None,
            Reservations::ram(32 << 20),
            false,
        )
        .await
        .unwrap();
        store.finish_recovery().await.unwrap();
        let scope = store
            .open_work(
                JobId {
                    channel: Digest::hash(b"paid channel"),
                    id: Digest::hash(b"paid job"),
                },
                vec![ContentRef::for_bytes(CANARY)],
                CANARY.len() as u64,
            )
            .await
            .unwrap();
        let mut upload = store
            .upload(&scope, ContentRef::for_bytes(CANARY), None)
            .await
            .unwrap();
        upload
            .declare(&hellas_xet::chunk(CANARY), true)
            .await
            .unwrap();
        upload.accept_chunk(CANARY).await.unwrap();
        store.close().await;
        // Exit without dropping the unpinned work scope or private file backing.
        std::process::exit(0);
    }
    let root = tempfile::tempdir().unwrap();
    let upper = root.path().join("upper");
    let child = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "no_paid_serve_refuses_a_work_owned_upper_before_any_cleanup",
            "--nocapture",
        ])
        .env(CRASH_UPPER, &upper)
        .kill_on_drop(true)
        .output()
        .await
        .unwrap();
    assert!(
        child.status.success(),
        "{}",
        String::from_utf8_lossy(&child.stderr)
    );
    let files = hellas_channel::test_support::all_files(&upper);
    assert!(
        files
            .iter()
            .any(|path| std::fs::read(path).unwrap() == CANARY)
    );
    let before: Vec<_> = files
        .iter()
        .filter(|path| {
            !path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("content.sqlite")
        })
        .map(|path| (path.clone(), std::fs::read(path).unwrap()))
        .collect();
    let config = root.path().join("content.toml");
    std::fs::write(
        &config,
        format!("[content]\nupper = {:?}\n", upper.to_str().unwrap()),
    )
    .unwrap();
    let output = tokio::time::timeout(
        hellas_channel::test_support::HANG_GUARD,
        tokio::process::Command::new(env!("CARGO_BIN_EXE_hellas"))
            .arg("--home")
            .arg(root.path())
            .args(["serve", "--no-discovery", "--port", "0", "--content-config"])
            .arg(config)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("serve failed to refuse")
    .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(
            "this store is owned by a node with paid work; run the command against the daemon"
        ),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(hellas_channel::test_support::all_files(&upper), files);
    for (path, bytes) in before {
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
}
