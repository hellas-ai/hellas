//! Manual Strix check: `gateway --local-grant` serves a real Qwen3 GGUF from
//! this machine's own allowance, with no chain and no remote provider.
//!
//! ```sh
//! nix develop .#rocm -c env HELLAS_TEST_TEXT_MODEL=/path/Qwen3-0.6B-BF16.gguf \
//!   HELLAS_TEST_CONTENT_INDEX=/path/content-index.bin cargo test -p hellas-cli --test grant_http local_text -- --ignored --nocapture
//! ```
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a HIP device and HELLAS_TEST_TEXT_MODEL; run manually on Strix"]
async fn local_grant_serves_a_text_model_without_a_chain() {
    use hellas_rpc::protocol::invocation::Limits;
    let model =
        PathBuf::from(std::env::var("HELLAS_TEST_TEXT_MODEL").expect("HELLAS_TEST_TEXT_MODEL"));
    let mut node = super::local_compute::LocalCompute::start(
        &model,
        "--text-model",
        &model,
        Limits {
            max_upload_bytes: 64 << 20,
            max_output_bytes: 1 << 20,
            max_steps: 256,
            execution_timeout_ms: 600_000,
        },
        None,
        &[],
    )
    .await;
    let http = &node.http;
    let address = &node.address;
    let url = format!("http://{address}/v1/completions");
    let label = model.file_stem().unwrap().to_string_lossy().into_owned();
    for max_tokens in [1, 2, 8, 60, 256] {
        let response = post(
            http,
            &url,
            json!({"model": label, "prompt": "The capital of France is", "max_tokens": max_tokens}),
        )
        .await;
        let status = response.status();
        let body = response.text().await.unwrap();
        println!("max_tokens={max_tokens} status={status} body={body}");
        if !status.is_success() {
            println!("{}", std::fs::read_to_string(&node.gateway.log).unwrap());
        }
        assert_eq!(status, reqwest::StatusCode::OK, "{body}");
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        let completion_tokens = body["usage"]["completion_tokens"].as_u64().unwrap();
        assert!((1..=max_tokens).contains(&completion_tokens), "{body}");
        match body["choices"][0]["finish_reason"].as_str().unwrap() {
            "length" => assert_eq!(completion_tokens, max_tokens, "{body}"),
            "stop" => {}
            reason => panic!("unexpected finish reason {reason}: {body}"),
        }
    }
    node.gateway.stop().await;
}
