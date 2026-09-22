use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use hellas_rpc::{Application, StaticSlice};

use super::*;

const PROGRAM: &[u8] = b"fn model() { return; }";
const WEIGHTS: &[u8] = b"resident weights";

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/hellas-executor-content-environment")
            .join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&path).expect("create scratch directory");
        Self(path)
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, bytes).expect("write fixture content");
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    scratch: Scratch,
    store: ContentStore,
    program: ContentRef,
    weights: ContentRef,
    weights_path: PathBuf,
    environment: CausalLmEnvironment,
}

impl Fixture {
    fn new() -> Self {
        let scratch = Scratch::new();
        let program_path = scratch.write("program.catena", PROGRAM);
        let weights_path = scratch.write("weights.safetensors", WEIGHTS);
        let store = ContentStore::new();
        let program = store.index(&program_path).expect("index program");
        let weights = store.index(&weights_path).expect("index weights");
        let program = ContentRef::new(ContentId::from_bytes(*program.id.as_bytes()), program.len);
        let weights = ContentRef::new(ContentId::from_bytes(*weights.id.as_bytes()), weights.len);
        let environment = environment(program, weights);
        let environment_path = scratch.write("environment.cbor", &environment.canonical_bytes());
        let indexed_environment = store.index(&environment_path).expect("index environment");
        assert_eq!(
            ContentId::from_bytes(*indexed_environment.id.as_bytes()),
            environment.content_id()
        );
        Self {
            scratch,
            store,
            program,
            weights,
            weights_path,
            environment,
        }
    }

    fn manifest_bytes(&self) -> Vec<u8> {
        self.environment.manifest().canonical_bytes()
    }

    fn environment_bytes(&self) -> Vec<u8> {
        self.environment.canonical_bytes()
    }

    fn bind(&self) -> Result<CausalLmEnvironmentSource, CausalLmEnvironmentSourceError> {
        CausalLmEnvironmentSource::from_manifest_bytes(&self.store, &self.manifest_bytes())
    }
}

fn environment(program: ContentRef, weights: ContentRef) -> CausalLmEnvironment {
    CausalLmEnvironment::new(
        program,
        "model",
        vec![weights],
        vec![StaticSlice::new(0, 0, weights.bytes())],
        vec![4],
        32,
        64,
        hellas_rpc::CausalLmGenerationSchedule {
            fixed_capacity: 64,
            prefill_chunk_tokens: 64,
        },
    )
    .expect("valid fixture environment")
}

#[test]
fn binds_and_reopens_exact_local_files() {
    let fixture = Fixture::new();
    let bound = fixture.bind().expect("bind environment");

    assert_eq!(
        bound.manifest_id(),
        fixture.environment.manifest().content_id()
    );
    assert_eq!(bound.environment(), &fixture.environment);

    let (program, static_objects) = bound.open_verified_files().expect("reopen content");
    assert_eq!(program.id(), fixture.program.id().digest());
    assert_eq!(program.len(), fixture.program.bytes());
    assert_eq!(static_objects.len(), 1);
    assert_eq!(static_objects[0].id(), fixture.weights.id().digest());
    assert_eq!(static_objects[0].len(), fixture.weights.bytes());

    let bytes = read_verified_bytes(
        static_objects
            .into_iter()
            .next()
            .expect("weights descriptor"),
    )
    .expect("read weights descriptor");
    assert_eq!(bytes, WEIGHTS);
}

#[test]
fn bound_source_reports_the_environment_metadata_pinned_by_its_arc() {
    let fixture = Fixture::new();
    let bound = fixture.bind().expect("bind environment");

    assert_eq!(
        bound.retained_heap_bytes(),
        bound.environment().retained_heap_bytes()
    );
    assert!(
        bound.retained_heap_bytes().unwrap()
            >= std::mem::size_of::<hellas_rpc::CausalLmEnvironment>()
    );
}

#[test]
fn bounded_verified_read_rejects_growth_and_truncation() {
    let grown = Fixture::new();
    let bound = grown.bind().expect("bind grown fixture");
    let descriptor = bound
        .open_verified_static_object(0)
        .expect("open weights before growth");
    OpenOptions::new()
        .append(true)
        .open(&grown.weights_path)
        .expect("open weights for append")
        .write_all(b"!")
        .expect("append weights");
    let error = read_verified_bytes(descriptor).expect_err("growth must be rejected");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);

    let truncated = Fixture::new();
    let bound = truncated.bind().expect("bind truncated fixture");
    let descriptor = bound
        .open_verified_static_object(0)
        .expect("open weights before truncation");
    OpenOptions::new()
        .write(true)
        .open(&truncated.weights_path)
        .expect("open weights for truncation")
        .set_len((WEIGHTS.len() - 1) as u64)
        .expect("truncate weights");
    let error = read_verified_bytes(descriptor).expect_err("truncation must be rejected");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn requires_the_exact_application_pair_and_environment_root() {
    let fixture = Fixture::new();
    let root = fixture.environment.content_id();
    let unsupported = ProgramManifest::new(
        Application::new(CATENA_GPU_EVALUATOR, format!("{CAUSAL_LM_ADAPTOR} ")).unwrap(),
        root,
    );
    assert!(matches!(
        CausalLmEnvironmentSource::from_manifest_bytes(
            &fixture.store,
            &unsupported.canonical_bytes(),
        ),
        Err(CausalLmEnvironmentSourceError::UnsupportedApplication { .. })
    ));

    let wrong_root = ProgramManifest::new(
        fixture.environment.manifest().application().clone(),
        ContentId::from_bytes([9; 32]),
    );
    assert!(matches!(
        CausalLmEnvironmentSource::from_manifest_bytes(
            &fixture.store,
            &wrong_root.canonical_bytes(),
        ),
        Err(CausalLmEnvironmentSourceError::MissingContent { id }) if id == wrong_root.root()
    ));
}

#[test]
fn rejects_noncanonical_outer_and_evaluator_metadata() {
    let fixture = Fixture::new();
    let canonical_manifest = fixture.manifest_bytes();
    let mut noncanonical_manifest = vec![0x98, 0x03];
    noncanonical_manifest.extend_from_slice(&canonical_manifest[1..]);
    assert!(matches!(
        CausalLmEnvironmentSource::from_manifest_bytes(&fixture.store, &noncanonical_manifest),
        Err(CausalLmEnvironmentSourceError::InvalidManifest(_))
    ));

    let canonical_environment = fixture.environment_bytes();
    let mut noncanonical_environment = vec![0x98, 0x07];
    noncanonical_environment.extend_from_slice(&canonical_environment[1..]);
    let path = fixture
        .scratch
        .write("noncanonical-environment.cbor", &noncanonical_environment);
    let indexed = fixture
        .store
        .index(&path)
        .expect("index noncanonical environment");
    let manifest = ProgramManifest::new(
        fixture.environment.manifest().application().clone(),
        ContentId::from_bytes(*indexed.id.as_bytes()),
    );
    assert!(matches!(
        CausalLmEnvironmentSource::from_manifest_bytes(&fixture.store, &manifest.canonical_bytes(),),
        Err(CausalLmEnvironmentSourceError::InvalidEnvironment(_))
    ));
}

#[test]
fn requires_every_object_and_its_exact_declared_length() {
    let fixture = Fixture::new();
    let program_only_store = ContentStore::new();
    let program_path = fixture.scratch.0.join("program.catena");
    program_only_store
        .index(&program_path)
        .expect("index only program");
    let environment_path = fixture.scratch.0.join("environment.cbor");
    program_only_store
        .index(&environment_path)
        .expect("index environment metadata");
    assert!(matches!(
        CausalLmEnvironmentSource::from_manifest_bytes(
            &program_only_store,
            &fixture.manifest_bytes(),
        ),
        Err(CausalLmEnvironmentSourceError::MissingContent { id }) if id == fixture.weights.id()
    ));

    let wrong_length = environment(
        ContentRef::new(fixture.program.id(), fixture.program.bytes() + 1),
        fixture.weights,
    );
    let path = fixture.scratch.write(
        "wrong-length-environment.cbor",
        &wrong_length.canonical_bytes(),
    );
    fixture
        .store
        .index(&path)
        .expect("index wrong-length environment");
    assert!(matches!(
        CausalLmEnvironmentSource::from_manifest_bytes(
            &fixture.store,
            &wrong_length.manifest().canonical_bytes(),
        ),
        Err(CausalLmEnvironmentSourceError::InvalidLocalContent { id })
            if id == fixture.program.id()
    ));
}

#[test]
fn reopening_refuses_a_replaced_cache_path() {
    let fixture = Fixture::new();
    let bound = fixture.bind().expect("bind environment");
    let replacement = fixture.scratch.write("replacement", b"hostile weights!");
    assert_eq!(
        std::fs::metadata(&replacement).unwrap().len(),
        WEIGHTS.len() as u64
    );
    std::fs::rename(replacement, &fixture.weights_path).expect("replace weights path");

    assert!(matches!(
        bound.open_verified_files(),
        Err(CausalLmEnvironmentSourceError::MissingContent { id }) if id == fixture.weights.id()
    ));
}
