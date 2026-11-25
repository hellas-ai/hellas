use super::*;

fn manifest(evaluator: &str, adaptor: &str, root: u8) -> ProgramManifest {
    ProgramManifest::new(
        Application::new(evaluator, adaptor).unwrap(),
        ContentId::from_bytes([root; 32]),
        None,
    )
}

fn raw_manifest(evaluator: &str, adaptor: &str) -> Vec<u8> {
    let mut encoder = DagCborEncoder::new();
    encoder.array(3);
    encoder.str(PROGRAM_MANIFEST_DOMAIN);
    encoder.array(2);
    encoder.str(evaluator);
    encoder.str(adaptor);
    encoder.bytes(&[0; 32]);
    encoder.into_bytes()
}

#[test]
fn application_validates_each_exact_utf8_component() {
    assert_eq!(
        Application::new("", "a"),
        Err(ApplicationError::EmptyEvaluator)
    );
    assert_eq!(
        Application::new("e", ""),
        Err(ApplicationError::EmptyAdaptor)
    );

    let boundary = "é".repeat(MAX_APPLICATION_ID_BYTES / 2);
    let application = Application::new(boundary.clone(), boundary.clone()).unwrap();
    assert_eq!(application.evaluator(), boundary);
    assert_eq!(application.adaptor(), boundary);
    let manifest = ProgramManifest::new(application, ContentId::from_bytes([0; 32]), None);
    assert!(manifest.canonical_bytes().len() <= MAX_PROGRAM_MANIFEST_BYTES);

    let unnormalized = Application::new(" evaluator ", "Adaptor+Build").unwrap();
    assert_eq!(unnormalized.evaluator(), " evaluator ");
    assert_eq!(unnormalized.adaptor(), "Adaptor+Build");

    assert_eq!(
        Application::new("e".repeat(MAX_APPLICATION_ID_BYTES + 1), "a"),
        Err(ApplicationError::EvaluatorTooLong {
            bytes: MAX_APPLICATION_ID_BYTES + 1,
            limit: MAX_APPLICATION_ID_BYTES,
        })
    );
    assert_eq!(
        Application::new("e", "é".repeat(MAX_APPLICATION_ID_BYTES / 2 + 1)),
        Err(ApplicationError::AdaptorTooLong {
            bytes: MAX_APPLICATION_ID_BYTES + 2,
            limit: MAX_APPLICATION_ID_BYTES,
        })
    );
}

#[test]
fn decoder_applies_the_same_application_validation() {
    for (bytes, expected) in [
        (raw_manifest("", "a"), ApplicationError::EmptyEvaluator),
        (raw_manifest("e", ""), ApplicationError::EmptyAdaptor),
        (
            raw_manifest(&"e".repeat(MAX_APPLICATION_ID_BYTES + 1), "a"),
            ApplicationError::EvaluatorTooLong {
                bytes: MAX_APPLICATION_ID_BYTES + 1,
                limit: MAX_APPLICATION_ID_BYTES,
            },
        ),
        (
            raw_manifest("e", &"a".repeat(MAX_APPLICATION_ID_BYTES + 1)),
            ApplicationError::AdaptorTooLong {
                bytes: MAX_APPLICATION_ID_BYTES + 1,
                limit: MAX_APPLICATION_ID_BYTES,
            },
        ),
    ] {
        assert_eq!(
            ProgramManifest::from_canonical_bytes(&bytes)
                .unwrap_err()
                .to_string(),
            expected.to_string()
        );
    }
}

#[test]
fn canonical_bytes_are_one_domain_tagged_shape() {
    let manifest = manifest("e", "a", 0x11);
    let mut expected = vec![0x83, 0x78, 0x1a];
    expected.extend_from_slice(b"hellas.program.manifest.v4");
    expected.extend_from_slice(&[0x82, 0x61, b'e', 0x61, b'a', 0x58, 0x20]);
    expected.extend_from_slice(&[0x11; 32]);

    assert_eq!(manifest.canonical_bytes(), expected);
    assert_eq!(
        ProgramManifest::from_canonical_bytes(&expected),
        Ok(manifest.clone())
    );
    assert_eq!(manifest.content_id(), ContentId::hash(&expected));
    assert_eq!(
        manifest.content_id().to_string(),
        "a0e154011f3dc2fdbcf69fafedca1d4aaf6bfc6e8fff625052c9a6f2b9169186"
    );
}

#[test]
fn identity_binds_the_whole_opaque_application_pair_and_root() {
    let joined_left = manifest("ab", "c", 7);
    let joined_right = manifest("a", "bc", 7);
    let other_evaluator = manifest("AB", "c", 7);
    let other_adaptor = manifest("ab", "C", 7);
    let other_root = manifest("ab", "c", 8);

    for other in [&joined_right, &other_evaluator, &other_adaptor, &other_root] {
        assert_ne!(&joined_left, other);
        assert_ne!(joined_left.content_id(), other.content_id());
    }
}

#[test]
fn decoder_rejects_noncanonical_trailing_and_oversized_inputs() {
    let canonical = manifest("e", "a", 0x11).canonical_bytes();

    let mut noncanonical = vec![0x98, 0x03];
    noncanonical.extend_from_slice(&canonical[1..]);
    assert!(
        ProgramManifest::from_canonical_bytes(&noncanonical)
            .unwrap_err()
            .to_string()
            .contains("non-canonical")
    );

    let mut trailing = canonical;
    trailing.push(0);
    assert!(
        ProgramManifest::from_canonical_bytes(&trailing)
            .unwrap_err()
            .to_string()
            .contains("trailing bytes")
    );

    let oversized = vec![0; MAX_PROGRAM_MANIFEST_BYTES + 1];
    assert!(
        ProgramManifest::from_canonical_bytes(&oversized)
            .unwrap_err()
            .to_string()
            .contains("over")
    );
}
