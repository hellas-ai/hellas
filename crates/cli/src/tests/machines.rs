use super::*;

#[test]
fn provisioning_uses_the_generic_client_side_commands_without_an_identity() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../../docs/machine-provider.json")).unwrap();
    let provider = fixture["provider"].as_str().unwrap();
    for action in ["list", "create", "destroy"] {
        let mut args = vec![
            "hellas",
            "machines",
            "--provider",
            provider,
            "--credential-source",
            "source.json",
            action,
        ];
        match action {
            "create" => args.extend(["--spec", "machine.json"]),
            "destroy" => args.push("machine-id"),
            _ => {}
        }
        let cli = Cli::try_parse_from(args).unwrap();
        validate_identity_options(&cli.command, None, false).unwrap();
        assert!(
            validate_identity_options(
                &cli.command,
                Some(std::path::Path::new("identity.json")),
                false
            )
            .is_err()
        );
    }
}
