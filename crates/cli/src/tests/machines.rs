use super::*;

#[test]
fn provisioning_uses_the_generic_client_side_commands_without_an_identity() {
    for action in ["list", "create", "destroy"] {
        let mut args = vec![
            "hellas",
            "machines",
            "--provider-config",
            "provider.json",
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
