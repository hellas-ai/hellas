use super::*;

#[test]
fn provisioning_uses_the_generic_client_side_commands() {
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
        assert!(!acts_for_principal(&cli.command));
    }
}
