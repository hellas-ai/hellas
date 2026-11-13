//! Argument parsers for the CLI's clap definitions.

pub(crate) fn parse_positive_usize(s: &str) -> Result<usize, String> {
    usize::try_from(parse_positive_u64(s)?)
        .map_err(|_| "invalid positive integer: number too large to fit in target type".to_string())
}

pub(crate) fn parse_positive_u64(s: &str) -> Result<u64, String> {
    let value = s
        .parse::<u64>()
        .map_err(|error| format!("invalid positive integer: {error}"))?;
    (value > 0)
        .then_some(value)
        .ok_or_else(|| "value must be greater than zero".to_string())
}
