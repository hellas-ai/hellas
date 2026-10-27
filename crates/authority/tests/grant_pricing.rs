use hellas_auth::authority::Revision;
use hellas_authority::model::grant::{
    budget::{Charge, Meter},
    pricing::{Pricing, PricingError, UnitPrice},
};
use std::num::NonZeroU64;

fn price(meter: Meter, usd_micros: u64, units: u64) -> UnitPrice {
    UnitPrice {
        meter,
        usd_micros,
        units: NonZeroU64::new(units).unwrap(),
    }
}
fn table(rates: Vec<UnitPrice>) -> Pricing {
    Pricing {
        revision: Revision(1),
        rates: Some(rates),
    }
}

#[test]
fn components_round_up_per_job_and_free_usage_is_distinct_from_unpriced() {
    let pricing = table(vec![
        price(Meter::Requests, 2, 1),
        price(Meter::OutputTokens, 3, 4),
    ]);
    for (output, expected) in [(0, 2), (1, 3), (2, 4), (3, 5), (4, 5), (8, 8)] {
        let usage = Charge([1, 999, output, 999, u64::MAX]);
        assert_eq!(pricing.quote(usage), Ok(Some(expected)));
        let reserve = pricing.reserve(usage).unwrap();
        assert_eq!(reserve.get(Meter::UsdMicros), expected);
        assert_eq!(pricing.settle(usage).unwrap(), reserve);
    }
    assert_eq!(table(vec![]).quote(Charge::default()), Ok(Some(0)));
    assert_eq!(
        Pricing {
            revision: Revision(1),
            rates: None
        }
        .quote(Charge::default()),
        Ok(None)
    );
}

#[test]
fn products_and_sums_never_wrap_and_overflowing_settlement_is_exhausted() {
    let one = table(vec![price(Meter::OutputTokens, u64::MAX, 8)]);
    assert_eq!(one.quote(Charge([1, 0, 8, 0, 0])), Ok(Some(u64::MAX)));
    let overrun = Charge([1, 0, 9, 0, 0]);
    assert_eq!(one.reserve(overrun), Err(PricingError::Overflow));
    assert_eq!(one.settle(overrun).unwrap().get(Meter::UsdMicros), u64::MAX);
    let two = table(vec![
        price(Meter::Requests, 1, 1),
        price(Meter::OutputTokens, u64::MAX, 1),
    ]);
    assert_eq!(
        two.quote(Charge([1, 0, 1, 0, 0])),
        Err(PricingError::Overflow)
    );
    let exact = table(vec![price(Meter::OutputTokens, u64::MAX, u64::MAX)]);
    assert_eq!(
        exact.quote(Charge([1, 0, u64::MAX, 0, 0])),
        Ok(Some(u64::MAX))
    );
}

#[test]
fn invalid_tables_are_refused_before_any_quote() {
    for pricing in [
        Pricing {
            revision: Revision(0),
            rates: None,
        },
        table(vec![price(Meter::UsdMicros, 1, 1)]),
        table(vec![
            price(Meter::Requests, 1, 1),
            price(Meter::Requests, 2, 1),
        ]),
    ] {
        assert_eq!(pricing.quote(Charge::default()), Err(PricingError::Invalid));
        assert_eq!(
            pricing.settle(Charge::default()),
            Err(PricingError::Invalid)
        );
    }
    for json in [
        r#"{"revision":1,"rates":[{"meter":"OutputTokens","usd_micros":1,"units":0}]}"#,
        r#"{"revision":1,"rates":[{"meter":"OutputTokens","usd_micros":-1,"units":1}]}"#,
        r#"{"revision":1,"rates":[],"currency":"unknown"}"#,
    ] {
        assert!(serde_json::from_str::<Pricing>(json).is_err());
    }
}

#[test]
fn smaller_trusted_usage_never_costs_more_than_its_conservative_reservation() {
    for numerator in [0, 1, 3, 1000, u64::MAX] {
        for denominator in [1, 4, 1000, u64::MAX] {
            let pricing = table(vec![price(Meter::OutputTokens, numerator, denominator)]);
            for bound in [1, 8, 1024, u64::MAX] {
                let reserve = pricing.reserve(Charge([1, 0, bound, 0, 0]));
                if let Ok(reserve) = reserve {
                    for output in [0, 1, bound / 2, bound] {
                        let actual = pricing.settle(Charge([1, 0, output, 0, 0])).unwrap();
                        assert!(!actual.exceeds(reserve));
                    }
                }
            }
        }
    }
}
