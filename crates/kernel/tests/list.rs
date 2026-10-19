//! Direct coverage of `List<T, N>` ergonomics — iteration, mapping, and
//! the constructors that didn't get exercised through the kernel's
//! higher-level paths.

#![allow(clippy::alloc_instead_of_core)]
#![allow(clippy::disallowed_types)]
#![allow(clippy::std_instead_of_alloc)]
#![allow(clippy::std_instead_of_core)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::indexing_slicing)] // tests may index; the panic-freedom lock targets src

use hellas_kernel::List;

#[test]
fn into_iter_yields_live_entries_consuming() {
    let list: List<u32, 4> = List::new([1, 2, 3, 4], 3).unwrap();

    let collected: Vec<u32> = list.into_iter().collect();

    assert_eq!(collected, vec![1, 2, 3]);
}

#[test]
fn into_iter_by_ref_yields_live_entries() {
    let list: List<u32, 4> = List::new([10, 20, 30, 40], 2).unwrap();

    let collected: Vec<u32> = (&list).into_iter().copied().collect();

    assert_eq!(collected, vec![10, 20]);
    // List still usable after the by-ref iteration.
    assert_eq!(list.len(), 2);
}

#[test]
fn for_loop_over_list_uses_by_ref_into_iter() {
    let list: List<u32, 4> = List::new([5, 6, 7, 8], 4).unwrap();

    let mut total: u32 = 0;
    for &item in &list {
        total += item;
    }

    assert_eq!(total, 5 + 6 + 7 + 8);
}

#[test]
fn map_transforms_each_live_entry() {
    let list: List<u32, 4> = List::new([1, 2, 3, 4], 3).unwrap();

    let doubled: List<u32, 4> = list.map(0, |x| x * 2);

    assert_eq!(doubled.len(), 3);
    assert_eq!(doubled.as_slice(), &[2, 4, 6]);
}

#[test]
fn map_preserves_zero_length() {
    let list: List<u32, 4> = List::empty(0);

    let mapped: List<u32, 4> = list.map(0, |x| x + 1);

    assert!(mapped.is_empty());
    assert_eq!(mapped.as_slice(), []);
}

#[test]
fn empty_constructor_yields_zero_length_list() {
    let list: List<u32, 4> = List::empty(42);

    assert_eq!(list.len(), 0);
    assert!(list.is_empty());
    assert_eq!(list.as_slice(), []);
}

#[test]
fn all_constructor_yields_full_list() {
    let list: List<u32, 3> = List::all([100, 200, 300]);

    assert_eq!(list.len(), 3);
    assert!(!list.is_empty());
    assert_eq!(list.as_slice(), &[100, 200, 300]);
}

#[test]
fn new_rejects_overflowing_length() {
    let result: Option<List<u32, 2>> = List::new([1, 2], 3);

    assert!(result.is_none());
}

#[test]
fn take_saturates_at_capacity() {
    let list: List<u32, 4> = List::take([1, 2, 3, 4], 999);

    assert_eq!(list.len(), 4);
    assert_eq!(list.as_slice(), &[1, 2, 3, 4]);
}

#[test]
fn take_preserves_under_capacity_length() {
    let list: List<u32, 4> = List::take([1, 2, 3, 4], 2);

    assert_eq!(list.len(), 2);
    assert_eq!(list.as_slice(), &[1, 2]);
}
