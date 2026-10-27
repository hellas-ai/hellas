use super::*;
use proptest::prelude::*;
use std::{collections::BTreeMap, io::Cursor, ops::Range};

fn string(out: &mut Vec<u8>, text: &str) -> Range<usize> {
    out.extend_from_slice(&(text.len() as u64).to_le_bytes());
    let start = out.len();
    out.extend_from_slice(text.as_bytes());
    start..out.len()
}
fn prefix(tensors: u64, metadata: u64) -> Vec<u8> {
    let mut out = b"GGUF".to_vec();
    out.extend_from_slice(&3_u32.to_le_bytes());
    out.extend_from_slice(&tensors.to_le_bytes());
    out.extend_from_slice(&metadata.to_le_bytes());
    out
}
struct Fields {
    name: Range<usize>,
    rank: usize,
    dimensions: usize,
    dtype: usize,
    offset: usize,
}
fn tensor(out: &mut Vec<u8>, name: &str, shape: &[u64], dtype: u32, offset: u64) -> Fields {
    let name = string(out, name);
    let rank = out.len();
    out.extend_from_slice(&(shape.len() as u32).to_le_bytes());
    let dimensions = out.len();
    for dimension in shape {
        out.extend_from_slice(&dimension.to_le_bytes());
    }
    let dtype_at = out.len();
    out.extend_from_slice(&dtype.to_le_bytes());
    let offset_at = out.len();
    out.extend_from_slice(&offset.to_le_bytes());
    Fields {
        name,
        rank,
        dimensions,
        dtype: dtype_at,
        offset: offset_at,
    }
}
struct Fixture {
    bytes: Vec<u8>,
    first: Fields,
    second: Fields,
    alignment: usize,
    table_end: usize,
}
fn fixture() -> Fixture {
    fixture_alignment(Some(64))
}
fn fixture_alignment(alignment: Option<u32>) -> Fixture {
    let mut bytes = prefix(2, if alignment.is_some() { 3 } else { 2 });
    let mut alignment_at = 0;
    if let Some(alignment) = alignment {
        string(&mut bytes, "general.alignment");
        bytes.extend_from_slice(&4_u32.to_le_bytes());
        alignment_at = bytes.len();
        bytes.extend_from_slice(&alignment.to_le_bytes());
    }
    string(&mut bytes, "ignored.strings");
    bytes.extend_from_slice(&9_u32.to_le_bytes());
    bytes.extend_from_slice(&8_u32.to_le_bytes());
    bytes.extend_from_slice(&2_u64.to_le_bytes());
    string(&mut bytes, "a");
    string(&mut bytes, "☃");
    string(&mut bytes, "ignored.numbers");
    bytes.extend_from_slice(&9_u32.to_le_bytes());
    bytes.extend_from_slice(&10_u32.to_le_bytes());
    bytes.extend_from_slice(&2_u64.to_le_bytes());
    bytes.extend_from_slice(&11_u64.to_le_bytes());
    bytes.extend_from_slice(&22_u64.to_le_bytes());
    let first = tensor(&mut bytes, "weight", &[3, 2], 30, 0);
    let second = tensor(&mut bytes, "normal", &[2], 0, 64);
    let table_end = bytes.len();
    let alignment = alignment.unwrap_or(32) as usize;
    let data = table_end.div_ceil(alignment) * alignment;
    bytes.resize(data + 72, 0);
    bytes[data..data + 12].copy_from_slice(b"actual bf16!");
    bytes[data + 64..].copy_from_slice(b"f32 norm");
    Fixture {
        bytes,
        first,
        second,
        alignment: alignment_at,
        table_end,
    }
}
fn patch32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn patch64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn actual_ranges_and_logical_shapes_are_pinned_without_reading_tensor_payloads() {
    let fixture = fixture();
    assert_eq!(fixture.table_end, 255);
    let mut input = SparseFile::new(1 << 40);
    input.fields.insert(0, fixture.bytes);
    let header = read_header(&mut input).unwrap();
    assert_eq!(header.data_offset, 256);
    assert_eq!(
        header.tensors,
        vec![
            Tensor {
                name: "weight".into(),
                dtype: Dtype::Bf16,
                shape: vec![2, 3],
                offset: 256,
                bytes: 12
            },
            Tensor {
                name: "normal".into(),
                dtype: Dtype::F32,
                shape: vec![2],
                offset: 320,
                bytes: 8
            },
        ]
    );
    assert_eq!(input.position, 256);
    assert!(
        input.read_end <= 255,
        "the terabyte-sized data section was not read"
    );
    let mut small = Cursor::new(fixture_alignment(Some(64)).bytes);
    let header = read_header(&mut small).unwrap();
    assert_eq!(
        &small.get_ref()[header.tensors[0].offset as usize..268],
        b"actual bf16!"
    );
    assert_eq!(
        &small.get_ref()[header.tensors[1].offset as usize..328],
        b"f32 norm"
    );
}

#[test]
fn absent_alignment_defaults_to_thirty_two_and_nonzero_reader_positions_are_reset() {
    let mut input = Cursor::new(fixture_alignment(None).bytes);
    input.set_position(19);
    let header = read_header(&mut input).unwrap();
    assert_eq!(header.data_offset, 224);
    assert_eq!(header.tensors[0].offset, 224);
    assert_eq!(header.tensors[1].offset, 288);
}

#[test]
fn every_truncated_prefix_is_refused() {
    let bytes = fixture().bytes;
    for end in 0..bytes.len() {
        assert!(
            read_header(&mut Cursor::new(&bytes[..end])).is_err(),
            "accepted prefix ending at {end}"
        );
    }
}

#[test]
fn invalid_versions_types_shapes_names_offsets_and_ranges_are_refused() {
    let f = fixture();
    let mut cases = Vec::new();
    let mut add = |label, bytes| cases.push((label, bytes));
    let mut bytes = f.bytes.clone();
    bytes[0] = 0;
    add("magic", bytes);
    let mut bytes = f.bytes.clone();
    patch32(&mut bytes, 4, 2);
    add("version", bytes);
    let mut bytes = f.bytes.clone();
    patch32(&mut bytes, f.first.rank, 5);
    add("rank", bytes);
    let mut bytes = f.bytes.clone();
    patch32(&mut bytes, f.first.dtype, 1);
    add("unsupported dtype", bytes);
    let mut bytes = f.bytes.clone();
    patch64(&mut bytes, f.first.dimensions, 0);
    add("zero dimension", bytes);
    let mut bytes = f.bytes.clone();
    patch64(&mut bytes, f.first.dimensions, u64::MAX);
    add("size overflow", bytes);
    let mut bytes = f.bytes.clone();
    patch64(&mut bytes, f.first.offset, 1);
    add("unaligned", bytes);
    let mut bytes = f.bytes.clone();
    patch64(&mut bytes, f.first.offset, u64::MAX - 63);
    add("offset overflow", bytes);
    let mut bytes = f.bytes.clone();
    patch64(&mut bytes, f.second.offset, 128);
    add("past end", bytes);
    let mut bytes = f.bytes.clone();
    patch64(&mut bytes, f.second.offset, 0);
    add("partial overlap", bytes);
    let mut bytes = f.bytes.clone();
    bytes[f.second.name.clone()].copy_from_slice(b"weight");
    add("duplicate", bytes);
    let mut bytes = f.bytes.clone();
    bytes[f.first.name.start] = 0xff;
    add("invalid UTF-8", bytes);
    for alignment in [0, 1, 4, 24] {
        let mut bytes = f.bytes.clone();
        patch32(&mut bytes, f.alignment, alignment);
        add("invalid alignment", bytes);
    }
    for (label, bytes) in cases {
        assert!(
            read_header(&mut Cursor::new(bytes)).is_err(),
            "accepted {label}"
        );
    }
}

#[test]
fn identical_ranges_can_alias_but_partial_overlaps_cannot() {
    let mut f = fixture();
    patch64(&mut f.bytes, f.second.offset, 0);
    patch64(&mut f.bytes, f.second.dimensions, 3);
    let header = read_header(&mut Cursor::new(f.bytes)).unwrap();
    assert_eq!(header.tensors[0].offset, header.tensors[1].offset);
    assert_eq!(header.tensors[0].bytes, header.tensors[1].bytes);
}

#[test]
fn all_metadata_scalar_types_and_nested_arrays_preserve_the_tensor_table() {
    let mut bytes = prefix(1, 14);
    for (kind, width) in [
        (0, 1),
        (1, 1),
        (2, 2),
        (3, 2),
        (4, 4),
        (5, 4),
        (6, 4),
        (7, 1),
        (10, 8),
        (11, 8),
        (12, 8),
    ] {
        string(&mut bytes, &format!("ignored.scalar_{kind}"));
        bytes.extend_from_slice(&(kind as u32).to_le_bytes());
        bytes.resize(bytes.len() + width, 0);
    }
    string(&mut bytes, "ignored.string");
    bytes.extend_from_slice(&8_u32.to_le_bytes());
    string(&mut bytes, "ignored");
    string(&mut bytes, "ignored.nested");
    bytes.extend_from_slice(&9_u32.to_le_bytes());
    bytes.extend_from_slice(&9_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u64.to_le_bytes());
    bytes.extend_from_slice(&8_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u64.to_le_bytes());
    string(&mut bytes, "nested string");
    string(&mut bytes, "ignored.empty");
    bytes.extend_from_slice(&9_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u64.to_le_bytes());
    tensor(&mut bytes, "scalar", &[], 0, 0);
    let data = bytes.len().div_ceil(32) * 32;
    bytes.resize(data + 4, 0);
    let header = read_header(&mut Cursor::new(bytes)).unwrap();
    assert_eq!(header.tensors[0].offset, data as u64);
    assert_eq!(header.tensors[0].bytes, 4);
}

#[test]
fn excessive_counts_strings_arrays_and_nesting_fail_before_large_allocations() {
    let mut bytes = prefix(1, 0);
    tensor(&mut bytes, "rank-five", &[1; 5], 0, 0);
    bytes.resize(160, 0);
    assert!(matches!(
        read_header(&mut Cursor::new(bytes)),
        Err(Error::Limit {
            field: "tensor rank",
            ..
        })
    ));
    for (at, field) in [(8, "tensor count"), (16, "metadata count")] {
        let mut bytes = prefix(0, 0);
        patch64(&mut bytes, at, u64::MAX);
        let mut input = SparseFile::new(u64::MAX);
        input.fields.insert(0, bytes);
        assert!(
            matches!(read_header(&mut input), Err(Error::Limit {field:actual,..}) if actual==field)
        );
        assert!(input.max_read <= 8);
    }
    for (metadata, length, expected) in [(false, 65, "tensor name"), (true, 65_536, "metadata key")]
    {
        let mut bytes = prefix(if metadata { 0 } else { 1 }, if metadata { 1 } else { 0 });
        bytes.extend_from_slice(&(length as u64).to_le_bytes());
        let mut input = SparseFile::new(u64::MAX);
        input.fields.insert(0, bytes);
        assert!(matches!(read_header(&mut input), Err(Error::Limit {field,..}) if field==expected));
        assert!(input.max_read <= 8);
    }
    for (kind, body, expected) in [
        (
            8,
            (MAX_STRING + 1).to_le_bytes().to_vec(),
            "metadata string",
        ),
        (
            9,
            [
                10_u32.to_le_bytes().as_slice(),
                &(MAX_ARRAY + 1).to_le_bytes(),
            ]
            .concat(),
            "metadata array count",
        ),
        (
            9,
            (0..=MAX_NESTING)
                .flat_map(|_| [9_u32.to_le_bytes().as_slice(), &1_u64.to_le_bytes()].concat())
                .collect(),
            "metadata nesting",
        ),
    ] {
        let mut bytes = prefix(0, 1);
        string(&mut bytes, "ignored");
        bytes.extend_from_slice(&(kind as u32).to_le_bytes());
        bytes.extend(body);
        let mut input = SparseFile::new(u64::MAX);
        input.fields.insert(0, bytes);
        assert!(matches!(read_header(&mut input),Err(Error::Limit {field,..}) if field==expected));
        assert!(input.max_read <= 8);
    }
}

#[test]
fn header_budget_bounds_ignored_metadata_without_allocating_the_file() {
    let mut input = SparseFile::new(1 << 40);
    input.fields.insert(0, prefix(0, 65));
    let mut at = 24;
    for _ in 0..65 {
        let mut field = Vec::new();
        string(&mut field, "ignored");
        field.extend_from_slice(&8_u32.to_le_bytes());
        field.extend_from_slice(&MAX_STRING.to_le_bytes());
        at += field.len() as u64;
        input.fields.insert(at - field.len() as u64, field);
        at += MAX_STRING;
    }
    assert!(matches!(
        read_header(&mut input),
        Err(Error::Limit {
            field: "header bytes",
            ..
        })
    ));
    assert_eq!(input.max_read, MAX_STRING as usize);
}

#[test]
fn ambiguous_alignment_and_unknown_metadata_types_are_refused() {
    for kind in [13, u32::MAX] {
        let mut bytes = prefix(0, 1);
        string(&mut bytes, "ignored");
        bytes.extend_from_slice(&kind.to_le_bytes());
        bytes.resize(128, 0);
        assert!(read_header(&mut Cursor::new(bytes)).is_err());
        let mut bytes = prefix(0, 1);
        string(&mut bytes, "ignored");
        bytes.extend_from_slice(&9_u32.to_le_bytes());
        bytes.extend_from_slice(&kind.to_le_bytes());
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        bytes.resize(128, 0);
        assert!(read_header(&mut Cursor::new(bytes)).is_err());
    }
    let mut bytes = prefix(0, 2);
    for _ in 0..2 {
        string(&mut bytes, "general.alignment");
        bytes.extend_from_slice(&4_u32.to_le_bytes());
        bytes.extend_from_slice(&32_u32.to_le_bytes());
    }
    bytes.resize(128, 0);
    assert!(read_header(&mut Cursor::new(bytes)).is_err());
}

proptest! {
    #[test]
    fn mutated_headers_and_truncations_never_panic_or_return_unreadable_ranges(
        patches in prop::collection::vec((8usize..255, any::<u8>()), 0..32),
        end in 0usize..=328,
    ) {
        let mut bytes=fixture().bytes;
        for (at,value) in patches {bytes[at]=value;}
        bytes.truncate(end);
        if let Ok(header)=read_header(&mut Cursor::new(&bytes)) {
            let mut names=BTreeSet::new();
            for tensor in header.tensors {
                prop_assert!(names.insert(tensor.name));
                prop_assert!(tensor.offset>=header.data_offset);
                prop_assert!(bytes.get(tensor.offset as usize..(tensor.offset+tensor.bytes) as usize).is_some());
            }
        }
    }
}

/// A sparse, arbitrarily large file: only the supplied header bytes exist in RAM.
struct SparseFile {
    fields: BTreeMap<u64, Vec<u8>>,
    position: u64,
    length: u64,
    max_read: usize,
    read_end: u64,
}
impl SparseFile {
    fn new(length: u64) -> Self {
        Self {
            fields: BTreeMap::new(),
            position: 0,
            length,
            max_read: 0,
            read_end: 0,
        }
    }
}
impl Read for SparseFile {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = (buffer.len() as u64).min(self.length.saturating_sub(self.position)) as usize;
        buffer[..count].fill(0);
        let end = self.position + count as u64;
        for (&at, field) in self.fields.range(..end) {
            let start = at.max(self.position);
            let stop = (at + field.len() as u64).min(end);
            if start < stop {
                buffer[(start - self.position) as usize..(stop - self.position) as usize]
                    .copy_from_slice(&field[(start - at) as usize..(stop - at) as usize]);
            }
        }
        self.max_read = self.max_read.max(count);
        self.read_end = self.read_end.max(end);
        self.position = end;
        Ok(count)
    }
}
impl Seek for SparseFile {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let position = match from {
            SeekFrom::Start(at) => at as i128,
            SeekFrom::Current(delta) => self.position as i128 + delta as i128,
            SeekFrom::End(delta) => self.length as i128 + delta as i128,
        };
        self.position = u64::try_from(position).map_err(|_| io::Error::other("invalid seek"))?;
        Ok(self.position)
    }
}
