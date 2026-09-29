#![no_main]
use libfuzzer_sys::fuzz_target;
use min_wire::{canonical_decode_strict, unframe};

fuzz_target!(|data: &[u8]| {
    let mut buf = data.to_vec();

    while let Some(result) = unframe(&mut buf) {
        match result {
            Ok(payload) => {
                assert!(payload.len() <= 256 * 1024);
            }
            Err(_) => {}
        }
    }

    let _: Result<u64, _> = canonical_decode_strict(data);
    let _: Result<Vec<u8>, _> = canonical_decode_strict(data);
    let _: Result<String, _> = canonical_decode_strict(data);
});
