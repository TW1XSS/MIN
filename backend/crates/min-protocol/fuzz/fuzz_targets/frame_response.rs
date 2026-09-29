#![no_main]
use libfuzzer_sys::fuzz_target;
use min_protocol::frame_api::FrameResponse;

/// Fuzzing для FrameResponse::from_wire.
///
/// Вход: произвольные байты как CBOR payload.
/// Ожидание: никаких паников, только ProtocolError.
fuzz_target!(|data: &[u8]| {
    let _: Result<FrameResponse, _> = FrameResponse::from_wire(data);
});