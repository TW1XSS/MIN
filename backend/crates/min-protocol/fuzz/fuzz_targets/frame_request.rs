#![no_main]
use libfuzzer_sys::fuzz_target;
use min_protocol::frame_api::FrameRequest;

/// Fuzzing для FrameRequest::from_wire.
///
/// Вход: произвольные байты как CBOR payload.
/// Ожидание: никаких паников, только ProtocolError.
fuzz_target!(|data: &[u8]| {
    // Попытаться декодировать произвольные байты как FrameRequest
    let _: Result<FrameRequest, _> = FrameRequest::from_wire(data);
});