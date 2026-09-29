#![no_main]
use libfuzzer_sys::fuzz_target;
use min_protocol::envelope::EnvelopeV1;

/// Fuzzing для EnvelopeV1::from_wire.
///
/// Вход: произвольные байты как CBOR envelope.
/// Ожидание: никаких паников, только ProtocolError.
fuzz_target!(|data: &[u8]| {
    let _: Result<EnvelopeV1, _> = EnvelopeV1::from_wire(data);
});