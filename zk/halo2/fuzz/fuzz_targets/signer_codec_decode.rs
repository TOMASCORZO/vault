#![no_main]

use libfuzzer_sys::fuzz_target;
use vault_privacy::OutputAuthorizationPacket;
use vault_protocol::TransferV2Effects;
use vault_signer::{
    DelegatedProvingPolicy, DelegatedProvingRequest, MultisigPolicy, SessionChallenge,
    SignerAuthorizationRequest,
};
use vault_zk_halo2_core::delegated_witness::DelegatedTransferWitness;

const SEEDS: [&[u8]; 7] = [
    include_bytes!(
        "../../../../docs/specs/test-vectors/h1-a3-v1/bucket-2/output-1-externalpayment.vaop"
    ),
    include_bytes!("../../../../docs/specs/test-vectors/h1-a3-v1/bucket-2/challenge.vsch"),
    include_bytes!("../../../../docs/specs/test-vectors/h1-a3-v1/bucket-2/sign-request.vsrq"),
    include_bytes!("../../../../docs/specs/test-vectors/h1-a3-v1/bucket-2/multisig-policy.vmsp"),
    include_bytes!("../../../../docs/specs/test-vectors/h1-a3-v1/bucket-2/delegated-policy.vdpp"),
    include_bytes!("../../../../docs/specs/test-vectors/h1-a3-v1/bucket-2/delegated-request.vdpr"),
    include_bytes!("../../../../docs/specs/test-vectors/h1-a3-v1/bucket-2/witness.vdpw"),
];

fn assert_decode_contract(bytes: &[u8]) {
    if let Ok(decoded) = OutputAuthorizationPacket::decode(bytes) {
        assert_eq!(decoded.encode().as_slice(), bytes);
    }
    if let Ok(decoded) = SessionChallenge::decode(bytes) {
        assert_eq!(decoded.encode().as_slice(), bytes);
    }
    if let Ok(decoded) = SignerAuthorizationRequest::decode(bytes) {
        assert_eq!(decoded.encode().as_slice(), bytes);
    }
    if let Ok(decoded) = MultisigPolicy::decode(bytes) {
        assert_eq!(decoded.encode(), bytes);
    }
    if let Ok(decoded) = DelegatedProvingPolicy::decode(bytes) {
        assert_eq!(decoded.encode().as_slice(), bytes);
    }
    if let Ok(decoded) = DelegatedProvingRequest::decode(bytes) {
        assert_eq!(decoded.encode().as_slice(), bytes);
    }
    if let Ok(decoded) = TransferV2Effects::decode_canonical(bytes) {
        assert_eq!(decoded.encode_canonical(), bytes);
    }

    match bytes.get(7).copied() {
        Some(2) => {
            if let Ok(decoded) = DelegatedTransferWitness::<2>::decode(bytes) {
                assert_eq!(decoded.encode().as_slice(), bytes);
            }
        }
        Some(4) => {
            if let Ok(decoded) = DelegatedTransferWitness::<4>::decode(bytes) {
                assert_eq!(decoded.encode().as_slice(), bytes);
            }
        }
        Some(8) => {
            if let Ok(decoded) = DelegatedTransferWitness::<8>::decode(bytes) {
                assert_eq!(decoded.encode().as_slice(), bytes);
            }
        }
        Some(16) => {
            if let Ok(decoded) = DelegatedTransferWitness::<16>::decode(bytes) {
                assert_eq!(decoded.encode().as_slice(), bytes);
            }
        }
        _ => {}
    }
}

fuzz_target!(|data: &[u8]| {
    assert_decode_contract(data);

    let seed_index = data.first().copied().map_or(0, usize::from) % SEEDS.len();
    let mut structured = SEEDS[seed_index].to_vec();
    for mutation in data.chunks_exact(3).take(64) {
        let offset = usize::from(u16::from_le_bytes([mutation[0], mutation[1]])) % structured.len();
        structured[offset] ^= mutation[2].max(1);
    }
    assert_decode_contract(&structured);
});
