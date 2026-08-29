use vault_privacy::OutputAuthorizationPacket;
use vault_signer::{
    BoundTransferV2Authorizations, DelegatedProvingRequest, DelegatedProvingResponse,
    MultisigPolicy, SessionChallenge, SignerAuthorizationRequest,
};

macro_rules! verify_bucket {
    ($count:literal, $external:literal) => {{
        let challenge = include_bytes!(concat!(
            "../../../docs/specs/test-vectors/h1-a3-v1/bucket-",
            stringify!($count),
            "/challenge.vsch"
        ));
        assert_eq!(
            SessionChallenge::decode(challenge)
                .unwrap()
                .encode()
                .as_slice(),
            challenge
        );

        let signer_request = include_bytes!(concat!(
            "../../../docs/specs/test-vectors/h1-a3-v1/bucket-",
            stringify!($count),
            "/sign-request.vsrq"
        ));
        let signer_request = SignerAuthorizationRequest::decode(signer_request).unwrap();
        let signer_response = include_bytes!(concat!(
            "../../../docs/specs/test-vectors/h1-a3-v1/bucket-",
            stringify!($count),
            "/sign-response.vsrp"
        ));
        let decoded_response = BoundTransferV2Authorizations::decode(
            signer_response,
            signer_request.transcript_id(),
            signer_request.effects(),
        )
        .unwrap();
        assert_eq!(decoded_response.encode(), signer_response);

        let output = include_bytes!(concat!(
            "../../../docs/specs/test-vectors/h1-a3-v1/bucket-",
            stringify!($count),
            "/output-",
            stringify!($external),
            "-externalpayment.vaop"
        ));
        assert_eq!(
            OutputAuthorizationPacket::decode(output)
                .unwrap()
                .encode()
                .as_slice(),
            output
        );

        let multisig_policy = include_bytes!(concat!(
            "../../../docs/specs/test-vectors/h1-a3-v1/bucket-",
            stringify!($count),
            "/multisig-policy.vmsp"
        ));
        assert_eq!(
            MultisigPolicy::decode(multisig_policy).unwrap().encode(),
            multisig_policy
        );

        let delegated_request = include_bytes!(concat!(
            "../../../docs/specs/test-vectors/h1-a3-v1/bucket-",
            stringify!($count),
            "/delegated-request.vdpr"
        ));
        let delegated_request = DelegatedProvingRequest::decode(delegated_request).unwrap();
        let delegated_response = include_bytes!(concat!(
            "../../../docs/specs/test-vectors/h1-a3-v1/bucket-",
            stringify!($count),
            "/delegated-response-context-negative.vdps"
        ));
        let decoded_response = DelegatedProvingResponse::decode(
            delegated_response,
            delegated_request.policy(),
            delegated_request.authorization(),
            delegated_request.effects(),
        )
        .unwrap();
        assert_eq!(decoded_response.encode(), delegated_response);

        let malformed = include_bytes!(concat!(
            "../../../docs/specs/test-vectors/h1-a3-v1/bucket-",
            stringify!($count),
            "/delegated-request.vdpr.bad-magic"
        ));
        assert!(DelegatedProvingRequest::decode(malformed).is_err());
    }};
}

#[test]
fn committed_signer_and_delegated_codec_corpus_matches_all_buckets() {
    verify_bucket!(2, 1);
    verify_bucket!(4, 3);
    verify_bucket!(8, 7);
    verify_bucket!(16, 15);
}
