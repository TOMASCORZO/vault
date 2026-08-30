#[cfg(unix)]
mod common;

use vault_signer::{SignerTransportError, SignerTransportKeyPair};

#[cfg(unix)]
use vault_signer::{MAX_SIGNER_MESSAGE_BYTES, SignerTransport, SignerTransportMessageKind};

#[cfg(unix)]
const NETWORK: [u8; 32] = [0x31; 32];

#[cfg(unix)]
fn paired_transport() -> (SignerTransport, SignerTransport) {
    common::paired_transport([0x91; 32], NETWORK)
}

#[test]
#[cfg(unix)]
fn paired_noise_channel_is_mutually_authenticated_and_bound() {
    let (mut initiator, mut responder) = paired_transport();
    assert_eq!(initiator.channel_binding(), responder.channel_binding());
    assert_ne!(initiator.channel_binding(), [0; 32]);

    let encrypted = initiator
        .write_message(SignerTransportMessageKind::Challenge, b"challenge")
        .unwrap();
    assert!(!encrypted.windows(9).any(|window| window == b"challenge"));
    let message = responder.read_message(&encrypted).unwrap();
    assert_eq!(message.kind, SignerTransportMessageKind::Challenge);
    assert_eq!(message.payload, b"challenge");

    let response = responder
        .write_message(SignerTransportMessageKind::AuthorizationResponse, b"ok")
        .unwrap();
    let response = initiator.read_message(&response).unwrap();
    assert_eq!(
        response.kind,
        SignerTransportMessageKind::AuthorizationResponse
    );
    assert_eq!(response.payload, b"ok");
}

#[test]
#[cfg(unix)]
fn transport_replay_reordering_and_tampering_poison_the_channel() {
    let (mut sender, mut receiver) = paired_transport();
    let first = sender
        .write_message(SignerTransportMessageKind::Challenge, b"first")
        .unwrap();
    assert!(receiver.read_message(&first).is_ok());
    assert_eq!(
        receiver.read_message(&first),
        Err(SignerTransportError::InvalidMessage)
    );
    assert_eq!(
        receiver.read_message(&first),
        Err(SignerTransportError::Closed)
    );

    let (mut sender, mut receiver) = paired_transport();
    let first = sender
        .write_message(SignerTransportMessageKind::Challenge, b"first")
        .unwrap();
    let second = sender
        .write_message(SignerTransportMessageKind::AuthorizationRequest, b"second")
        .unwrap();
    assert_eq!(
        receiver.read_message(&second),
        Err(SignerTransportError::InvalidMessage)
    );
    assert_eq!(
        receiver.read_message(&first),
        Err(SignerTransportError::Closed)
    );

    let (mut sender, mut receiver) = paired_transport();
    let mut message = sender
        .write_message(SignerTransportMessageKind::Challenge, b"auth")
        .unwrap();
    message[0] ^= 1;
    assert_eq!(
        receiver.read_message(&message),
        Err(SignerTransportError::InvalidMessage)
    );
}

#[test]
#[cfg(unix)]
fn exact_resource_bound_is_enforced() {
    let (mut sender, mut receiver) = paired_transport();
    let payload = vec![0x5a; MAX_SIGNER_MESSAGE_BYTES];
    let encrypted = sender
        .write_message(SignerTransportMessageKind::AuthorizationRequest, &payload)
        .unwrap();
    assert_eq!(receiver.read_message(&encrypted).unwrap().payload, payload);

    assert_eq!(
        sender.write_message(
            SignerTransportMessageKind::AuthorizationRequest,
            &vec![0; MAX_SIGNER_MESSAGE_BYTES + 1],
        ),
        Err(SignerTransportError::MessageTooLarge)
    );
}

#[test]
fn restored_transport_identity_is_byte_exact() {
    let private = [0x44; 32];
    let restored = SignerTransportKeyPair::from_private(private).unwrap();
    let restored_again = SignerTransportKeyPair::from_private(*restored.export_private()).unwrap();
    assert_eq!(restored.public_key(), restored_again.public_key());
    assert!(format!("{restored:?}").contains("REDACTED"));
    assert_eq!(
        SignerTransportKeyPair::from_private([0; 32]).unwrap_err(),
        SignerTransportError::InvalidConfiguration
    );
}
