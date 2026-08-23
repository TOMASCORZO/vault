use core::fmt;

use rand_core::{CryptoRng, RngCore};
use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

const FRAME_MAGIC: [u8; 4] = *b"VST1";
const FRAME_VERSION: u16 = 1;
const FRAME_HEADER_BYTES: usize = 4 + 2 + 1 + 8 + 4;
const MAX_TRANSPORT_MESSAGES: u64 = 4;
const HANDSHAKE_BUFFER_BYTES: usize = 256;
const NOISE_TAG_BYTES: usize = 16;

/// Exact paired-peer Noise profile selected for Vault signer transport v1.
pub const SIGNER_NOISE_PROTOCOL: &str = "Noise_KK_25519_ChaChaPoly_BLAKE2s";
/// Maximum authenticated application plaintext in one signer message.
pub const MAX_SIGNER_PLAINTEXT_BYTES: usize = 60 * 1024;
/// Maximum payload after the Vault frame header.
pub const MAX_SIGNER_MESSAGE_BYTES: usize = MAX_SIGNER_PLAINTEXT_BYTES - FRAME_HEADER_BYTES;

const PROLOGUE_DOMAIN: &[u8] = b"vault.signer.noise-kk.prologue.v1";

/// Fail-closed signer transport error. Cryptographic failures are deliberately
/// opaque at the application boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignerTransportError {
    /// Key, network, protocol, or handshake state is invalid.
    InvalidConfiguration,
    /// The authenticated handshake failed or was used out of order.
    HandshakeFailed,
    /// A transport ciphertext failed authentication or canonical decoding.
    InvalidMessage,
    /// A message exceeded the fixed Noise or Vault resource limit.
    MessageTooLarge,
    /// This connection was closed or poisoned by an earlier failure.
    Closed,
}

impl fmt::Display for SignerTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidConfiguration => "invalid signer transport configuration",
            Self::HandshakeFailed => "signer transport handshake failed",
            Self::InvalidMessage => "invalid signer transport message",
            Self::MessageTooLarge => "signer transport message exceeds limit",
            Self::Closed => "signer transport is closed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SignerTransportError {}

/// Dedicated X25519 identity for a paired signer transport.
///
/// This key is never derived from or reused as a Vault spending/viewing key.
pub struct SignerTransportKeyPair {
    private: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl fmt::Debug for SignerTransportKeyPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignerTransportKeyPair")
            .field("public", &self.public)
            .field("private", &"REDACTED")
            .finish()
    }
}

impl SignerTransportKeyPair {
    /// Generates a dedicated static transport identity with caller-supplied CSPRNG.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let secret = StaticSecret::random_from_rng(rng);
        let private = secret.to_bytes();
        let public = PublicKey::from(&secret).to_bytes();
        Self {
            private: Zeroizing::new(private),
            public,
        }
    }

    /// Restores a static transport identity from protected key storage.
    pub fn from_private(mut private: [u8; 32]) -> Result<Self, SignerTransportError> {
        if private == [0; 32] {
            private.zeroize();
            return Err(SignerTransportError::InvalidConfiguration);
        }
        let secret = StaticSecret::from(private);
        let public = PublicKey::from(&secret).to_bytes();
        Ok(Self {
            private: Zeroizing::new(private),
            public,
        })
    }

    /// Public pairing identity displayed or authenticated out of band.
    #[must_use]
    pub const fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// Returns a zeroizing copy for encrypted identity-key backup.
    #[must_use]
    pub fn export_private(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.private)
    }

    pub(crate) fn private_bytes(&self) -> &[u8; 32] {
        &self.private
    }
}

/// In-progress two-message Noise KK handshake for already-paired peers.
pub struct SignerHandshake {
    state: HandshakeState,
    failed: bool,
}

impl fmt::Debug for SignerHandshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignerHandshake")
            .field("finished", &self.state.is_handshake_finished())
            .finish_non_exhaustive()
    }
}

impl SignerHandshake {
    /// Creates the initiator side. Both static public keys must already have
    /// been authenticated by a separate pairing ceremony.
    pub(crate) fn initiator(
        local: &SignerTransportKeyPair,
        remote_public: [u8; 32],
        network_id: [u8; 32],
    ) -> Result<Self, SignerTransportError> {
        Self::new(local, remote_public, network_id, true)
    }

    /// Creates the responder side for the exact same pre-paired identities.
    pub(crate) fn responder(
        local: &SignerTransportKeyPair,
        remote_public: [u8; 32],
        network_id: [u8; 32],
    ) -> Result<Self, SignerTransportError> {
        Self::new(local, remote_public, network_id, false)
    }

    fn new(
        local: &SignerTransportKeyPair,
        remote_public: [u8; 32],
        network_id: [u8; 32],
        initiator: bool,
    ) -> Result<Self, SignerTransportError> {
        if network_id == [0; 32] || remote_public == [0; 32] || remote_public == local.public {
            return Err(SignerTransportError::InvalidConfiguration);
        }
        let parameters: NoiseParams = SIGNER_NOISE_PROTOCOL
            .parse()
            .map_err(|_| SignerTransportError::InvalidConfiguration)?;
        let prologue = prologue(network_id, local.public, remote_public, initiator);
        let builder = Builder::new(parameters)
            .local_private_key(local.private.as_ref())
            .map_err(|_| SignerTransportError::InvalidConfiguration)?
            .remote_public_key(&remote_public)
            .map_err(|_| SignerTransportError::InvalidConfiguration)?
            .prologue(&prologue)
            .map_err(|_| SignerTransportError::InvalidConfiguration)?;
        let state = if initiator {
            builder.build_initiator()
        } else {
            builder.build_responder()
        }
        .map_err(|_| SignerTransportError::InvalidConfiguration)?;
        Ok(Self {
            state,
            failed: false,
        })
    }

    /// Writes the next fixed empty-payload handshake flight.
    pub fn write_message(&mut self) -> Result<Vec<u8>, SignerTransportError> {
        if self.failed || self.state.is_handshake_finished() || !self.state.is_my_turn() {
            return Err(SignerTransportError::HandshakeFailed);
        }
        let mut message = vec![0; HANDSHAKE_BUFFER_BYTES];
        let length = match self.state.write_message(&[], &mut message) {
            Ok(length) => length,
            Err(_) => {
                self.failed = true;
                return Err(SignerTransportError::HandshakeFailed);
            }
        };
        message.truncate(length);
        Ok(message)
    }

    /// Authenticates and consumes the next handshake flight. Handshake payloads
    /// are forbidden so negotiation cannot silently alter this profile.
    pub fn read_message(&mut self, message: &[u8]) -> Result<(), SignerTransportError> {
        if self.failed || self.state.is_handshake_finished() || self.state.is_my_turn() {
            return Err(SignerTransportError::HandshakeFailed);
        }
        let mut payload = [0; 1];
        let length = match self.state.read_message(message, &mut payload) {
            Ok(length) => length,
            Err(_) => {
                self.failed = true;
                return Err(SignerTransportError::HandshakeFailed);
            }
        };
        if length != 0 {
            self.failed = true;
            return Err(SignerTransportError::HandshakeFailed);
        }
        Ok(())
    }

    /// Converts a completed handshake into a bounded ordered transport and
    /// retains the Noise handshake hash as its channel binding.
    pub fn into_transport(self) -> Result<SignerTransport, SignerTransportError> {
        if self.failed || !self.state.is_handshake_finished() {
            return Err(SignerTransportError::HandshakeFailed);
        }
        let channel_binding: [u8; 32] = self
            .state
            .get_handshake_hash()
            .try_into()
            .map_err(|_| SignerTransportError::HandshakeFailed)?;
        let state = self
            .state
            .into_transport_mode()
            .map_err(|_| SignerTransportError::HandshakeFailed)?;
        Ok(SignerTransport {
            state,
            channel_binding,
            send_sequence: 0,
            receive_sequence: 0,
            closed: false,
        })
    }
}

fn prologue(
    network_id: [u8; 32],
    local_public: [u8; 32],
    remote_public: [u8; 32],
    initiator: bool,
) -> Vec<u8> {
    let (initiator_public, responder_public) = if initiator {
        (local_public, remote_public)
    } else {
        (remote_public, local_public)
    };
    let mut value = Vec::with_capacity(PROLOGUE_DOMAIN.len() + 32 * 3);
    value.extend_from_slice(PROLOGUE_DOMAIN);
    value.extend_from_slice(&network_id);
    value.extend_from_slice(&initiator_public);
    value.extend_from_slice(&responder_public);
    value
}

/// Authenticated signer application message kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SignerTransportMessageKind {
    /// Signer-generated freshness challenge.
    Challenge = 0,
    /// Coordinator request containing effects and private packets.
    AuthorizationRequest = 1,
    /// Signer response containing transcript-bound authorizations.
    AuthorizationResponse = 2,
    /// Terminal fail-closed abort without detailed secret-bearing reason.
    Abort = 3,
}

impl SignerTransportMessageKind {
    fn from_byte(value: u8) -> Result<Self, SignerTransportError> {
        match value {
            0 => Ok(Self::Challenge),
            1 => Ok(Self::AuthorizationRequest),
            2 => Ok(Self::AuthorizationResponse),
            3 => Ok(Self::Abort),
            _ => Err(SignerTransportError::InvalidMessage),
        }
    }
}

/// Decrypted, strictly ordered Vault signer message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerTransportMessage {
    /// Application message kind.
    pub kind: SignerTransportMessageKind,
    /// Exact authenticated payload.
    pub payload: Vec<u8>,
}

/// One ordered Noise transport. Any authentication or codec failure poisons it.
pub struct SignerTransport {
    state: TransportState,
    channel_binding: [u8; 32],
    send_sequence: u64,
    receive_sequence: u64,
    closed: bool,
}

impl fmt::Debug for SignerTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignerTransport")
            .field("send_sequence", &self.send_sequence)
            .field("receive_sequence", &self.receive_sequence)
            .field("cryptographic_state", &"REDACTED")
            .finish()
    }
}

impl SignerTransport {
    /// Noise handshake hash used for post-handshake channel binding.
    #[must_use]
    pub const fn channel_binding(&self) -> [u8; 32] {
        self.channel_binding
    }

    /// Encrypts one bounded, canonical, strictly ordered application frame.
    pub fn write_message(
        &mut self,
        kind: SignerTransportMessageKind,
        payload: &[u8],
    ) -> Result<Vec<u8>, SignerTransportError> {
        if self.closed || self.send_sequence >= MAX_TRANSPORT_MESSAGES {
            self.closed = true;
            return Err(SignerTransportError::Closed);
        }
        if payload.len() > MAX_SIGNER_MESSAGE_BYTES {
            return Err(SignerTransportError::MessageTooLarge);
        }
        let payload_length =
            u32::try_from(payload.len()).map_err(|_| SignerTransportError::MessageTooLarge)?;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(FRAME_HEADER_BYTES + payload.len()));
        plaintext.extend_from_slice(&FRAME_MAGIC);
        plaintext.extend_from_slice(&FRAME_VERSION.to_le_bytes());
        plaintext.push(kind as u8);
        plaintext.extend_from_slice(&self.send_sequence.to_le_bytes());
        plaintext.extend_from_slice(&payload_length.to_le_bytes());
        plaintext.extend_from_slice(payload);
        let mut ciphertext = vec![0; plaintext.len() + NOISE_TAG_BYTES];
        let result = self.state.write_message(&plaintext, &mut ciphertext);
        let length = match result {
            Ok(length) => length,
            Err(_) => {
                self.closed = true;
                return Err(SignerTransportError::InvalidMessage);
            }
        };
        ciphertext.truncate(length);
        self.send_sequence += 1;
        Ok(ciphertext)
    }

    /// Authenticates and decodes the next exact application frame.
    pub fn read_message(
        &mut self,
        ciphertext: &[u8],
    ) -> Result<SignerTransportMessage, SignerTransportError> {
        if self.closed || self.receive_sequence >= MAX_TRANSPORT_MESSAGES {
            self.closed = true;
            return Err(SignerTransportError::Closed);
        }
        if ciphertext.len() > MAX_SIGNER_PLAINTEXT_BYTES + NOISE_TAG_BYTES
            || ciphertext.len() < FRAME_HEADER_BYTES + NOISE_TAG_BYTES
        {
            self.closed = true;
            return Err(SignerTransportError::MessageTooLarge);
        }
        let mut plaintext = Zeroizing::new(vec![0; ciphertext.len()]);
        let result = self.state.read_message(ciphertext, &mut plaintext);
        let length = match result {
            Ok(length) => length,
            Err(_) => {
                self.closed = true;
                return Err(SignerTransportError::InvalidMessage);
            }
        };
        plaintext.truncate(length);
        let decoded = decode_frame(&plaintext, self.receive_sequence);
        match decoded {
            Ok(message) => {
                self.receive_sequence += 1;
                Ok(message)
            }
            Err(error) => {
                self.closed = true;
                Err(error)
            }
        }
    }

    /// Irreversibly closes the current transport session.
    pub fn close(&mut self) {
        self.closed = true;
    }
}

fn decode_frame(
    plaintext: &[u8],
    expected_sequence: u64,
) -> Result<SignerTransportMessage, SignerTransportError> {
    if plaintext.len() < FRAME_HEADER_BYTES || plaintext[..4] != FRAME_MAGIC {
        return Err(SignerTransportError::InvalidMessage);
    }
    let version = u16::from_le_bytes(
        plaintext[4..6]
            .try_into()
            .map_err(|_| SignerTransportError::InvalidMessage)?,
    );
    if version != FRAME_VERSION {
        return Err(SignerTransportError::InvalidMessage);
    }
    let kind = SignerTransportMessageKind::from_byte(plaintext[6])?;
    let sequence = u64::from_le_bytes(
        plaintext[7..15]
            .try_into()
            .map_err(|_| SignerTransportError::InvalidMessage)?,
    );
    if sequence != expected_sequence {
        return Err(SignerTransportError::InvalidMessage);
    }
    let payload_length = usize::try_from(u32::from_le_bytes(
        plaintext[15..19]
            .try_into()
            .map_err(|_| SignerTransportError::InvalidMessage)?,
    ))
    .map_err(|_| SignerTransportError::InvalidMessage)?;
    if payload_length != plaintext.len() - FRAME_HEADER_BYTES {
        return Err(SignerTransportError::InvalidMessage);
    }
    Ok(SignerTransportMessage {
        kind,
        payload: plaintext[FRAME_HEADER_BYTES..].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

    use super::*;

    const NETWORK: [u8; 32] = [0x31; 32];

    #[test]
    fn low_level_kk_rejects_wrong_network_identity_and_tampering() {
        let mut rng = ChaCha20Rng::from_seed([0x92; 32]);
        let initiator_key = SignerTransportKeyPair::generate(&mut rng);
        let responder_key = SignerTransportKeyPair::generate(&mut rng);
        let attacker_key = SignerTransportKeyPair::generate(&mut rng);

        let mut initiator =
            SignerHandshake::initiator(&initiator_key, responder_key.public_key(), NETWORK)
                .unwrap();
        let mut wrong_network =
            SignerHandshake::responder(&responder_key, initiator_key.public_key(), [0x32; 32])
                .unwrap();
        let first = initiator.write_message().unwrap();
        assert_eq!(
            wrong_network.read_message(&first),
            Err(SignerTransportError::HandshakeFailed)
        );

        let mut initiator =
            SignerHandshake::initiator(&initiator_key, responder_key.public_key(), NETWORK)
                .unwrap();
        let mut wrong_identity =
            SignerHandshake::responder(&responder_key, attacker_key.public_key(), NETWORK).unwrap();
        let first = initiator.write_message().unwrap();
        assert_eq!(
            wrong_identity.read_message(&first),
            Err(SignerTransportError::HandshakeFailed)
        );

        let mut initiator =
            SignerHandshake::initiator(&initiator_key, responder_key.public_key(), NETWORK)
                .unwrap();
        let mut responder =
            SignerHandshake::responder(&responder_key, initiator_key.public_key(), NETWORK)
                .unwrap();
        let mut first = initiator.write_message().unwrap();
        *first.last_mut().unwrap() ^= 1;
        assert_eq!(
            responder.read_message(&first),
            Err(SignerTransportError::HandshakeFailed)
        );
    }
}
