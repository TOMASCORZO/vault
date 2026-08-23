use core::{fmt, str::FromStr};

use blake3::Hasher;
use snow::{Builder, HandshakeState, params::NoiseParams};
use subtle::ConstantTimeEq;

use crate::{SignerHandshake, SignerTransportError, SignerTransportKeyPair};

const PAIRING_PROLOGUE_DOMAIN: &[u8] = b"vault.signer.noise-xx.prologue.v1";
const PAIRING_FINGERPRINT_DOMAIN: &str = "vault.signer.pairing-fingerprint.v1";
const PAIRING_RECORD_MAGIC: [u8; 4] = *b"VSPR";
const PAIRING_RECORD_VERSION: u16 = 1;
const PAIRING_HANDSHAKE_BUFFER_BYTES: usize = 256;
const PAIRING_FINGERPRINT_BYTES: usize = 16;

/// Exact first-contact Noise profile selected for Vault signer pairing v1.
pub const SIGNER_PAIRING_NOISE_PROTOCOL: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
/// Fixed canonical byte length of one public paired-peer record.
pub const PAIRED_SIGNER_RECORD_BYTES: usize = 4 + 2 + 1 + 1 + 32 + 32 + 32 + 32 + 16;

/// Fail-closed first-contact pairing error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignerPairingError {
    /// Local key, network, protocol, or role configuration is invalid.
    InvalidConfiguration,
    /// The Noise XX handshake failed or was used out of order.
    HandshakeFailed,
    /// The out-of-band fingerprint comparison did not match.
    ConfirmationFailed,
    /// A persisted paired-peer record was malformed or inconsistent.
    InvalidRecord,
}

impl fmt::Display for SignerPairingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidConfiguration => "invalid signer pairing configuration",
            Self::HandshakeFailed => "signer pairing handshake failed",
            Self::ConfirmationFailed => "signer pairing confirmation failed",
            Self::InvalidRecord => "invalid paired signer record",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SignerPairingError {}

/// Stable role assigned during the first-contact ceremony and every later KK
/// connection. The coordinator initiates; the signer responds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SignerPairingRole {
    /// Transaction coordinator and Noise initiator.
    Coordinator = 0,
    /// Software/hardware signer and Noise responder.
    Signer = 1,
}

impl SignerPairingRole {
    fn from_byte(value: u8) -> Result<Self, SignerPairingError> {
        match value {
            0 => Ok(Self::Coordinator),
            1 => Ok(Self::Signer),
            _ => Err(SignerPairingError::InvalidRecord),
        }
    }
}

/// Human-verifiable 128-bit short authentication string for one exact XX
/// transcript and ordered identity pair.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PairingFingerprint([u8; PAIRING_FINGERPRINT_BYTES]);

impl PairingFingerprint {
    /// Restores the exact value entered/scanned through a trusted UI.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; PAIRING_FINGERPRINT_BYTES]) -> Self {
        Self(bytes)
    }

    /// Exact fingerprint bytes, suitable for an independently rendered QR.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; PAIRING_FINGERPRINT_BYTES] {
        self.0
    }

    /// Canonical four-group uppercase hexadecimal representation.
    #[must_use]
    pub fn human_code(self) -> String {
        use fmt::Write as _;

        let mut value = String::with_capacity(35);
        for (index, byte) in self.0.iter().enumerate() {
            if index != 0 && index % 4 == 0 {
                value.push('-');
            }
            write!(&mut value, "{byte:02X}").expect("writing into String cannot fail");
        }
        value
    }

    fn matches(self, other: Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl fmt::Debug for PairingFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingFingerprint(REDACTED)")
    }
}

impl fmt::Display for PairingFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.human_code())
    }
}

impl FromStr for PairingFingerprint {
    type Err = SignerPairingError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 35 {
            return Err(SignerPairingError::ConfirmationFailed);
        }
        let bytes = value.as_bytes();
        if bytes[8] != b'-' || bytes[17] != b'-' || bytes[26] != b'-' {
            return Err(SignerPairingError::ConfirmationFailed);
        }
        let mut decoded = [0; PAIRING_FINGERPRINT_BYTES];
        let mut source = 0;
        for output in &mut decoded {
            if source == 8 || source == 17 || source == 26 {
                source += 1;
            }
            let high = decode_hex(bytes[source])?;
            let low = decode_hex(bytes[source + 1])?;
            *output = (high << 4) | low;
            source += 2;
        }
        Ok(Self(decoded))
    }
}

fn decode_hex(value: u8) -> Result<u8, SignerPairingError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(SignerPairingError::ConfirmationFailed),
    }
}

/// In-progress three-flight Noise XX ceremony. XX authenticates possession of
/// the exchanged static keys, but not their real-world identity.
pub struct SignerPairingHandshake {
    state: HandshakeState,
    role: SignerPairingRole,
    network_id: [u8; 32],
    local_public: [u8; 32],
    failed: bool,
}

impl fmt::Debug for SignerPairingHandshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignerPairingHandshake")
            .field("role", &self.role)
            .field("finished", &self.state.is_handshake_finished())
            .finish_non_exhaustive()
    }
}

impl SignerPairingHandshake {
    /// Creates the coordinator/initiator side of a first-contact ceremony.
    pub fn coordinator(
        local: &SignerTransportKeyPair,
        network_id: [u8; 32],
    ) -> Result<Self, SignerPairingError> {
        Self::new(local, network_id, SignerPairingRole::Coordinator)
    }

    /// Creates the signer/responder side of a first-contact ceremony.
    pub fn signer(
        local: &SignerTransportKeyPair,
        network_id: [u8; 32],
    ) -> Result<Self, SignerPairingError> {
        Self::new(local, network_id, SignerPairingRole::Signer)
    }

    fn new(
        local: &SignerTransportKeyPair,
        network_id: [u8; 32],
        role: SignerPairingRole,
    ) -> Result<Self, SignerPairingError> {
        if network_id == [0; 32] || local.public_key() == [0; 32] {
            return Err(SignerPairingError::InvalidConfiguration);
        }
        let parameters: NoiseParams = SIGNER_PAIRING_NOISE_PROTOCOL
            .parse()
            .map_err(|_| SignerPairingError::InvalidConfiguration)?;
        let prologue = pairing_prologue(network_id);
        let builder = Builder::new(parameters)
            .local_private_key(local.private_bytes())
            .map_err(|_| SignerPairingError::InvalidConfiguration)?
            .prologue(&prologue)
            .map_err(|_| SignerPairingError::InvalidConfiguration)?;
        let state = match role {
            SignerPairingRole::Coordinator => builder.build_initiator(),
            SignerPairingRole::Signer => builder.build_responder(),
        }
        .map_err(|_| SignerPairingError::InvalidConfiguration)?;
        Ok(Self {
            state,
            role,
            network_id,
            local_public: local.public_key(),
            failed: false,
        })
    }

    /// Writes the next fixed empty-payload XX flight.
    pub fn write_message(&mut self) -> Result<Vec<u8>, SignerPairingError> {
        if self.failed || self.state.is_handshake_finished() || !self.state.is_my_turn() {
            return Err(SignerPairingError::HandshakeFailed);
        }
        let mut message = vec![0; PAIRING_HANDSHAKE_BUFFER_BYTES];
        let length = match self.state.write_message(&[], &mut message) {
            Ok(length) => length,
            Err(_) => {
                self.failed = true;
                return Err(SignerPairingError::HandshakeFailed);
            }
        };
        message.truncate(length);
        Ok(message)
    }

    /// Authenticates the next bounded XX flight. Negotiation payloads are
    /// forbidden so the application profile cannot be changed in-band.
    pub fn read_message(&mut self, message: &[u8]) -> Result<(), SignerPairingError> {
        if self.failed
            || self.state.is_handshake_finished()
            || self.state.is_my_turn()
            || message.len() > PAIRING_HANDSHAKE_BUFFER_BYTES
        {
            self.failed = true;
            return Err(SignerPairingError::HandshakeFailed);
        }
        let mut payload = [0; 1];
        let length = match self.state.read_message(message, &mut payload) {
            Ok(length) => length,
            Err(_) => {
                self.failed = true;
                return Err(SignerPairingError::HandshakeFailed);
            }
        };
        if length != 0 {
            self.failed = true;
            return Err(SignerPairingError::HandshakeFailed);
        }
        Ok(())
    }

    /// Ends the cryptographic exchange but deliberately returns an unconfirmed
    /// value that cannot create an application transport.
    pub fn finish(self) -> Result<UnconfirmedSignerPairing, SignerPairingError> {
        if self.failed || !self.state.is_handshake_finished() {
            return Err(SignerPairingError::HandshakeFailed);
        }
        let remote_public: [u8; 32] = self
            .state
            .get_remote_static()
            .ok_or(SignerPairingError::HandshakeFailed)?
            .try_into()
            .map_err(|_| SignerPairingError::HandshakeFailed)?;
        let pairing_hash: [u8; 32] = self
            .state
            .get_handshake_hash()
            .try_into()
            .map_err(|_| SignerPairingError::HandshakeFailed)?;
        if remote_public == [0; 32] || remote_public == self.local_public || pairing_hash == [0; 32]
        {
            return Err(SignerPairingError::HandshakeFailed);
        }
        let fingerprint = derive_pairing_fingerprint(
            self.network_id,
            self.role,
            self.local_public,
            remote_public,
            pairing_hash,
        );
        Ok(UnconfirmedSignerPairing {
            role: self.role,
            network_id: self.network_id,
            local_public: self.local_public,
            remote_public,
            pairing_hash,
            fingerprint,
        })
    }
}

/// Completed XX transcript awaiting a human-authenticated comparison. This
/// type intentionally exposes no method for opening the KK application channel.
pub struct UnconfirmedSignerPairing {
    role: SignerPairingRole,
    network_id: [u8; 32],
    local_public: [u8; 32],
    remote_public: [u8; 32],
    pairing_hash: [u8; 32],
    fingerprint: PairingFingerprint,
}

impl fmt::Debug for UnconfirmedSignerPairing {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnconfirmedSignerPairing")
            .field("role", &self.role)
            .field("cryptographic_state", &"REDACTED")
            .finish()
    }
}

impl UnconfirmedSignerPairing {
    /// Fingerprint that MUST be compared through an authenticated independent
    /// path or visually on both devices before confirmation.
    #[must_use]
    pub const fn fingerprint(&self) -> PairingFingerprint {
        self.fingerprint
    }

    /// Converts this one-shot unconfirmed transcript into a persistent record
    /// only when the independently obtained value matches in constant time.
    pub fn confirm(
        self,
        independently_observed: PairingFingerprint,
    ) -> Result<PairedSignerRecord, SignerPairingError> {
        if !self.fingerprint.matches(independently_observed) {
            return Err(SignerPairingError::ConfirmationFailed);
        }
        Ok(PairedSignerRecord {
            role: self.role,
            network_id: self.network_id,
            local_public: self.local_public,
            remote_public: self.remote_public,
            pairing_hash: self.pairing_hash,
            fingerprint: self.fingerprint,
        })
    }
}

/// Public metadata for one OOB-confirmed signer relationship. It contains no
/// private key and MUST still live inside authenticated wallet storage.
#[derive(Clone, Eq, PartialEq)]
pub struct PairedSignerRecord {
    role: SignerPairingRole,
    network_id: [u8; 32],
    local_public: [u8; 32],
    remote_public: [u8; 32],
    pairing_hash: [u8; 32],
    fingerprint: PairingFingerprint,
}

impl fmt::Debug for PairedSignerRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairedSignerRecord")
            .field("role", &self.role)
            .field("peer_metadata", &"REDACTED")
            .finish()
    }
}

impl PairedSignerRecord {
    /// Role fixed by the confirmed ceremony.
    #[must_use]
    pub const fn role(&self) -> SignerPairingRole {
        self.role
    }

    /// Vault network to which the relationship is cryptographically bound.
    #[must_use]
    pub const fn network_id(&self) -> [u8; 32] {
        self.network_id
    }

    /// Local X25519 identity to which this record is pinned.
    #[must_use]
    pub const fn local_public_key(&self) -> [u8; 32] {
        self.local_public
    }

    /// Confirmed remote X25519 identity.
    #[must_use]
    pub const fn remote_public_key(&self) -> [u8; 32] {
        self.remote_public
    }

    /// Fingerprint retained for peer-management UI and revocation records.
    #[must_use]
    pub const fn fingerprint(&self) -> PairingFingerprint {
        self.fingerprint
    }

    /// Exact fixed-size public record codec for authenticated wallet storage.
    #[must_use]
    pub fn encode(&self) -> [u8; PAIRED_SIGNER_RECORD_BYTES] {
        let mut bytes = [0; PAIRED_SIGNER_RECORD_BYTES];
        bytes[..4].copy_from_slice(&PAIRING_RECORD_MAGIC);
        bytes[4..6].copy_from_slice(&PAIRING_RECORD_VERSION.to_le_bytes());
        bytes[6] = self.role as u8;
        bytes[7] = 0;
        bytes[8..40].copy_from_slice(&self.network_id);
        bytes[40..72].copy_from_slice(&self.local_public);
        bytes[72..104].copy_from_slice(&self.remote_public);
        bytes[104..136].copy_from_slice(&self.pairing_hash);
        bytes[136..152].copy_from_slice(&self.fingerprint.0);
        bytes
    }

    /// Parses a record and recomputes its transcript-derived fingerprint.
    pub fn decode(bytes: &[u8]) -> Result<Self, SignerPairingError> {
        if bytes.len() != PAIRED_SIGNER_RECORD_BYTES
            || bytes[..4] != PAIRING_RECORD_MAGIC
            || u16::from_le_bytes(
                bytes[4..6]
                    .try_into()
                    .map_err(|_| SignerPairingError::InvalidRecord)?,
            ) != PAIRING_RECORD_VERSION
            || bytes[7] != 0
        {
            return Err(SignerPairingError::InvalidRecord);
        }
        let role = SignerPairingRole::from_byte(bytes[6])?;
        let network_id = bytes[8..40]
            .try_into()
            .map_err(|_| SignerPairingError::InvalidRecord)?;
        let local_public = bytes[40..72]
            .try_into()
            .map_err(|_| SignerPairingError::InvalidRecord)?;
        let remote_public = bytes[72..104]
            .try_into()
            .map_err(|_| SignerPairingError::InvalidRecord)?;
        let pairing_hash = bytes[104..136]
            .try_into()
            .map_err(|_| SignerPairingError::InvalidRecord)?;
        let encoded_fingerprint = PairingFingerprint::from_bytes(
            bytes[136..152]
                .try_into()
                .map_err(|_| SignerPairingError::InvalidRecord)?,
        );
        if network_id == [0; 32]
            || local_public == [0; 32]
            || remote_public == [0; 32]
            || local_public == remote_public
            || pairing_hash == [0; 32]
        {
            return Err(SignerPairingError::InvalidRecord);
        }
        let fingerprint =
            derive_pairing_fingerprint(network_id, role, local_public, remote_public, pairing_hash);
        if !fingerprint.matches(encoded_fingerprint) {
            return Err(SignerPairingError::InvalidRecord);
        }
        Ok(Self {
            role,
            network_id,
            local_public,
            remote_public,
            pairing_hash,
            fingerprint,
        })
    }

    /// Opens the production KK handshake only when the protected local key
    /// matches the identity fixed by this confirmed record.
    pub(crate) fn open_handshake(
        &self,
        local: &SignerTransportKeyPair,
    ) -> Result<SignerHandshake, SignerPairingError> {
        if !bool::from(local.public_key().ct_eq(&self.local_public)) {
            return Err(SignerPairingError::InvalidRecord);
        }
        let result = match self.role {
            SignerPairingRole::Coordinator => {
                SignerHandshake::initiator(local, self.remote_public, self.network_id)
            }
            SignerPairingRole::Signer => {
                SignerHandshake::responder(local, self.remote_public, self.network_id)
            }
        };
        result.map_err(map_transport_error)
    }
}

fn map_transport_error(_: SignerTransportError) -> SignerPairingError {
    SignerPairingError::InvalidRecord
}

fn pairing_prologue(network_id: [u8; 32]) -> Vec<u8> {
    let mut value = Vec::with_capacity(PAIRING_PROLOGUE_DOMAIN.len() + 32);
    value.extend_from_slice(PAIRING_PROLOGUE_DOMAIN);
    value.extend_from_slice(&network_id);
    value
}

fn derive_pairing_fingerprint(
    network_id: [u8; 32],
    role: SignerPairingRole,
    local_public: [u8; 32],
    remote_public: [u8; 32],
    pairing_hash: [u8; 32],
) -> PairingFingerprint {
    let (coordinator_public, signer_public) = match role {
        SignerPairingRole::Coordinator => (local_public, remote_public),
        SignerPairingRole::Signer => (remote_public, local_public),
    };
    let mut hasher = Hasher::new_derive_key(PAIRING_FINGERPRINT_DOMAIN);
    hasher.update(SIGNER_PAIRING_NOISE_PROTOCOL.as_bytes());
    hasher.update(&network_id);
    hasher.update(&pairing_hash);
    hasher.update(&coordinator_public);
    hasher.update(&signer_public);
    let digest = hasher.finalize();
    let mut fingerprint = [0; PAIRING_FINGERPRINT_BYTES];
    fingerprint.copy_from_slice(&digest.as_bytes()[..PAIRING_FINGERPRINT_BYTES]);
    PairingFingerprint(fingerprint)
}
