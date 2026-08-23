//! Fail-closed signer reconstruction for one Ironwood output.
//!
//! The authorization packet contains wallet-private note construction data and
//! MUST travel only over an authenticated confidential channel. Its fixed codec
//! is intended for local, hardware, multisignature, and delegated-prover
//! transports; it is never a consensus or block encoding.

use core::fmt;

use orchard::{
    Note, NoteVersion,
    keys::Scope,
    note::{ExtractedNoteCommitment, RandomSeed, Rho},
    note_encryption::{IronwoodDomain, IronwoodNoteEncryption},
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
};
use rand_core::{Error as RngError, RngCore};
use subtle::ConstantTimeEq;
use zcash_note_encryption::Domain;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    ActionNullifier, EncryptedNote, KeyScope, MEMO_BYTES, NOTE_CIPHERTEXT_BYTES,
    OUTGOING_CIPHERTEXT_BYTES, PreparedNoteOutput, VaultAddress, VaultFullViewingKey,
};

const PACKET_MAGIC: [u8; 4] = *b"VAOP";
const PACKET_VERSION: u16 = 1;
const PACKET_DIGEST_DOMAIN: &str = "vault.privacy.output-authorization.packet.v1";
const SIGNER_FINGERPRINT_DOMAIN: &str = "vault.privacy.output-authorization.signer.2026-08-22";

/// Exact fixed-size binary representation of one private output-authorization
/// packet.
pub const OUTPUT_AUTHORIZATION_PACKET_BYTES: usize = 4
    + 2
    + 32
    + 1
    + 1
    + 43
    + 8
    + 32
    + 32
    + MEMO_BYTES
    + 32
    + 32
    + 32
    + 32
    + NOTE_CIPHERTEXT_BYTES
    + OUTGOING_CIPHERTEXT_BYTES;

/// Signer-approved purpose of an output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OutputKind {
    /// Non-zero payment whose value participates in the mandatory burn base.
    ExternalPayment = 0,
    /// Non-zero output to this signer's internal address.
    InternalChange = 1,
    /// Zero-valued padded output to this signer's internal address.
    Dummy = 2,
}

impl OutputKind {
    fn from_byte(value: u8) -> Result<Self, OutputAuthorizationError> {
        match value {
            0 => Ok(Self::ExternalPayment),
            1 => Ok(Self::InternalChange),
            2 => Ok(Self::Dummy),
            _ => Err(OutputAuthorizationError::InvalidEncoding),
        }
    }

    fn validate_value(self, value: u64) -> Result<(), OutputAuthorizationError> {
        match (self, value) {
            (Self::ExternalPayment | Self::InternalChange, 0) | (Self::Dummy, 1..) => {
                Err(OutputAuthorizationError::InvalidClassification)
            }
            _ => Ok(()),
        }
    }
}

/// Detailed local signing failures. These errors never cross the consensus
/// boundary and do not reveal packet secrets through their messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputAuthorizationError {
    /// Packet length, magic, version, scope, or classification is invalid.
    InvalidEncoding,
    /// The all-zero network domain is reserved.
    ZeroNetworkId,
    /// Packet and signer-approved network differ.
    NetworkMismatch,
    /// Packet fields differ from the signer-approved private intent.
    IntentMismatch,
    /// The transaction output differs from the packet's exact public output.
    OutputMismatch,
    /// Output kind and value do not form an allowed payment/change/dummy pair.
    InvalidClassification,
    /// Change or dummy output is not owned by the signer's internal capability.
    WrongChangeRecipient,
    /// `rho`, `rseed`, or the V3 note construction is invalid.
    InvalidNote,
    /// The output-value trapdoor is zero or non-canonical.
    InvalidValueTrapdoor,
    /// The reconstructed note commitment differs from the public output.
    NoteCommitmentMismatch,
    /// The reconstructed output value commitment differs from the public output.
    ValueCommitmentMismatch,
    /// The deterministic Ironwood ephemeral key differs from the public output.
    EphemeralKeyMismatch,
    /// The deterministic authenticated recipient ciphertext differs.
    RecipientCiphertextMismatch,
    /// The deterministic authenticated sender-recovery ciphertext differs.
    OutgoingCiphertextMismatch,
}

impl fmt::Display for OutputAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidEncoding => "invalid output-authorization packet encoding",
            Self::ZeroNetworkId => "output authorization uses the zero network",
            Self::NetworkMismatch => "output authorization belongs to another network",
            Self::IntentMismatch => "output authorization differs from approved intent",
            Self::OutputMismatch => "output authorization differs from transaction effects",
            Self::InvalidClassification => "invalid output authorization classification",
            Self::WrongChangeRecipient => "change output is not signer-owned internal change",
            Self::InvalidNote => "invalid output authorization note",
            Self::InvalidValueTrapdoor => "invalid output value-commitment trapdoor",
            Self::NoteCommitmentMismatch => "output note commitment mismatch",
            Self::ValueCommitmentMismatch => "output value commitment mismatch",
            Self::EphemeralKeyMismatch => "output ephemeral key mismatch",
            Self::RecipientCiphertextMismatch => "recipient ciphertext mismatch",
            Self::OutgoingCiphertextMismatch => "outgoing ciphertext mismatch",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for OutputAuthorizationError {}

/// Private intent approved by a signer or hardware-wallet UI.
///
/// It is deliberately separate from coordinator-supplied ciphertext bytes.
/// Debug output and drop behavior never expose the recipient, amount, or memo.
pub struct OutputAuthorizationIntent {
    network_id: [u8; 32],
    sender_scope: KeyScope,
    kind: OutputKind,
    recipient: VaultAddress,
    value: u64,
    action_nullifier: ActionNullifier,
    memo: Zeroizing<[u8; MEMO_BYTES]>,
}

impl fmt::Debug for OutputAuthorizationIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutputAuthorizationIntent")
            .field("kind", &self.kind)
            .field("private_fields", &"REDACTED")
            .finish()
    }
}

impl Drop for OutputAuthorizationIntent {
    fn drop(&mut self) {
        self.network_id.zeroize();
        self.recipient.0.zeroize();
        self.value.zeroize();
        self.action_nullifier.0.zeroize();
    }
}

impl OutputAuthorizationIntent {
    /// Creates an exact user-approved intent. Non-dummy outputs must be
    /// non-zero; dummy outputs must be zero.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network_id: [u8; 32],
        sender_scope: KeyScope,
        kind: OutputKind,
        recipient: VaultAddress,
        value: u64,
        action_nullifier: ActionNullifier,
        memo: [u8; MEMO_BYTES],
    ) -> Result<Self, OutputAuthorizationError> {
        if network_id == [0; 32] {
            return Err(OutputAuthorizationError::ZeroNetworkId);
        }
        kind.validate_value(value)?;
        Ok(Self {
            network_id,
            sender_scope,
            kind,
            recipient,
            value,
            action_nullifier,
            memo: Zeroizing::new(memo),
        })
    }
}

/// Fixed-size wallet-private packet supplied by a transaction constructor to a
/// signer for independent reconstruction.
pub struct OutputAuthorizationPacket {
    network_id: [u8; 32],
    sender_scope: KeyScope,
    kind: OutputKind,
    recipient: VaultAddress,
    value: u64,
    action_nullifier: ActionNullifier,
    rseed: Zeroizing<[u8; 32]>,
    memo: Zeroizing<[u8; MEMO_BYTES]>,
    value_commitment_trapdoor: Zeroizing<[u8; 32]>,
    output: EncryptedNote,
}

impl fmt::Debug for OutputAuthorizationPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutputAuthorizationPacket")
            .field("encoded_bytes", &OUTPUT_AUTHORIZATION_PACKET_BYTES)
            .field("private_fields", &"REDACTED")
            .finish()
    }
}

impl Drop for OutputAuthorizationPacket {
    fn drop(&mut self) {
        self.network_id.zeroize();
        self.recipient.0.zeroize();
        self.value.zeroize();
        self.action_nullifier.0.zeroize();
    }
}

impl PreparedNoteOutput {
    /// Exports the exact private construction data for an independently
    /// validating signer. The result must only cross an authenticated,
    /// confidential wallet channel.
    pub fn authorization_packet(
        &self,
        network_id: [u8; 32],
        kind: OutputKind,
    ) -> Result<OutputAuthorizationPacket, OutputAuthorizationError> {
        if network_id == [0; 32] {
            return Err(OutputAuthorizationError::ZeroNetworkId);
        }
        kind.validate_value(self.note.value)?;
        Ok(OutputAuthorizationPacket {
            network_id,
            sender_scope: self.sender_scope,
            kind,
            recipient: self.note.recipient,
            value: self.note.value,
            action_nullifier: ActionNullifier::from_bytes(self.note.rho)
                .map_err(|_| OutputAuthorizationError::InvalidNote)?,
            rseed: Zeroizing::new(*self.note.rseed),
            memo: Zeroizing::new(*self.memo),
            value_commitment_trapdoor: Zeroizing::new(*self.value_commitment_trapdoor),
            output: self.output.clone(),
        })
    }
}

impl OutputAuthorizationPacket {
    /// Serializes one exact, non-extensible packet. The returned allocation is
    /// zeroized when dropped.
    #[must_use]
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(OUTPUT_AUTHORIZATION_PACKET_BYTES));
        bytes.extend_from_slice(&PACKET_MAGIC);
        bytes.extend_from_slice(&PACKET_VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.network_id);
        bytes.push(scope_byte(self.sender_scope));
        bytes.push(self.kind as u8);
        bytes.extend_from_slice(&self.recipient.0);
        bytes.extend_from_slice(&self.value.to_le_bytes());
        bytes.extend_from_slice(&self.action_nullifier.0);
        bytes.extend_from_slice(&self.rseed[..]);
        bytes.extend_from_slice(&self.memo[..]);
        bytes.extend_from_slice(&self.value_commitment_trapdoor[..]);
        bytes.extend_from_slice(&self.output.note_commitment);
        bytes.extend_from_slice(&self.output.value_commitment);
        bytes.extend_from_slice(&self.output.ephemeral_key);
        bytes.extend_from_slice(&self.output.note_ciphertext);
        bytes.extend_from_slice(&self.output.outgoing_ciphertext);
        debug_assert_eq!(bytes.len(), OUTPUT_AUTHORIZATION_PACKET_BYTES);
        bytes
    }

    /// Parses the exact fixed-size signer packet and rejects trailing bytes,
    /// unknown versions, invalid classifications, and malformed public fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, OutputAuthorizationError> {
        if bytes.len() != OUTPUT_AUTHORIZATION_PACKET_BYTES {
            return Err(OutputAuthorizationError::InvalidEncoding);
        }
        let mut offset = 0;
        if take::<4>(bytes, &mut offset)? != PACKET_MAGIC
            || u16::from_le_bytes(take(bytes, &mut offset)?) != PACKET_VERSION
        {
            return Err(OutputAuthorizationError::InvalidEncoding);
        }
        let network_id = take(bytes, &mut offset)?;
        if network_id == [0; 32] {
            return Err(OutputAuthorizationError::ZeroNetworkId);
        }
        let sender_scope = scope_from_byte(take::<1>(bytes, &mut offset)?[0])?;
        let kind = OutputKind::from_byte(take::<1>(bytes, &mut offset)?[0])?;
        let recipient = VaultAddress::from_bytes(take(bytes, &mut offset)?)
            .map_err(|_| OutputAuthorizationError::InvalidEncoding)?;
        let value = u64::from_le_bytes(take(bytes, &mut offset)?);
        kind.validate_value(value)?;
        let action_nullifier = ActionNullifier::from_bytes(take(bytes, &mut offset)?)
            .map_err(|_| OutputAuthorizationError::InvalidEncoding)?;
        let rseed = Zeroizing::new(take(bytes, &mut offset)?);
        let memo = Zeroizing::new(take(bytes, &mut offset)?);
        let value_commitment_trapdoor = Zeroizing::new(take(bytes, &mut offset)?);
        let note_commitment = take(bytes, &mut offset)?;
        let value_commitment = take(bytes, &mut offset)?;
        let ephemeral_key = take(bytes, &mut offset)?;
        let note_ciphertext = take(bytes, &mut offset)?;
        let outgoing_ciphertext = take(bytes, &mut offset)?;
        if offset != bytes.len() {
            return Err(OutputAuthorizationError::InvalidEncoding);
        }
        let output = EncryptedNote::from_parts(
            note_commitment,
            value_commitment,
            ephemeral_key,
            note_ciphertext,
            outgoing_ciphertext,
        )
        .map_err(|_| OutputAuthorizationError::InvalidEncoding)?;
        Ok(Self {
            network_id,
            sender_scope,
            kind,
            recipient,
            value,
            action_nullifier,
            rseed,
            memo,
            value_commitment_trapdoor,
            output,
        })
    }

    /// Reconstructs every output component from signer-approved intent and
    /// returns an opaque token only after exact equality succeeds.
    pub fn verify(
        &self,
        full_viewing_key: &VaultFullViewingKey,
        intent: &OutputAuthorizationIntent,
        expected_output: &EncryptedNote,
        maximum_value: u64,
    ) -> Result<VerifiedOutputAuthorization, OutputAuthorizationError> {
        if self.network_id != intent.network_id {
            return Err(OutputAuthorizationError::NetworkMismatch);
        }
        if self.sender_scope != intent.sender_scope
            || self.kind != intent.kind
            || self.recipient != intent.recipient
            || self.value != intent.value
            || self.action_nullifier != intent.action_nullifier
            || self.memo[..] != intent.memo[..]
        {
            return Err(OutputAuthorizationError::IntentMismatch);
        }
        if self.value > maximum_value {
            return Err(OutputAuthorizationError::InvalidClassification);
        }
        self.kind.validate_value(self.value)?;
        if self.output != *expected_output {
            return Err(OutputAuthorizationError::OutputMismatch);
        }
        if matches!(self.kind, OutputKind::InternalChange | OutputKind::Dummy)
            && full_viewing_key
                .orchard()
                .scope_for_address(&self.recipient.orchard())
                != Some(Scope::Internal)
        {
            return Err(OutputAuthorizationError::WrongChangeRecipient);
        }

        let rho = Option::<Rho>::from(Rho::from_bytes(&self.action_nullifier.0))
            .ok_or(OutputAuthorizationError::InvalidNote)?;
        let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(*self.rseed, &rho))
            .ok_or(OutputAuthorizationError::InvalidNote)?;
        let note = Option::<Note>::from(Note::from_parts(
            self.recipient.orchard(),
            NoteValue::from_raw(self.value),
            rho,
            rseed,
            NoteVersion::V3,
        ))
        .ok_or(OutputAuthorizationError::InvalidNote)?;
        let note_commitment = ExtractedNoteCommitment::from(note.commitment());
        if note_commitment.to_bytes() != self.output.note_commitment {
            return Err(OutputAuthorizationError::NoteCommitmentMismatch);
        }

        if self.value_commitment_trapdoor.as_ref() == [0; 32] {
            return Err(OutputAuthorizationError::InvalidValueTrapdoor);
        }
        let trapdoor = Option::<ValueCommitTrapdoor>::from(ValueCommitTrapdoor::from_bytes(
            *self.value_commitment_trapdoor,
        ))
        .ok_or(OutputAuthorizationError::InvalidValueTrapdoor)?;
        let value_commitment =
            ValueCommitment::derive(NoteValue::from_raw(self.value) - NoteValue::ZERO, trapdoor);
        if value_commitment.to_bytes() != self.output.value_commitment {
            return Err(OutputAuthorizationError::ValueCommitmentMismatch);
        }

        let outgoing_viewing_key = full_viewing_key.orchard().to_ovk(self.sender_scope.into());
        let encryptor = IronwoodNoteEncryption::new(Some(outgoing_viewing_key), note, *self.memo);
        if IronwoodDomain::epk_bytes(encryptor.epk()).0 != self.output.ephemeral_key {
            return Err(OutputAuthorizationError::EphemeralKeyMismatch);
        }
        if encryptor.encrypt_note_plaintext() != self.output.note_ciphertext {
            return Err(OutputAuthorizationError::RecipientCiphertextMismatch);
        }
        let mut unused_rng = ZeroRng;
        if encryptor.encrypt_outgoing_plaintext(
            &value_commitment,
            &note_commitment,
            &mut unused_rng,
        ) != self.output.outgoing_ciphertext
        {
            return Err(OutputAuthorizationError::OutgoingCiphertextMismatch);
        }

        Ok(VerifiedOutputAuthorization {
            network_id: self.network_id,
            action_nullifier: self.action_nullifier,
            output: self.output.clone(),
            kind: self.kind,
            packet_digest: self.transport_digest(),
            signer_fingerprint: signer_fingerprint(full_viewing_key),
        })
    }

    /// Domain-separated digest used only to bind this secret packet into an
    /// authenticated signer-session transcript.
    #[must_use]
    pub fn transport_digest(&self) -> [u8; 32] {
        let encoded = self.encode();
        let mut hasher = blake3::Hasher::new_derive_key(PACKET_DIGEST_DOMAIN);
        hasher.update(encoded.as_ref());
        *hasher.finalize().as_bytes()
    }
}

/// Opaque proof that one output packet matched signer-approved intent and was
/// independently reconstructed under a specific full viewing key.
pub struct VerifiedOutputAuthorization {
    network_id: [u8; 32],
    action_nullifier: ActionNullifier,
    output: EncryptedNote,
    kind: OutputKind,
    packet_digest: [u8; 32],
    signer_fingerprint: [u8; 32],
}

impl fmt::Debug for VerifiedOutputAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedOutputAuthorization")
            .field("kind", &self.kind)
            .field("private_authorizer", &"REDACTED")
            .finish_non_exhaustive()
    }
}

impl Drop for VerifiedOutputAuthorization {
    fn drop(&mut self) {
        self.signer_fingerprint.zeroize();
    }
}

impl VerifiedOutputAuthorization {
    /// Network whose exact transfer effects may consume this token.
    #[must_use]
    pub const fn network_id(&self) -> [u8; 32] {
        self.network_id
    }

    /// Approved payment/change/dummy classification.
    #[must_use]
    pub const fn kind(&self) -> OutputKind {
        self.kind
    }

    /// Whether this token covers the exact canonical action output.
    #[must_use]
    pub fn matches_action(
        &self,
        action_nullifier: ActionNullifier,
        output: &EncryptedNote,
    ) -> bool {
        self.action_nullifier == action_nullifier && self.output == *output
    }

    /// Whether the token was reconstructed under this exact full viewing key.
    #[must_use]
    pub fn verified_for(&self, full_viewing_key: &VaultFullViewingKey) -> bool {
        let mut expected = signer_fingerprint(full_viewing_key);
        let matches = self.signer_fingerprint.ct_eq(&expected).into();
        expected.zeroize();
        matches
    }

    /// Digest of the exact private packet independently reconstructed to mint
    /// this token. It is safe only inside the authenticated signer transcript.
    #[must_use]
    pub const fn packet_digest(&self) -> [u8; 32] {
        self.packet_digest
    }
}

fn signer_fingerprint(full_viewing_key: &VaultFullViewingKey) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(SIGNER_FINGERPRINT_DOMAIN);
    let bytes = full_viewing_key.export();
    hasher.update(bytes.as_ref());
    *hasher.finalize().as_bytes()
}

fn scope_byte(scope: KeyScope) -> u8 {
    match scope {
        KeyScope::External => 0,
        KeyScope::Internal => 1,
    }
}

fn scope_from_byte(value: u8) -> Result<KeyScope, OutputAuthorizationError> {
    match value {
        0 => Ok(KeyScope::External),
        1 => Ok(KeyScope::Internal),
        _ => Err(OutputAuthorizationError::InvalidEncoding),
    }
}

fn take<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], OutputAuthorizationError> {
    let end = offset
        .checked_add(N)
        .ok_or(OutputAuthorizationError::InvalidEncoding)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(OutputAuthorizationError::InvalidEncoding)?
        .try_into()
        .map_err(|_| OutputAuthorizationError::InvalidEncoding)?;
    *offset = end;
    Ok(value)
}

/// Deterministic placeholder for an API whose `ovk = Some` branch consumes no
/// randomness. The exact dependency is pinned; output reconstruction tests
/// would fail if this assumption changed.
struct ZeroRng;

impl RngCore for ZeroRng {
    fn next_u32(&mut self) -> u32 {
        0
    }

    fn next_u64(&mut self) -> u64 {
        0
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        destination.fill(0);
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
        self.fill_bytes(destination);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

    use super::*;
    use crate::{KeyScope, PreparedNoteOutput, VaultSpendingKey};

    const NETWORK: [u8; 32] = [0x31; 32];
    const MAXIMUM_VALUE: u64 = 21_000_000 * 1_000_000_000;
    const MEMO: [u8; MEMO_BYTES] = [0x4d; MEMO_BYTES];

    struct Fixture {
        full_viewing_key: VaultFullViewingKey,
        prepared: PreparedNoteOutput,
        intent: OutputAuthorizationIntent,
    }

    fn make_fixture(kind: OutputKind) -> Fixture {
        let spending_key = VaultSpendingKey::derive(&[0x91; 32], NETWORK, 0).unwrap();
        let full_viewing_key = spending_key.full_viewing_key();
        let recipient = match kind {
            OutputKind::ExternalPayment => VaultSpendingKey::derive(&[0x92; 32], NETWORK, 0)
                .unwrap()
                .full_viewing_key()
                .address_at(7, KeyScope::External),
            OutputKind::InternalChange | OutputKind::Dummy => {
                full_viewing_key.address_at(11, KeyScope::Internal)
            }
        };
        let value = match kind {
            OutputKind::Dummy => 0,
            OutputKind::ExternalPayment | OutputKind::InternalChange => 1_234,
        };
        let action_nullifier = ActionNullifier::from_bytes([3; 32]).unwrap();
        let mut rng = ChaCha20Rng::from_seed([0xa4; 32]);
        let prepared = PreparedNoteOutput::create(
            &full_viewing_key,
            KeyScope::External,
            recipient,
            value,
            MAXIMUM_VALUE,
            action_nullifier,
            MEMO,
            &mut rng,
        )
        .unwrap();
        let intent = OutputAuthorizationIntent::new(
            NETWORK,
            KeyScope::External,
            kind,
            recipient,
            value,
            action_nullifier,
            MEMO,
        )
        .unwrap();
        Fixture {
            full_viewing_key,
            prepared,
            intent,
        }
    }

    fn verify_fixture(
        fixture: &Fixture,
        packet: &OutputAuthorizationPacket,
    ) -> Result<VerifiedOutputAuthorization, OutputAuthorizationError> {
        packet.verify(
            &fixture.full_viewing_key,
            &fixture.intent,
            fixture.prepared.encrypted_note(),
            MAXIMUM_VALUE,
        )
    }

    #[test]
    fn fixed_packet_round_trip_reconstructs_every_output_component() {
        let fixture = make_fixture(OutputKind::ExternalPayment);
        let packet = fixture
            .prepared
            .authorization_packet(NETWORK, OutputKind::ExternalPayment)
            .unwrap();
        let encoded = packet.encode();
        assert_eq!(encoded.len(), OUTPUT_AUTHORIZATION_PACKET_BYTES);
        let digest = blake3::hash(encoded.as_ref());
        assert_eq!(
            digest.to_hex().as_str(),
            "9d865241263d1f25c8c31592197dc7d0857c822f5c4614aaed970773e6154123"
        );

        let decoded = OutputAuthorizationPacket::decode(encoded.as_ref()).unwrap();
        let verified = verify_fixture(&fixture, &decoded).unwrap();
        assert_eq!(verified.network_id(), NETWORK);
        assert_eq!(verified.kind(), OutputKind::ExternalPayment);
        assert!(verified.matches_action(
            fixture.prepared.note().action_nullifier().unwrap(),
            fixture.prepared.encrypted_note(),
        ));
        assert!(verified.verified_for(&fixture.full_viewing_key));

        let wrong_viewing_key = VaultSpendingKey::derive(&[0x93; 32], NETWORK, 0)
            .unwrap()
            .full_viewing_key();
        assert!(!verified.verified_for(&wrong_viewing_key));
        assert!(!format!("{packet:?}").contains("1234"));
        assert!(!format!("{:?}", fixture.intent).contains("1234"));
    }

    #[test]
    fn codec_rejects_noncanonical_boundaries() {
        let fixture = make_fixture(OutputKind::ExternalPayment);
        let packet = fixture
            .prepared
            .authorization_packet(NETWORK, OutputKind::ExternalPayment)
            .unwrap();
        let encoded = packet.encode();

        assert_eq!(
            OutputAuthorizationPacket::decode(&encoded[..encoded.len() - 1]).unwrap_err(),
            OutputAuthorizationError::InvalidEncoding
        );
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert_eq!(
            OutputAuthorizationPacket::decode(&trailing).unwrap_err(),
            OutputAuthorizationError::InvalidEncoding
        );
        for (offset, expected) in [
            (0, OutputAuthorizationError::InvalidEncoding),
            (4, OutputAuthorizationError::InvalidEncoding),
            (6, OutputAuthorizationError::ZeroNetworkId),
            (38, OutputAuthorizationError::InvalidEncoding),
            (39, OutputAuthorizationError::InvalidEncoding),
        ] {
            let mut changed = encoded.to_vec();
            if offset == 6 {
                changed[offset..offset + 32].fill(0);
            } else {
                changed[offset] = 0xff;
            }
            assert_eq!(
                OutputAuthorizationPacket::decode(&changed).unwrap_err(),
                expected
            );
        }
    }

    #[test]
    fn signer_rejects_intent_network_owner_and_policy_mismatches() {
        let fixture = make_fixture(OutputKind::ExternalPayment);
        let mut packet = fixture
            .prepared
            .authorization_packet(NETWORK, OutputKind::ExternalPayment)
            .unwrap();
        packet.network_id = [0x32; 32];
        assert_eq!(
            verify_fixture(&fixture, &packet).unwrap_err(),
            OutputAuthorizationError::NetworkMismatch
        );

        let fixture = make_fixture(OutputKind::ExternalPayment);
        let mut packet = fixture
            .prepared
            .authorization_packet(NETWORK, OutputKind::ExternalPayment)
            .unwrap();
        packet.value += 1;
        assert_eq!(
            verify_fixture(&fixture, &packet).unwrap_err(),
            OutputAuthorizationError::IntentMismatch
        );

        let fixture = make_fixture(OutputKind::InternalChange);
        let packet = fixture
            .prepared
            .authorization_packet(NETWORK, OutputKind::InternalChange)
            .unwrap();
        let wrong_viewing_key = VaultSpendingKey::derive(&[0x94; 32], NETWORK, 0)
            .unwrap()
            .full_viewing_key();
        assert_eq!(
            packet
                .verify(
                    &wrong_viewing_key,
                    &fixture.intent,
                    fixture.prepared.encrypted_note(),
                    MAXIMUM_VALUE,
                )
                .unwrap_err(),
            OutputAuthorizationError::WrongChangeRecipient
        );

        let fixture = make_fixture(OutputKind::ExternalPayment);
        let packet = fixture
            .prepared
            .authorization_packet(NETWORK, OutputKind::ExternalPayment)
            .unwrap();
        assert_eq!(
            packet
                .verify(
                    &fixture.full_viewing_key,
                    &fixture.intent,
                    fixture.prepared.encrypted_note(),
                    1_000,
                )
                .unwrap_err(),
            OutputAuthorizationError::InvalidClassification
        );
    }

    #[test]
    fn every_private_or_public_output_mutation_fails_closed() {
        let fixture = make_fixture(OutputKind::ExternalPayment);
        let mut packet = fixture
            .prepared
            .authorization_packet(NETWORK, OutputKind::ExternalPayment)
            .unwrap();
        packet.rseed[0] ^= 1;
        assert_eq!(
            verify_fixture(&fixture, &packet).unwrap_err(),
            OutputAuthorizationError::NoteCommitmentMismatch
        );

        let mut fixture = make_fixture(OutputKind::ExternalPayment);
        let mut packet = fixture
            .prepared
            .authorization_packet(NETWORK, OutputKind::ExternalPayment)
            .unwrap();
        packet.memo[0] ^= 1;
        fixture.intent.memo[0] ^= 1;
        assert_eq!(
            verify_fixture(&fixture, &packet).unwrap_err(),
            OutputAuthorizationError::RecipientCiphertextMismatch
        );

        let fixture = make_fixture(OutputKind::ExternalPayment);
        let mut packet = fixture
            .prepared
            .authorization_packet(NETWORK, OutputKind::ExternalPayment)
            .unwrap();
        packet.value_commitment_trapdoor[0] ^= 1;
        assert_eq!(
            verify_fixture(&fixture, &packet).unwrap_err(),
            OutputAuthorizationError::ValueCommitmentMismatch
        );

        let fixture = make_fixture(OutputKind::ExternalPayment);
        let mut packet = fixture
            .prepared
            .authorization_packet(NETWORK, OutputKind::ExternalPayment)
            .unwrap();
        packet.output.note_commitment[0] ^= 1;
        let expected = packet.output.clone();
        assert_eq!(
            packet
                .verify(
                    &fixture.full_viewing_key,
                    &fixture.intent,
                    &expected,
                    MAXIMUM_VALUE,
                )
                .unwrap_err(),
            OutputAuthorizationError::NoteCommitmentMismatch
        );

        let fixture = make_fixture(OutputKind::ExternalPayment);
        let mut packet = fixture
            .prepared
            .authorization_packet(NETWORK, OutputKind::ExternalPayment)
            .unwrap();
        packet.output.value_commitment[0] ^= 1;
        let expected = packet.output.clone();
        assert_eq!(
            packet
                .verify(
                    &fixture.full_viewing_key,
                    &fixture.intent,
                    &expected,
                    MAXIMUM_VALUE,
                )
                .unwrap_err(),
            OutputAuthorizationError::ValueCommitmentMismatch
        );

        let fixture = make_fixture(OutputKind::ExternalPayment);
        let mut packet = fixture
            .prepared
            .authorization_packet(NETWORK, OutputKind::ExternalPayment)
            .unwrap();
        packet.output.ephemeral_key[0] ^= 1;
        let expected = packet.output.clone();
        assert_eq!(
            packet
                .verify(
                    &fixture.full_viewing_key,
                    &fixture.intent,
                    &expected,
                    MAXIMUM_VALUE,
                )
                .unwrap_err(),
            OutputAuthorizationError::EphemeralKeyMismatch
        );

        let fixture = make_fixture(OutputKind::ExternalPayment);
        let mut packet = fixture
            .prepared
            .authorization_packet(NETWORK, OutputKind::ExternalPayment)
            .unwrap();
        packet.output.note_ciphertext[0] ^= 1;
        let expected = packet.output.clone();
        assert_eq!(
            packet
                .verify(
                    &fixture.full_viewing_key,
                    &fixture.intent,
                    &expected,
                    MAXIMUM_VALUE,
                )
                .unwrap_err(),
            OutputAuthorizationError::RecipientCiphertextMismatch
        );

        let fixture = make_fixture(OutputKind::ExternalPayment);
        let mut packet = fixture
            .prepared
            .authorization_packet(NETWORK, OutputKind::ExternalPayment)
            .unwrap();
        packet.output.outgoing_ciphertext[0] ^= 1;
        let expected = packet.output.clone();
        assert_eq!(
            packet
                .verify(
                    &fixture.full_viewing_key,
                    &fixture.intent,
                    &expected,
                    MAXIMUM_VALUE,
                )
                .unwrap_err(),
            OutputAuthorizationError::OutgoingCiphertextMismatch
        );
    }

    #[test]
    fn classification_rules_are_fail_closed() {
        let fixture = make_fixture(OutputKind::ExternalPayment);
        assert_eq!(
            fixture
                .prepared
                .authorization_packet(NETWORK, OutputKind::Dummy)
                .unwrap_err(),
            OutputAuthorizationError::InvalidClassification
        );
        assert_eq!(
            OutputAuthorizationIntent::new(
                NETWORK,
                KeyScope::External,
                OutputKind::InternalChange,
                fixture.prepared.note().recipient(),
                0,
                fixture.prepared.note().action_nullifier().unwrap(),
                MEMO,
            )
            .unwrap_err(),
            OutputAuthorizationError::InvalidClassification
        );

        for kind in [OutputKind::InternalChange, OutputKind::Dummy] {
            let fixture = make_fixture(kind);
            let packet = fixture
                .prepared
                .authorization_packet(NETWORK, kind)
                .unwrap();
            assert_eq!(verify_fixture(&fixture, &packet).unwrap().kind(), kind);
        }
    }
}
