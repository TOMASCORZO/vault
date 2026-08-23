//! Production-intent key, note, and note-encryption layer for Vault.
//!
//! This crate adapts the maintained Ironwood/Orchard implementation instead of
//! defining new cryptographic primitives. It provides Vault-specific root-key domain
//! separation, diversified addresses, separated viewing capabilities, binding
//! note commitments, deterministic nullifiers, fixed-size authenticated note
//! encryption, and sender output recovery.
//!
//! It is not a complete private transfer: the activated proof circuit must
//! still constrain note membership, ownership, nullifiers, output openings,
//! value commitments, burn, fees, and ciphertext consistency.

use std::fmt;

use ff::PrimeField;
use orchard::{
    Address, Note, NoteVersion,
    keys::{
        FullViewingKey, IncomingViewingKey, OutgoingViewingKey, Scope, SpendAuthorizingKey,
        SpendValidatingKey, SpendingKey,
    },
    note::{ExtractedNoteCommitment, Nullifier as OrchardNullifier, RandomSeed, Rho},
    note_encryption::{CompactAction, IronwoodDomain, IronwoodNoteEncryption},
    primitives::redpallas::{self, SpendAuth},
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
};
use pasta_curves::{
    group::{Group, GroupEncoding},
    pallas,
};
use rand_core::{CryptoRng, RngCore};
use zcash_note_encryption::{
    Domain, ENC_CIPHERTEXT_SIZE, EphemeralKeyBytes, OUT_CIPHERTEXT_SIZE, ShieldedOutput, batch,
    try_note_decryption, try_output_recovery_with_ovk,
};
use zeroize::{Zeroize, Zeroizing};

mod signing;
mod tree;

#[cfg(feature = "circuit")]
pub mod circuit;

pub use signing::{
    OUTPUT_AUTHORIZATION_PACKET_BYTES, OutputAuthorizationError, OutputAuthorizationIntent,
    OutputAuthorizationPacket, OutputKind, VerifiedOutputAuthorization,
};
pub use tree::{
    NOTE_TREE_DEPTH, NoteCommitmentTree, NoteMembershipPath, NoteTreeAppend, NoteTreeRoot,
    NoteTreeSnapshot,
};

const SPENDING_KEY_DERIVATION_DOMAIN: &str = "vault.privacy.orchard-v1.spending-key.2026-08-21";
const SPEND_AUTHORIZATION_DOMAIN: &str = "vault.privacy.spend-authorization-v1.2026-08-21";
const MINIMUM_SEED_BYTES: usize = 32;
const MAXIMUM_SEED_BYTES: usize = 4096;

/// Fixed plaintext memo size inherited from Orchard note encryption.
pub const MEMO_BYTES: usize = 512;
/// Fixed recipient ciphertext size, including its authentication tag.
pub const NOTE_CIPHERTEXT_BYTES: usize = ENC_CIPHERTEXT_SIZE;
/// Fixed sender-recovery ciphertext size, including its authentication tag.
pub const OUTGOING_CIPHERTEXT_BYTES: usize = OUT_CIPHERTEXT_SIZE;
/// Exact wallet-private note bytes: address, value, rho, and Ironwood rseed.
pub const PRIVATE_NOTE_BYTES: usize = 43 + 8 + 32 + 32;
/// Exact wallet-private decrypted-note bytes, including its fixed memo.
pub const DECRYPTED_NOTE_BYTES: usize = PRIVATE_NOTE_BYTES + MEMO_BYTES;
/// Defensive bound for one local batch-scanning call.
pub const MAX_SCAN_BATCH_OUTPUTS: usize = 4096;
/// Defensive bound on incoming viewing capabilities tested in one batch.
pub const MAX_SCAN_VIEWING_KEYS: usize = 16;

/// Errors returned before any note or key is accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivacyError {
    /// Root seed material is too short for a wallet seed.
    SeedTooShort,
    /// Root seed material exceeds the defensive input limit.
    SeedTooLong,
    /// The all-zero network domain is reserved.
    ZeroNetworkId,
    /// Raw spending-key bytes do not produce valid Orchard key components.
    InvalidSpendingKey,
    /// Raw full-viewing-key bytes are non-canonical or internally inconsistent.
    InvalidFullViewingKey,
    /// Raw incoming-viewing-key bytes are non-canonical or invalid.
    InvalidIncomingViewingKey,
    /// Raw payment-address bytes contain an invalid transmission key.
    InvalidAddress,
    /// An action nullifier is zero or not a canonical Pallas base-field element.
    InvalidActionNullifier,
    /// A note amount exceeds the policy bound supplied by the caller.
    NoteValueOutOfRange,
    /// Note randomness could not produce a valid note within the bounded loop.
    NoteConstructionFailed,
    /// Public encrypted-output fields are non-canonical or malformed.
    InvalidEncryptedOutput,
    /// A public Orchard value commitment is not canonically encoded.
    InvalidValueCommitment,
    /// A note-tree root is not a canonical Pallas base-field element.
    InvalidNoteTreeRoot,
    /// The note commitment tree has no remaining leaf positions.
    NoteTreeFull,
    /// Persisted note-tree frontier data is inconsistent or non-canonical.
    InvalidNoteTreeSnapshot,
    /// A note-tree membership path is malformed.
    InvalidMembershipPath,
    /// A local trial-decryption batch exceeds its output bound.
    ScanBatchTooLarge,
    /// A local trial-decryption batch contains too many viewing keys.
    TooManyScanViewingKeys,
    /// A spend-authorization randomizer is zero or non-canonical.
    InvalidAuthorizationRandomizer,
    /// A randomized validating key or signature encoding is invalid.
    InvalidSpendAuthorization,
    /// The spending key does not match the prepared randomized validating key.
    AuthorizationKeyMismatch,
    /// Secret action witnesses are internally inconsistent.
    InvalidCircuitWitness,
    /// Public action fields cannot form a canonical circuit instance.
    InvalidCircuitInstance,
}

impl fmt::Display for PrivacyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::SeedTooShort => "wallet seed is shorter than 32 bytes",
            Self::SeedTooLong => "wallet seed exceeds 4096-byte input limit",
            Self::ZeroNetworkId => "zero network id is reserved",
            Self::InvalidSpendingKey => "invalid spending key",
            Self::InvalidFullViewingKey => "invalid full viewing key",
            Self::InvalidIncomingViewingKey => "invalid incoming viewing key",
            Self::InvalidAddress => "invalid shielded address",
            Self::InvalidActionNullifier => "invalid action nullifier",
            Self::NoteValueOutOfRange => "note value exceeds Vault policy",
            Self::NoteConstructionFailed => "failed to construct a valid note",
            Self::InvalidEncryptedOutput => "invalid encrypted note output",
            Self::InvalidValueCommitment => "invalid value commitment",
            Self::InvalidNoteTreeRoot => "invalid note-tree root",
            Self::NoteTreeFull => "note commitment tree is full",
            Self::InvalidNoteTreeSnapshot => "invalid note tree snapshot",
            Self::InvalidMembershipPath => "invalid note membership path",
            Self::ScanBatchTooLarge => "note scan batch exceeds output limit",
            Self::TooManyScanViewingKeys => "note scan batch exceeds viewing-key limit",
            Self::InvalidAuthorizationRandomizer => "invalid spend authorization randomizer",
            Self::InvalidSpendAuthorization => "invalid spend authorization",
            Self::AuthorizationKeyMismatch => "spending key does not match authorization",
            Self::InvalidCircuitWitness => "inconsistent private action circuit witness",
            Self::InvalidCircuitInstance => "invalid public action circuit instance",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for PrivacyError {}

/// External addresses receive payments; internal addresses receive change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyScope {
    /// Diversified addresses safe to give to counterparties.
    External,
    /// Wallet-internal addresses used only for change and internal bookkeeping.
    Internal,
}

impl From<KeyScope> for Scope {
    fn from(scope: KeyScope) -> Self {
        match scope {
            KeyScope::External => Scope::External,
            KeyScope::Internal => Scope::Internal,
        }
    }
}

/// Vault root spending key. Secret bytes are zeroized on drop.
pub struct VaultSpendingKey(Zeroizing<[u8; 32]>);

impl fmt::Debug for VaultSpendingKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VaultSpendingKey(REDACTED)")
    }
}

impl VaultSpendingKey {
    /// Derives a Vault account key from high-entropy wallet seed material.
    ///
    /// The network ID and account index are length-unambiguous inputs to BLAKE3
    /// derive-key mode. A counter provides deterministic rejection sampling for
    /// the validity conditions enforced by Orchard's key parser.
    pub fn derive(seed: &[u8], network_id: [u8; 32], account: u32) -> Result<Self, PrivacyError> {
        if seed.len() < MINIMUM_SEED_BYTES {
            return Err(PrivacyError::SeedTooShort);
        }
        if seed.len() > MAXIMUM_SEED_BYTES {
            return Err(PrivacyError::SeedTooLong);
        }
        if network_id == [0; 32] {
            return Err(PrivacyError::ZeroNetworkId);
        }

        for counter in 0..=u32::MAX {
            let mut hasher = blake3::Hasher::new_derive_key(SPENDING_KEY_DERIVATION_DOMAIN);
            hasher.update(&network_id);
            hasher.update(&account.to_le_bytes());
            hasher.update(&counter.to_le_bytes());
            hasher.update(&(seed.len() as u64).to_le_bytes());
            hasher.update(seed);
            let mut candidate = *hasher.finalize().as_bytes();

            if Option::<SpendingKey>::from(SpendingKey::from_bytes(candidate)).is_some() {
                return Ok(Self(Zeroizing::new(candidate)));
            }
            candidate.zeroize();
        }

        // The loop is exhaustive for its explicit counter domain. Reaching this
        // branch would imply a broken key derivation or parser.
        Err(PrivacyError::InvalidSpendingKey)
    }

    /// Restores already domain-separated Vault spending-key bytes.
    pub fn from_bytes(mut bytes: [u8; 32]) -> Result<Self, PrivacyError> {
        if Option::<SpendingKey>::from(SpendingKey::from_bytes(bytes)).is_none() {
            bytes.zeroize();
            return Err(PrivacyError::InvalidSpendingKey);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Returns a zeroizing copy for encrypted wallet backup code.
    #[must_use]
    pub fn export(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.0)
    }

    /// Derives the full viewing capability without exposing spending authority.
    #[must_use]
    pub fn full_viewing_key(&self) -> VaultFullViewingKey {
        let spending_key = self.orchard();
        let full_viewing_key = FullViewingKey::from(&spending_key);
        VaultFullViewingKey(Zeroizing::new(full_viewing_key.to_bytes()))
    }

    /// Creates a fresh randomized spend-validating key and retains its secret
    /// randomizer for the proof circuit and signer.
    pub fn prepare_spend_authorization<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<PreparedSpendAuthorization, PrivacyError> {
        let spending_key = self.orchard();
        let authorizing_key = SpendAuthorizingKey::from(&spending_key);
        let validating_key = SpendValidatingKey::from(&authorizing_key);

        for _ in 0..=u16::MAX {
            let (randomizer, randomizer_bytes) = sample_nonzero_scalar(rng)?;
            let randomized_key = validating_key.randomize(&randomizer);
            if !randomized_key.is_identity() {
                return Ok(PreparedSpendAuthorization {
                    randomized_verification_key: (&randomized_key).into(),
                    randomizer: Zeroizing::new(randomizer_bytes),
                });
            }
        }
        Err(PrivacyError::InvalidAuthorizationRandomizer)
    }

    /// Low-level primitive that signs an exact Vault authorization digest with
    /// the prepared randomized key. A different spending key is rejected.
    ///
    /// Transfer-v2 wallets must call this only through
    /// `PreparedTransferV2Authorization::sign_action`, after independently
    /// reconstructing every output. This primitive remains public so protocol
    /// layers do not create a dependency cycle; it does not validate outputs,
    /// gas, burn policy, or the activated circuit by itself.
    pub fn sign_spend_authorization<R: RngCore + CryptoRng>(
        &self,
        prepared: &PreparedSpendAuthorization,
        digest: SpendAuthorizationDigest,
        rng: &mut R,
    ) -> Result<SpendAuthorization, PrivacyError> {
        let randomizer = parse_nonzero_scalar(&prepared.randomizer)?;
        let authorizing_key = SpendAuthorizingKey::from(&self.orchard());
        let randomized_signing_key = authorizing_key.randomize(&randomizer);
        let randomized_verification_key = redpallas::VerificationKey::from(&randomized_signing_key);
        let randomized_verification_key_bytes: [u8; 32] = (&randomized_verification_key).into();
        if randomized_verification_key_bytes != prepared.randomized_verification_key {
            return Err(PrivacyError::AuthorizationKeyMismatch);
        }

        let signature = randomized_signing_key.sign(rng, digest.as_bytes());
        SpendAuthorization::from_parts(randomized_verification_key_bytes, (&signature).into())
    }

    fn orchard(&self) -> SpendingKey {
        Option::<SpendingKey>::from(SpendingKey::from_bytes(*self.0))
            .expect("VaultSpendingKey is validated at construction")
    }
}

/// Network- and transaction-bound message signed by every private spend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpendAuthorizationDigest([u8; 32]);

impl SpendAuthorizationDigest {
    /// Domain-separates a complete transaction-effects digest for one Vault
    /// network. Signature bytes themselves must be excluded from `effects`.
    pub fn derive(
        network_id: [u8; 32],
        transaction_effects: [u8; 32],
    ) -> Result<Self, PrivacyError> {
        if network_id == [0; 32] {
            return Err(PrivacyError::ZeroNetworkId);
        }
        let mut hasher = blake3::Hasher::new_derive_key(SPEND_AUTHORIZATION_DOMAIN);
        hasher.update(&network_id);
        hasher.update(&transaction_effects);
        Ok(Self(*hasher.finalize().as_bytes()))
    }

    /// Exact 32-byte RedPallas message.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Canonical, non-identity RedPallas validating key randomized for one spend.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct RandomizedSpendValidatingKey([u8; 32]);

impl fmt::Debug for RandomizedSpendValidatingKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("RandomizedSpendValidatingKey")
            .field(&format_args!("{}…", HexPrefix(&self.0[..6])))
            .finish()
    }
}

impl RandomizedSpendValidatingKey {
    /// Parses a canonical RedPallas key and rejects the identity point.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, PrivacyError> {
        let verification_key = redpallas::VerificationKey::<SpendAuth>::try_from(bytes)
            .map_err(|_| PrivacyError::InvalidSpendAuthorization)?;
        if verification_key.is_identity() {
            return Err(PrivacyError::InvalidSpendAuthorization);
        }
        Ok(Self(bytes))
    }

    /// Canonical compressed RedPallas point.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Secret authorization material created before proving and signing.
pub struct PreparedSpendAuthorization {
    randomized_verification_key: [u8; 32],
    randomizer: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for PreparedSpendAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedSpendAuthorization")
            .field(
                "randomized_verification_key",
                &format_args!("{}…", HexPrefix(&self.randomized_verification_key[..6])),
            )
            .field("randomizer", &"REDACTED")
            .finish()
    }
}

impl PreparedSpendAuthorization {
    /// Public randomized validating key bound inside the transfer proof.
    #[must_use]
    pub const fn randomized_verification_key(&self) -> [u8; 32] {
        self.randomized_verification_key
    }

    /// Returns a zeroizing copy of the circuit witness `alpha`.
    #[must_use]
    pub fn randomizer(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.randomizer)
    }
}

/// Public per-spend randomized validating key and RedPallas authorization.
#[derive(Clone, Eq, PartialEq)]
pub struct SpendAuthorization {
    randomized_verification_key: RandomizedSpendValidatingKey,
    signature: [u8; 64],
}

impl fmt::Debug for SpendAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SpendAuthorization")
            .field(
                "randomized_verification_key",
                &format_args!("{}…", HexPrefix(&self.randomized_verification_key.0[..6])),
            )
            .field("signature", &"64 bytes")
            .finish()
    }
}

impl SpendAuthorization {
    /// Parses a non-identity canonical randomized key and signature bytes.
    pub fn from_parts(
        randomized_verification_key: [u8; 32],
        signature: [u8; 64],
    ) -> Result<Self, PrivacyError> {
        let randomized_verification_key =
            RandomizedSpendValidatingKey::from_bytes(randomized_verification_key)?;
        Ok(Self {
            randomized_verification_key,
            signature,
        })
    }

    /// Randomized validating key bound by the private-transfer circuit.
    #[must_use]
    pub const fn randomized_verification_key(&self) -> [u8; 32] {
        self.randomized_verification_key.to_bytes()
    }

    /// Typed randomized validating key used by a transfer action.
    #[must_use]
    pub const fn validating_key(&self) -> RandomizedSpendValidatingKey {
        self.randomized_verification_key
    }

    /// Canonical 64-byte RedPallas signature.
    #[must_use]
    pub const fn signature(&self) -> [u8; 64] {
        self.signature
    }

    /// Verifies the signature over the exact network-bound authorization digest.
    #[must_use]
    pub fn verify(&self, digest: SpendAuthorizationDigest) -> bool {
        let Ok(verification_key) = redpallas::VerificationKey::<SpendAuth>::try_from(
            self.randomized_verification_key.to_bytes(),
        ) else {
            return false;
        };
        if verification_key.is_identity() {
            return false;
        }
        let signature = redpallas::Signature::<SpendAuth>::from(self.signature);
        verification_key
            .verify(digest.as_bytes(), &signature)
            .is_ok()
    }
}

/// Canonical compressed Orchard value commitment.
///
/// The identity encoding is accepted because a padded action may have a zero
/// net value. The transfer circuit, not this parser, constrains its opening.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct CanonicalValueCommitment([u8; 32]);

impl fmt::Debug for CanonicalValueCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CanonicalValueCommitment")
            .field(&format_args!("{}…", HexPrefix(&self.0[..6])))
            .finish()
    }
}

impl CanonicalValueCommitment {
    /// Parses the unique compressed encoding of a Pallas value-commitment point.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, PrivacyError> {
        Option::<ValueCommitment>::from(ValueCommitment::from_bytes(&bytes))
            .map(|_| Self(bytes))
            .ok_or(PrivacyError::InvalidValueCommitment)
    }

    /// Canonical compressed point.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Whether this commitment is the group identity.
    #[must_use]
    pub fn is_identity(self) -> bool {
        self.0 == pallas::Point::identity().to_bytes()
    }
}

/// Full viewing capability. It can detect incoming and outgoing notes and
/// derive their nullifiers, but cannot authorize a spend.
pub struct VaultFullViewingKey(Zeroizing<[u8; 96]>);

impl fmt::Debug for VaultFullViewingKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VaultFullViewingKey(REDACTED)")
    }
}

impl VaultFullViewingKey {
    /// Parses and validates a serialized full viewing key.
    pub fn from_bytes(bytes: [u8; 96]) -> Result<Self, PrivacyError> {
        FullViewingKey::from_bytes(&bytes)
            .map(|_| Self(Zeroizing::new(bytes)))
            .ok_or(PrivacyError::InvalidFullViewingKey)
    }

    /// Returns a zeroizing copy for encrypted wallet backup or watch-only use.
    #[must_use]
    pub fn export(&self) -> Zeroizing<[u8; 96]> {
        Zeroizing::new(*self.0)
    }

    /// Derives one diversified payment address.
    #[must_use]
    pub fn address_at(&self, index: u32, scope: KeyScope) -> VaultAddress {
        VaultAddress(
            self.orchard()
                .address_at(index, scope.into())
                .to_raw_address_bytes(),
        )
    }

    /// Derives the capability that can trial-decrypt incoming notes only.
    #[must_use]
    pub fn incoming_viewing_key(&self, scope: KeyScope) -> VaultIncomingViewingKey {
        VaultIncomingViewingKey(Zeroizing::new(
            self.orchard().to_ivk(scope.into()).to_bytes(),
        ))
    }

    /// Derives the capability used to recover sent-output details.
    #[must_use]
    pub fn outgoing_viewing_key(&self, scope: KeyScope) -> VaultOutgoingViewingKey {
        VaultOutgoingViewingKey(Zeroizing::new(
            *self.orchard().to_ovk(scope.into()).as_ref(),
        ))
    }

    /// Derives the unique public nullifier for a note owned by this account.
    pub fn note_nullifier(&self, note: &PrivateNote) -> Result<ActionNullifier, PrivacyError> {
        let note = note.orchard()?;
        let nullifier = note.nullifier(&self.orchard()).to_bytes();
        ActionNullifier::from_bytes(nullifier)
    }

    fn orchard(&self) -> FullViewingKey {
        FullViewingKey::from_bytes(&self.0)
            .expect("VaultFullViewingKey is validated at construction")
    }
}

/// Incoming-only viewing capability. Secret bytes are zeroized on drop.
pub struct VaultIncomingViewingKey(Zeroizing<[u8; 64]>);

impl fmt::Debug for VaultIncomingViewingKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VaultIncomingViewingKey(REDACTED)")
    }
}

impl VaultIncomingViewingKey {
    /// Parses a serialized incoming viewing capability.
    pub fn from_bytes(bytes: [u8; 64]) -> Result<Self, PrivacyError> {
        Option::<IncomingViewingKey>::from(IncomingViewingKey::from_bytes(&bytes))
            .map(|_| Self(Zeroizing::new(bytes)))
            .ok_or(PrivacyError::InvalidIncomingViewingKey)
    }

    /// Returns a zeroizing copy for watch-only wallet storage.
    #[must_use]
    pub fn export(&self) -> Zeroizing<[u8; 64]> {
        Zeroizing::new(*self.0)
    }

    /// Attempts authenticated recipient decryption and commitment validation.
    #[must_use]
    pub fn decrypt(
        &self,
        action_nullifier: ActionNullifier,
        output: &EncryptedNote,
    ) -> Option<DecryptedNote> {
        let domain = output.domain(action_nullifier).ok()?;
        let incoming = self.orchard();
        let prepared = incoming.prepare();
        let (note, _address, memo) = try_note_decryption(&domain, &prepared, output)?;
        Some(DecryptedNote::from_orchard(note, memo))
    }

    fn orchard(&self) -> IncomingViewingKey {
        Option::<IncomingViewingKey>::from(IncomingViewingKey::from_bytes(&self.0))
            .expect("VaultIncomingViewingKey is validated at construction")
    }
}

/// Outgoing-only recovery capability. Secret bytes are zeroized on drop.
pub struct VaultOutgoingViewingKey(Zeroizing<[u8; 32]>);

impl fmt::Debug for VaultOutgoingViewingKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VaultOutgoingViewingKey(REDACTED)")
    }
}

impl VaultOutgoingViewingKey {
    /// Restores a serialized outgoing viewing capability.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Returns a zeroizing copy for encrypted wallet storage.
    #[must_use]
    pub fn export(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.0)
    }

    /// Recovers a sent note and validates its commitment and ephemeral key.
    #[must_use]
    pub fn recover(
        &self,
        action_nullifier: ActionNullifier,
        output: &EncryptedNote,
    ) -> Option<DecryptedNote> {
        let domain = output.domain(action_nullifier).ok()?;
        let value_commitment =
            Option::<ValueCommitment>::from(ValueCommitment::from_bytes(&output.value_commitment))?;
        let outgoing = OutgoingViewingKey::from(*self.0);
        let (note, _address, memo) = try_output_recovery_with_ovk(
            &domain,
            &outgoing,
            output,
            &value_commitment,
            &output.outgoing_ciphertext,
        )?;
        Some(DecryptedNote::from_orchard(note, memo))
    }
}

/// Canonically encoded diversified Vault payment address.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct VaultAddress([u8; 43]);

impl fmt::Debug for VaultAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("VaultAddress")
            .field(&format_args!("{}…", HexPrefix(&self.0[..6])))
            .finish()
    }
}

impl VaultAddress {
    /// Parses and validates raw diversified-address bytes.
    pub fn from_bytes(bytes: [u8; 43]) -> Result<Self, PrivacyError> {
        Option::<Address>::from(Address::from_raw_address_bytes(&bytes))
            .map(|_| Self(bytes))
            .ok_or(PrivacyError::InvalidAddress)
    }

    /// Canonical 43-byte representation for a future network-specific codec.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 43] {
        self.0
    }

    fn orchard(self) -> Address {
        Option::<Address>::from(Address::from_raw_address_bytes(&self.0))
            .expect("VaultAddress is validated at construction")
    }
}

/// A canonical non-zero nullifier used as an action ID and as the output
/// note's unique `rho` value.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct ActionNullifier([u8; 32]);

impl fmt::Debug for ActionNullifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ActionNullifier")
            .field(&format_args!("{}…", HexPrefix(&self.0[..6])))
            .finish()
    }
}

impl ActionNullifier {
    /// Parses the canonical representation and rejects the reserved zero value.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, PrivacyError> {
        if bytes == [0; 32]
            || Option::<OrchardNullifier>::from(OrchardNullifier::from_bytes(&bytes)).is_none()
        {
            return Err(PrivacyError::InvalidActionNullifier);
        }
        Ok(Self(bytes))
    }

    /// Canonical public representation.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    fn orchard(self) -> OrchardNullifier {
        Option::<OrchardNullifier>::from(OrchardNullifier::from_bytes(&self.0))
            .expect("ActionNullifier is validated at construction")
    }
}

/// Private note plaintext retained by a wallet or consumed as a proof witness.
/// Randomness and amount are zeroized on drop.
pub struct PrivateNote {
    recipient: VaultAddress,
    value: u64,
    rho: [u8; 32],
    rseed: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for PrivateNote {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateNote(REDACTED)")
    }
}

impl Drop for PrivateNote {
    fn drop(&mut self) {
        self.recipient.0.zeroize();
        self.value.zeroize();
        self.rho.zeroize();
    }
}

impl PrivateNote {
    /// Creates a fresh note tied to one unique action nullifier.
    pub fn create<R: RngCore + CryptoRng>(
        recipient: VaultAddress,
        value: u64,
        maximum_value: u64,
        action_nullifier: ActionNullifier,
        rng: &mut R,
    ) -> Result<Self, PrivacyError> {
        if value > maximum_value {
            return Err(PrivacyError::NoteValueOutOfRange);
        }

        let rho = Rho::from_bytes(&action_nullifier.0);
        let rho = Option::<Rho>::from(rho).ok_or(PrivacyError::InvalidActionNullifier)?;
        for _ in 0..=u16::MAX {
            let mut rseed_bytes = [0; 32];
            rng.fill_bytes(&mut rseed_bytes);
            let rseed = RandomSeed::from_bytes(rseed_bytes, &rho);
            if Option::<RandomSeed>::from(rseed).is_some() {
                return Ok(Self {
                    recipient,
                    value,
                    rho: action_nullifier.0,
                    rseed: Zeroizing::new(rseed_bytes),
                });
            }
            rseed_bytes.zeroize();
        }
        Err(PrivacyError::NoteConstructionFailed)
    }

    /// Note value in atomic VLT units. This is wallet-private data.
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.value
    }

    /// Recipient address. This is wallet-private linkage data.
    #[must_use]
    pub const fn recipient(&self) -> VaultAddress {
        self.recipient
    }

    /// Public action nullifier from which this note's unique `rho` is derived.
    pub fn action_nullifier(&self) -> Result<ActionNullifier, PrivacyError> {
        ActionNullifier::from_bytes(self.rho)
    }

    /// Binding extracted note commitment appended to the note tree.
    pub fn commitment(&self) -> Result<[u8; 32], PrivacyError> {
        Ok(ExtractedNoteCommitment::from(self.orchard()?.commitment()).to_bytes())
    }

    /// Fixed-size wallet-private persistence codec. The returned buffer
    /// zeroizes on drop and MUST be encrypted by the wallet storage adapter.
    #[must_use]
    pub fn encode_private(&self) -> Zeroizing<[u8; PRIVATE_NOTE_BYTES]> {
        let mut bytes = Zeroizing::new([0; PRIVATE_NOTE_BYTES]);
        bytes[..43].copy_from_slice(&self.recipient.0);
        bytes[43..51].copy_from_slice(&self.value.to_le_bytes());
        bytes[51..83].copy_from_slice(&self.rho);
        bytes[83..].copy_from_slice(self.rseed.as_ref());
        bytes
    }

    /// Restores and fully validates the fixed wallet-private note codec.
    /// Generic plaintext serialization is intentionally unavailable.
    pub fn decode_private(
        bytes: [u8; PRIVATE_NOTE_BYTES],
        maximum_value: u64,
    ) -> Result<Self, PrivacyError> {
        let bytes = Zeroizing::new(bytes);
        let recipient = VaultAddress::from_bytes(
            bytes[..43]
                .try_into()
                .map_err(|_| PrivacyError::InvalidAddress)?,
        )?;
        let value = u64::from_le_bytes(
            bytes[43..51]
                .try_into()
                .map_err(|_| PrivacyError::NoteConstructionFailed)?,
        );
        if value > maximum_value {
            return Err(PrivacyError::NoteValueOutOfRange);
        }
        let rho: [u8; 32] = bytes[51..83]
            .try_into()
            .map_err(|_| PrivacyError::InvalidActionNullifier)?;
        ActionNullifier::from_bytes(rho)?;
        let rseed: [u8; 32] = bytes[83..]
            .try_into()
            .map_err(|_| PrivacyError::NoteConstructionFailed)?;
        let note = Self {
            recipient,
            value,
            rho,
            rseed: Zeroizing::new(rseed),
        };
        note.orchard()?;
        Ok(note)
    }

    fn orchard(&self) -> Result<Note, PrivacyError> {
        let rho = Option::<Rho>::from(Rho::from_bytes(&self.rho))
            .ok_or(PrivacyError::InvalidActionNullifier)?;
        let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(*self.rseed, &rho))
            .ok_or(PrivacyError::NoteConstructionFailed)?;
        Option::<Note>::from(Note::from_parts(
            self.recipient.orchard(),
            NoteValue::from_raw(self.value),
            rho,
            rseed,
            NoteVersion::V3,
        ))
        .ok_or(PrivacyError::NoteConstructionFailed)
    }

    fn from_orchard(note: Note) -> Self {
        Self {
            recipient: VaultAddress(note.recipient().to_raw_address_bytes()),
            value: note.value().inner(),
            rho: note.rho().to_bytes(),
            rseed: Zeroizing::new(*note.rseed().as_bytes()),
        }
    }
}

/// Public, fixed-size encrypted note output.
#[derive(Clone, Eq, PartialEq)]
pub struct EncryptedNote {
    note_commitment: [u8; 32],
    value_commitment: [u8; 32],
    ephemeral_key: [u8; 32],
    note_ciphertext: [u8; NOTE_CIPHERTEXT_BYTES],
    outgoing_ciphertext: [u8; OUTGOING_CIPHERTEXT_BYTES],
}

impl fmt::Debug for EncryptedNote {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedNote")
            .field(
                "note_commitment",
                &format_args!("{}…", HexPrefix(&self.note_commitment[..6])),
            )
            .field(
                "ciphertext_bytes",
                &(NOTE_CIPHERTEXT_BYTES + OUTGOING_CIPHERTEXT_BYTES),
            )
            .finish_non_exhaustive()
    }
}

impl EncryptedNote {
    /// Parses public output fields with canonical curve and field encodings.
    pub fn from_parts(
        note_commitment: [u8; 32],
        value_commitment: [u8; 32],
        ephemeral_key: [u8; 32],
        note_ciphertext: [u8; NOTE_CIPHERTEXT_BYTES],
        outgoing_ciphertext: [u8; OUTGOING_CIPHERTEXT_BYTES],
    ) -> Result<Self, PrivacyError> {
        let output = Self {
            note_commitment,
            value_commitment,
            ephemeral_key,
            note_ciphertext,
            outgoing_ciphertext,
        };
        output.validate_public_fields()?;
        Ok(output)
    }

    /// Extracted note commitment appended to shielded state.
    #[must_use]
    pub const fn note_commitment(&self) -> [u8; 32] {
        self.note_commitment
    }

    /// Hiding Pedersen commitment to this output's value.
    #[must_use]
    pub const fn value_commitment(&self) -> [u8; 32] {
        self.value_commitment
    }

    /// Ephemeral public key for recipient note decryption.
    #[must_use]
    pub const fn ephemeral_key(&self) -> [u8; 32] {
        self.ephemeral_key
    }

    /// Fixed-size authenticated recipient ciphertext.
    #[must_use]
    pub const fn note_ciphertext(&self) -> &[u8; NOTE_CIPHERTEXT_BYTES] {
        &self.note_ciphertext
    }

    /// Fixed-size authenticated sender-recovery ciphertext.
    #[must_use]
    pub const fn outgoing_ciphertext(&self) -> &[u8; OUTGOING_CIPHERTEXT_BYTES] {
        &self.outgoing_ciphertext
    }

    fn validate_public_fields(&self) -> Result<(), PrivacyError> {
        if self.note_commitment == [0; 32]
            || Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(
                &self.note_commitment,
            ))
            .is_none()
            || self.value_commitment == [0; 32]
            || Option::<ValueCommitment>::from(ValueCommitment::from_bytes(&self.value_commitment))
                .is_none()
        {
            return Err(PrivacyError::InvalidEncryptedOutput);
        }

        if IronwoodDomain::epk(&EphemeralKeyBytes(self.ephemeral_key)).is_none() {
            return Err(PrivacyError::InvalidEncryptedOutput);
        }

        Ok(())
    }

    fn domain(&self, action_nullifier: ActionNullifier) -> Result<IronwoodDomain, PrivacyError> {
        let cmx = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(
            &self.note_commitment,
        ))
        .ok_or(PrivacyError::InvalidEncryptedOutput)?;
        let compact = CompactAction::from_parts(
            action_nullifier.orchard(),
            cmx,
            EphemeralKeyBytes(self.ephemeral_key),
            self.note_ciphertext[..52]
                .try_into()
                .expect("Orchard note ciphertext is at least 52 bytes"),
        );
        // Force canonical parsing of epk through the full decryption API later;
        // CompactAction itself is a byte container. A malformed epk cannot yield
        // a successful decrypt, while `from_parts` rejects it at transaction codec.
        Ok(IronwoodDomain::for_compact_action(&compact))
    }
}

impl ShieldedOutput<IronwoodDomain, NOTE_CIPHERTEXT_BYTES> for EncryptedNote {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.ephemeral_key)
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.note_commitment
    }

    fn enc_ciphertext(&self) -> &[u8; NOTE_CIPHERTEXT_BYTES] {
        &self.note_ciphertext
    }
}

struct BorrowedEncryptedNote<'a>(&'a EncryptedNote);

impl ShieldedOutput<IronwoodDomain, NOTE_CIPHERTEXT_BYTES> for BorrowedEncryptedNote<'_> {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.0.ephemeral_key)
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.0.note_commitment
    }

    fn enc_ciphertext(&self) -> &[u8; NOTE_CIPHERTEXT_BYTES] {
        &self.0.note_ciphertext
    }
}

/// One note detected by bounded batched trial decryption.
pub struct DetectedNote {
    viewing_key_index: usize,
    decrypted: DecryptedNote,
}

impl fmt::Debug for DetectedNote {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DetectedNote")
            .field("viewing_key_index", &self.viewing_key_index)
            .field("decrypted", &"REDACTED")
            .finish()
    }
}

impl DetectedNote {
    /// Index into the viewing-key slice passed to [`scan_incoming_notes`].
    #[must_use]
    pub const fn viewing_key_index(&self) -> usize {
        self.viewing_key_index
    }

    /// Authenticated note and memo.
    #[must_use]
    pub const fn decrypted(&self) -> &DecryptedNote {
        &self.decrypted
    }

    /// Transfers the authenticated private note into a durable wallet update.
    #[must_use]
    pub fn into_decrypted(self) -> DecryptedNote {
        self.decrypted
    }
}

/// Batch trial-decrypts full fixed-size outputs without sending wallet
/// addresses or viewing keys to a remote node.
///
/// Results preserve input order. `None` means that none of the supplied
/// incoming viewing keys could authenticate and decrypt that output.
pub fn scan_incoming_notes(
    viewing_keys: &[&VaultIncomingViewingKey],
    outputs: &[(ActionNullifier, &EncryptedNote)],
) -> Result<Vec<Option<DetectedNote>>, PrivacyError> {
    if outputs.len() > MAX_SCAN_BATCH_OUTPUTS {
        return Err(PrivacyError::ScanBatchTooLarge);
    }
    if viewing_keys.len() > MAX_SCAN_VIEWING_KEYS {
        return Err(PrivacyError::TooManyScanViewingKeys);
    }

    let prepared_viewing_keys = viewing_keys
        .iter()
        .map(|viewing_key| viewing_key.orchard().prepare())
        .collect::<Vec<_>>();
    let batch_outputs = outputs
        .iter()
        .map(|(action_nullifier, output)| {
            output
                .domain(*action_nullifier)
                .map(|domain| (domain, BorrowedEncryptedNote(output)))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(
        batch::try_note_decryption(&prepared_viewing_keys, &batch_outputs)
            .into_iter()
            .map(|result| {
                result.map(|((note, _address, memo), viewing_key_index)| DetectedNote {
                    viewing_key_index,
                    decrypted: DecryptedNote::from_orchard(note, memo),
                })
            })
            .collect(),
    )
}

/// Wallet-private output package used by the transfer prover. It binds the
/// encrypted public output to its note plaintext and value trapdoor.
pub struct PreparedNoteOutput {
    note: PrivateNote,
    output: EncryptedNote,
    value_commitment_trapdoor: Zeroizing<[u8; 32]>,
    sender_scope: KeyScope,
    memo: Zeroizing<[u8; MEMO_BYTES]>,
}

/// Hiding commitment to one action's private `input - output` value.
///
/// This is distinct from the output value commitment used by sender recovery.
/// The specialized Action circuit binds this commitment to the input and output
/// note values, while the bundle accounting layer binds their aggregate to gas
/// and the mandatory burn.
pub struct PreparedNetValueCommitment {
    commitment: CanonicalValueCommitment,
    trapdoor: Zeroizing<[u8; 32]>,
}

/// Wallet-private opening of the mandatory burn value commitment.
///
/// Its trapdoor is sampled from the Pallas base-field subset of the scalar
/// field. This remains statistically indistinguishable at the protocol's
/// security level and lets the Halo2 variable-base gadget consume the exact
/// same canonical bytes without a non-native scalar representation.
pub struct PreparedBurnCommitment {
    amount: u64,
    commitment: CanonicalValueCommitment,
    trapdoor: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for PreparedBurnCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedBurnCommitment")
            .field("commitment", &self.commitment)
            .field("amount", &"REDACTED")
            .field("trapdoor", &"REDACTED")
            .finish()
    }
}

impl Drop for PreparedBurnCommitment {
    fn drop(&mut self) {
        self.amount.zeroize();
    }
}

impl PreparedBurnCommitment {
    /// Commits to one bounded burn amount with a circuit-compatible non-zero
    /// trapdoor. Identity commitments are resampled.
    pub fn create<R: RngCore + CryptoRng>(
        amount: u64,
        maximum_amount: u64,
        rng: &mut R,
    ) -> Result<Self, PrivacyError> {
        if amount > maximum_amount {
            return Err(PrivacyError::NoteValueOutOfRange);
        }
        for _ in 0..=u16::MAX {
            let (trapdoor, trapdoor_bytes) = sample_circuit_value_trapdoor(rng)?;
            let commitment = ValueCommitment::derive(
                NoteValue::from_raw(amount) - NoteValue::from_raw(0),
                trapdoor,
            );
            let commitment = CanonicalValueCommitment::from_bytes(commitment.to_bytes())?;
            if !commitment.is_identity() {
                return Ok(Self {
                    amount,
                    commitment,
                    trapdoor: Zeroizing::new(trapdoor_bytes),
                });
            }
        }
        Err(PrivacyError::NoteConstructionFailed)
    }

    /// Hidden burn amount consumed by the accounting circuit.
    #[must_use]
    pub const fn amount(&self) -> u64 {
        self.amount
    }

    /// Public burn commitment carried by transfer-v2.
    #[must_use]
    pub const fn commitment(&self) -> CanonicalValueCommitment {
        self.commitment
    }

    /// Zeroizing circuit witness for the commitment trapdoor.
    #[must_use]
    pub fn trapdoor(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.trapdoor)
    }
}

impl fmt::Debug for PreparedNetValueCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedNetValueCommitment")
            .field("commitment", &self.commitment)
            .field("trapdoor", &"REDACTED")
            .finish()
    }
}

impl PreparedNetValueCommitment {
    /// Commits to the signed difference between one input and one output note.
    pub fn create<R: RngCore + CryptoRng>(
        input_value: u64,
        output_value: u64,
        rng: &mut R,
    ) -> Result<Self, PrivacyError> {
        let (trapdoor, trapdoor_bytes) = sample_value_trapdoor(rng)?;
        let commitment = ValueCommitment::derive(
            NoteValue::from_raw(input_value) - NoteValue::from_raw(output_value),
            trapdoor,
        );
        Ok(Self {
            commitment: CanonicalValueCommitment::from_bytes(commitment.to_bytes())?,
            trapdoor: Zeroizing::new(trapdoor_bytes),
        })
    }

    /// Public commitment included in the transfer action.
    #[must_use]
    pub const fn commitment(&self) -> CanonicalValueCommitment {
        self.commitment
    }

    /// Returns a zeroizing copy of the proving witness `rcv`.
    #[must_use]
    pub fn trapdoor(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.trapdoor)
    }
}

impl fmt::Debug for PreparedNoteOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedNoteOutput(REDACTED)")
    }
}

impl PreparedNoteOutput {
    /// Constructs, commits, and encrypts one output with sender recovery enabled.
    #[allow(clippy::too_many_arguments)]
    pub fn create<R: RngCore + CryptoRng>(
        sender_viewing_key: &VaultFullViewingKey,
        sender_scope: KeyScope,
        recipient: VaultAddress,
        value: u64,
        maximum_value: u64,
        action_nullifier: ActionNullifier,
        memo: [u8; MEMO_BYTES],
        rng: &mut R,
    ) -> Result<Self, PrivacyError> {
        let note = PrivateNote::create(recipient, value, maximum_value, action_nullifier, rng)?;
        let orchard_note = note.orchard()?;
        let note_commitment = ExtractedNoteCommitment::from(orchard_note.commitment()).to_bytes();
        let (trapdoor, trapdoor_bytes) = sample_value_trapdoor(rng)?;
        let value_commitment =
            ValueCommitment::derive(orchard_note.value() - NoteValue::ZERO, trapdoor);
        let value_commitment_bytes = value_commitment.to_bytes();
        let outgoing_viewing_key = sender_viewing_key.orchard().to_ovk(sender_scope.into());
        let encryptor = IronwoodNoteEncryption::new(Some(outgoing_viewing_key), orchard_note, memo);
        let ephemeral_key = IronwoodDomain::epk_bytes(encryptor.epk()).0;
        let note_ciphertext = encryptor.encrypt_note_plaintext();
        let outgoing_ciphertext = encryptor.encrypt_outgoing_plaintext(
            &value_commitment,
            &Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(
                &note_commitment,
            ))
            .expect("fresh commitment has a canonical encoding"),
            rng,
        );
        let output = EncryptedNote::from_parts(
            note_commitment,
            value_commitment_bytes,
            ephemeral_key,
            note_ciphertext,
            outgoing_ciphertext,
        )?;

        Ok(Self {
            note,
            output,
            value_commitment_trapdoor: Zeroizing::new(trapdoor_bytes),
            sender_scope,
            memo: Zeroizing::new(memo),
        })
    }

    /// Wallet note that must remain private and becomes a proof witness.
    #[must_use]
    pub const fn note(&self) -> &PrivateNote {
        &self.note
    }

    /// Public encrypted output committed by the transaction transcript.
    #[must_use]
    pub const fn encrypted_note(&self) -> &EncryptedNote {
        &self.output
    }

    /// Secret value-commitment trapdoor required by the proving circuit.
    #[must_use]
    pub fn value_commitment_trapdoor(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.value_commitment_trapdoor)
    }
}

/// Successfully decrypted and commitment-validated wallet data.
pub struct DecryptedNote {
    note: PrivateNote,
    memo: Zeroizing<[u8; MEMO_BYTES]>,
}

impl fmt::Debug for DecryptedNote {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DecryptedNote(REDACTED)")
    }
}

impl DecryptedNote {
    /// Decrypted private note.
    #[must_use]
    pub const fn note(&self) -> &PrivateNote {
        &self.note
    }

    /// Returns a zeroizing copy of the fixed-size private memo.
    #[must_use]
    pub fn memo(&self) -> Zeroizing<[u8; MEMO_BYTES]> {
        Zeroizing::new(*self.memo)
    }

    /// Fixed-size wallet-private persistence codec. Storage MUST authenticate
    /// and encrypt this buffer before it leaves the wallet trust boundary.
    #[must_use]
    pub fn encode_private(&self) -> Zeroizing<[u8; DECRYPTED_NOTE_BYTES]> {
        let note = self.note.encode_private();
        let mut bytes = Zeroizing::new([0; DECRYPTED_NOTE_BYTES]);
        bytes[..PRIVATE_NOTE_BYTES].copy_from_slice(note.as_ref());
        bytes[PRIVATE_NOTE_BYTES..].copy_from_slice(self.memo.as_ref());
        bytes
    }

    /// Restores the exact wallet-private note and memo representation.
    pub fn decode_private(
        bytes: [u8; DECRYPTED_NOTE_BYTES],
        maximum_value: u64,
    ) -> Result<Self, PrivacyError> {
        let bytes = Zeroizing::new(bytes);
        let note = PrivateNote::decode_private(
            bytes[..PRIVATE_NOTE_BYTES]
                .try_into()
                .map_err(|_| PrivacyError::NoteConstructionFailed)?,
            maximum_value,
        )?;
        let memo = bytes[PRIVATE_NOTE_BYTES..]
            .try_into()
            .map_err(|_| PrivacyError::NoteConstructionFailed)?;
        Ok(Self {
            note,
            memo: Zeroizing::new(memo),
        })
    }

    fn from_orchard(note: Note, memo: [u8; MEMO_BYTES]) -> Self {
        Self {
            note: PrivateNote::from_orchard(note),
            memo: Zeroizing::new(memo),
        }
    }
}

fn sample_value_trapdoor<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<(ValueCommitTrapdoor, [u8; 32]), PrivacyError> {
    for _ in 0..=u16::MAX {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        let trapdoor = Option::<ValueCommitTrapdoor>::from(ValueCommitTrapdoor::from_bytes(bytes));
        if bytes != [0; 32] {
            if let Some(trapdoor) = trapdoor {
                return Ok((trapdoor, bytes));
            }
        }
        bytes.zeroize();
    }
    Err(PrivacyError::NoteConstructionFailed)
}

fn sample_circuit_value_trapdoor<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<(ValueCommitTrapdoor, [u8; 32]), PrivacyError> {
    for _ in 0..=u16::MAX {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        let base = Option::<pallas::Base>::from(pallas::Base::from_repr(bytes));
        let trapdoor = Option::<ValueCommitTrapdoor>::from(ValueCommitTrapdoor::from_bytes(bytes));
        if bytes != [0; 32] && base.is_some() {
            if let Some(trapdoor) = trapdoor {
                return Ok((trapdoor, bytes));
            }
        }
        bytes.zeroize();
    }
    Err(PrivacyError::NoteConstructionFailed)
}

fn sample_nonzero_scalar<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<(pallas::Scalar, [u8; 32]), PrivacyError> {
    for _ in 0..=u16::MAX {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        if let Ok(scalar) = parse_nonzero_scalar(&bytes) {
            return Ok((scalar, bytes));
        }
        bytes.zeroize();
    }
    Err(PrivacyError::InvalidAuthorizationRandomizer)
}

fn parse_nonzero_scalar(bytes: &[u8; 32]) -> Result<pallas::Scalar, PrivacyError> {
    if bytes == &[0; 32] {
        return Err(PrivacyError::InvalidAuthorizationRandomizer);
    }
    Option::<pallas::Scalar>::from(pallas::Scalar::from_repr(*bytes))
        .ok_or(PrivacyError::InvalidAuthorizationRandomizer)
}

struct HexPrefix<'a>(&'a [u8]);

impl fmt::Display for HexPrefix<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

    const NETWORK_A: [u8; 32] = [0xA1; 32];
    const NETWORK_B: [u8; 32] = [0xB2; 32];
    const WALLET_SEED: [u8; 32] = [0x5A; 32];
    const MAXIMUM_VALUE: u64 = 21_000_000 * 1_000_000_000;

    fn wallet() -> (VaultFullViewingKey, VaultAddress, VaultIncomingViewingKey) {
        let spending_key = VaultSpendingKey::derive(&WALLET_SEED, NETWORK_A, 0).unwrap();
        let full_viewing_key = spending_key.full_viewing_key();
        let address = full_viewing_key.address_at(0, KeyScope::External);
        let incoming = full_viewing_key.incoming_viewing_key(KeyScope::External);
        (full_viewing_key, address, incoming)
    }

    fn nullifier(byte: u8) -> ActionNullifier {
        ActionNullifier::from_bytes([byte; 32]).unwrap()
    }

    fn output_vector_digest(output: &EncryptedNote) -> [u8; 32] {
        let mut hasher =
            blake3::Hasher::new_derive_key("vault.privacy.note-output.test-vector.2026-08-21");
        hasher.update(&output.note_commitment);
        hasher.update(&output.value_commitment);
        hasher.update(&output.ephemeral_key);
        hasher.update(&output.note_ciphertext);
        hasher.update(&output.outgoing_ciphertext);
        *hasher.finalize().as_bytes()
    }

    #[test]
    fn key_derivation_is_network_and_account_separated() {
        let a0 = VaultSpendingKey::derive(&WALLET_SEED, NETWORK_A, 0).unwrap();
        let a1 = VaultSpendingKey::derive(&WALLET_SEED, NETWORK_A, 1).unwrap();
        let b0 = VaultSpendingKey::derive(&WALLET_SEED, NETWORK_B, 0).unwrap();

        assert_ne!(*a0.export(), *a1.export());
        assert_ne!(*a0.export(), *b0.export());
        assert_ne!(
            a0.full_viewing_key().address_at(0, KeyScope::External),
            b0.full_viewing_key().address_at(0, KeyScope::External)
        );
        assert_eq!(
            *a0.export(),
            [
                0x90, 0x8f, 0xf9, 0x8c, 0xb2, 0xac, 0xad, 0x01, 0xe2, 0x22, 0x24, 0x9d, 0xd8, 0x63,
                0x0c, 0x48, 0x3d, 0xed, 0x26, 0xde, 0x9a, 0xec, 0x9e, 0xce, 0xf8, 0xa8, 0xe9, 0x1a,
                0x45, 0x59, 0x00, 0x4f,
            ]
        );
        assert_eq!(
            a0.full_viewing_key()
                .address_at(0, KeyScope::External)
                .to_bytes(),
            [
                0x91, 0xa2, 0x8f, 0xfa, 0x59, 0x87, 0xf0, 0xbe, 0xce, 0x55, 0x1b, 0x77, 0x05, 0x98,
                0x1d, 0xcb, 0x3b, 0x1e, 0xf4, 0x8e, 0xb6, 0x82, 0x5a, 0x1e, 0x87, 0x66, 0x9b, 0x33,
                0x48, 0x80, 0xb7, 0x66, 0x80, 0x89, 0x81, 0xa6, 0xc8, 0x37, 0x72, 0x44, 0x41, 0xb9,
                0x05,
            ]
        );
    }

    #[test]
    fn burn_commitment_is_bounded_and_uses_a_circuit_scalar() {
        let mut rng = ChaCha20Rng::from_seed([0xB7; 32]);
        let prepared = PreparedBurnCommitment::create(25, MAXIMUM_VALUE, &mut rng).unwrap();
        assert_eq!(prepared.amount(), 25);
        assert!(!prepared.commitment().is_identity());
        assert!(
            Option::<pallas::Base>::from(pallas::Base::from_repr(*prepared.trapdoor())).is_some()
        );
        assert!(
            Option::<ValueCommitTrapdoor>::from(ValueCommitTrapdoor::from_bytes(
                *prepared.trapdoor()
            ))
            .is_some()
        );
        assert!(matches!(
            PreparedBurnCommitment::create(MAXIMUM_VALUE + 1, MAXIMUM_VALUE, &mut rng),
            Err(PrivacyError::NoteValueOutOfRange)
        ));
    }

    #[test]
    fn diversified_addresses_share_incoming_capability_without_linking_public_bytes() {
        let (full_viewing_key, first, incoming) = wallet();
        let second = full_viewing_key.address_at(1, KeyScope::External);
        assert_ne!(first, second);

        let mut rng = ChaCha20Rng::from_seed([7; 32]);
        let prepared = PreparedNoteOutput::create(
            &full_viewing_key,
            KeyScope::External,
            second,
            50_000,
            MAXIMUM_VALUE,
            nullifier(3),
            [9; MEMO_BYTES],
            &mut rng,
        )
        .unwrap();
        let decrypted = incoming
            .decrypt(nullifier(3), prepared.encrypted_note())
            .expect("same incoming key decrypts a diversified address");
        assert_eq!(decrypted.note().recipient(), second);
        assert_eq!(decrypted.note().value(), 50_000);
    }

    #[test]
    fn recipient_and_sender_recover_the_same_committed_note() {
        let (full_viewing_key, address, incoming) = wallet();
        let outgoing = full_viewing_key.outgoing_viewing_key(KeyScope::External);
        let action_nullifier = nullifier(4);
        let mut rng = ChaCha20Rng::from_seed([8; 32]);
        let prepared = PreparedNoteOutput::create(
            &full_viewing_key,
            KeyScope::External,
            address,
            123_456,
            MAXIMUM_VALUE,
            action_nullifier,
            [0xAB; MEMO_BYTES],
            &mut rng,
        )
        .unwrap();

        let recipient = incoming
            .decrypt(action_nullifier, prepared.encrypted_note())
            .expect("recipient authenticates and decrypts");
        let sender = outgoing
            .recover(action_nullifier, prepared.encrypted_note())
            .expect("sender recovers outgoing note");

        assert_eq!(recipient.note().value(), 123_456);
        assert_eq!(sender.note().value(), 123_456);
        assert_eq!(recipient.note().commitment(), sender.note().commitment());
        assert_eq!(*recipient.memo(), [0xAB; MEMO_BYTES]);
        assert_eq!(*sender.memo(), [0xAB; MEMO_BYTES]);
        assert_eq!(
            output_vector_digest(prepared.encrypted_note()),
            [
                0xf6, 0x5e, 0xe3, 0xc6, 0x23, 0x69, 0xa3, 0x27, 0x49, 0x2b, 0xd6, 0x46, 0x37, 0xed,
                0xb5, 0x83, 0x05, 0x09, 0x61, 0x58, 0x92, 0x3d, 0x3b, 0xb7, 0xf8, 0x8d, 0xff, 0x4b,
                0xb1, 0x6b, 0x09, 0xa7,
            ]
        );
    }

    #[test]
    fn wallet_private_note_codec_round_trips_and_revalidates_secrets() {
        let (full_viewing_key, address, incoming) = wallet();
        let action_nullifier = nullifier(19);
        let mut rng = ChaCha20Rng::from_seed([0xA9; 32]);
        let prepared = PreparedNoteOutput::create(
            &full_viewing_key,
            KeyScope::External,
            address,
            987_654,
            MAXIMUM_VALUE,
            action_nullifier,
            [0xC3; MEMO_BYTES],
            &mut rng,
        )
        .unwrap();
        let decrypted = incoming
            .decrypt(action_nullifier, prepared.encrypted_note())
            .unwrap();
        let encoded = decrypted.encode_private();
        assert_eq!(encoded.len(), DECRYPTED_NOTE_BYTES);
        let restored = DecryptedNote::decode_private(*encoded, MAXIMUM_VALUE).unwrap();
        assert_eq!(restored.note().recipient(), address);
        assert_eq!(restored.note().value(), 987_654);
        assert_eq!(
            restored.note().action_nullifier().unwrap(),
            action_nullifier
        );
        assert_eq!(
            restored.note().commitment().unwrap(),
            prepared.encrypted_note().note_commitment()
        );
        assert_eq!(*restored.memo(), [0xC3; MEMO_BYTES]);

        let mut excessive_value = *encoded;
        excessive_value[43..51].copy_from_slice(&(MAXIMUM_VALUE + 1).to_le_bytes());
        assert_eq!(
            DecryptedNote::decode_private(excessive_value, MAXIMUM_VALUE).unwrap_err(),
            PrivacyError::NoteValueOutOfRange
        );
        let mut zero_rho = *encoded;
        zero_rho[51..83].fill(0);
        assert_eq!(
            DecryptedNote::decode_private(zero_rho, MAXIMUM_VALUE).unwrap_err(),
            PrivacyError::InvalidActionNullifier
        );
        let mut different_rseed = *encoded;
        different_rseed[83] ^= 1;
        let different = DecryptedNote::decode_private(different_rseed, MAXIMUM_VALUE).unwrap();
        assert_ne!(
            different.note().commitment().unwrap(),
            restored.note().commitment().unwrap()
        );
    }

    #[test]
    fn wrong_viewing_key_cannot_decrypt() {
        let (full_viewing_key, address, _incoming) = wallet();
        let other = VaultSpendingKey::derive(&[0x6B; 32], NETWORK_A, 0)
            .unwrap()
            .full_viewing_key()
            .incoming_viewing_key(KeyScope::External);
        let mut rng = ChaCha20Rng::from_seed([9; 32]);
        let prepared = PreparedNoteOutput::create(
            &full_viewing_key,
            KeyScope::External,
            address,
            42,
            MAXIMUM_VALUE,
            nullifier(5),
            [0; MEMO_BYTES],
            &mut rng,
        )
        .unwrap();

        assert!(
            other
                .decrypt(nullifier(5), prepared.encrypted_note())
                .is_none()
        );
    }

    #[test]
    fn batch_scanner_preserves_order_and_reports_the_matching_capability() {
        let (first_fvk, first_address, first_ivk) = wallet();
        let second_fvk = VaultSpendingKey::derive(&[0x6B; 32], NETWORK_A, 0)
            .unwrap()
            .full_viewing_key();
        let second_address = second_fvk.address_at(0, KeyScope::External);
        let second_ivk = second_fvk.incoming_viewing_key(KeyScope::External);
        let third_fvk = VaultSpendingKey::derive(&[0x7C; 32], NETWORK_A, 0)
            .unwrap()
            .full_viewing_key();
        let third_address = third_fvk.address_at(0, KeyScope::External);
        let mut rng = ChaCha20Rng::from_seed([15; 32]);

        let first = PreparedNoteOutput::create(
            &first_fvk,
            KeyScope::External,
            first_address,
            100,
            MAXIMUM_VALUE,
            nullifier(12),
            [1; MEMO_BYTES],
            &mut rng,
        )
        .unwrap();
        let third = PreparedNoteOutput::create(
            &third_fvk,
            KeyScope::External,
            third_address,
            300,
            MAXIMUM_VALUE,
            nullifier(13),
            [3; MEMO_BYTES],
            &mut rng,
        )
        .unwrap();
        let second = PreparedNoteOutput::create(
            &second_fvk,
            KeyScope::External,
            second_address,
            200,
            MAXIMUM_VALUE,
            nullifier(14),
            [2; MEMO_BYTES],
            &mut rng,
        )
        .unwrap();

        let detected = scan_incoming_notes(
            &[&first_ivk, &second_ivk],
            &[
                (nullifier(12), first.encrypted_note()),
                (nullifier(13), third.encrypted_note()),
                (nullifier(14), second.encrypted_note()),
            ],
        )
        .unwrap();
        assert_eq!(detected.len(), 3);
        assert_eq!(detected[0].as_ref().unwrap().viewing_key_index(), 0);
        assert_eq!(
            detected[0].as_ref().unwrap().decrypted().note().value(),
            100
        );
        assert!(detected[1].is_none());
        assert_eq!(detected[2].as_ref().unwrap().viewing_key_index(), 1);
        assert_eq!(
            detected[2].as_ref().unwrap().decrypted().note().value(),
            200
        );

        let oversized_outputs =
            vec![(nullifier(12), first.encrypted_note()); MAX_SCAN_BATCH_OUTPUTS + 1];
        assert_eq!(
            scan_incoming_notes(&[&first_ivk], &oversized_outputs).unwrap_err(),
            PrivacyError::ScanBatchTooLarge
        );
        let oversized_keys = vec![&first_ivk; MAX_SCAN_VIEWING_KEYS + 1];
        assert_eq!(
            scan_incoming_notes(&oversized_keys, &[]).unwrap_err(),
            PrivacyError::TooManyScanViewingKeys
        );
    }

    #[test]
    fn ciphertext_commitment_ephemeral_key_and_rho_tampering_fail_closed() {
        let (full_viewing_key, address, incoming) = wallet();
        let action_nullifier = nullifier(6);
        let mut rng = ChaCha20Rng::from_seed([10; 32]);
        let prepared = PreparedNoteOutput::create(
            &full_viewing_key,
            KeyScope::External,
            address,
            9_999,
            MAXIMUM_VALUE,
            action_nullifier,
            [1; MEMO_BYTES],
            &mut rng,
        )
        .unwrap();
        let original = prepared.encrypted_note();

        let mut ciphertext = original.note_ciphertext;
        ciphertext[100] ^= 1;
        let tampered_ciphertext = EncryptedNote {
            note_ciphertext: ciphertext,
            ..original.clone()
        };
        assert!(
            incoming
                .decrypt(action_nullifier, &tampered_ciphertext)
                .is_none()
        );

        let mut commitment = original.note_commitment;
        commitment[0] ^= 1;
        let tampered_commitment = EncryptedNote {
            note_commitment: commitment,
            ..original.clone()
        };
        assert!(
            incoming
                .decrypt(action_nullifier, &tampered_commitment)
                .is_none()
        );

        let mut ephemeral_key = original.ephemeral_key;
        ephemeral_key[0] ^= 1;
        let tampered_ephemeral_key = EncryptedNote {
            ephemeral_key,
            ..original.clone()
        };
        assert!(
            incoming
                .decrypt(action_nullifier, &tampered_ephemeral_key)
                .is_none()
        );

        assert!(incoming.decrypt(nullifier(7), original).is_none());
    }

    #[test]
    fn sender_recovery_rejects_value_and_outgoing_ciphertext_tampering() {
        let (full_viewing_key, address, _incoming) = wallet();
        let outgoing = full_viewing_key.outgoing_viewing_key(KeyScope::External);
        let action_nullifier = nullifier(10);
        let mut rng = ChaCha20Rng::from_seed([13; 32]);
        let prepared = PreparedNoteOutput::create(
            &full_viewing_key,
            KeyScope::External,
            address,
            314,
            MAXIMUM_VALUE,
            action_nullifier,
            [2; MEMO_BYTES],
            &mut rng,
        )
        .unwrap();
        let original = prepared.encrypted_note();

        let mut value_commitment = original.value_commitment;
        value_commitment[0] ^= 1;
        let tampered_value_commitment = EncryptedNote {
            value_commitment,
            ..original.clone()
        };
        assert!(
            outgoing
                .recover(action_nullifier, &tampered_value_commitment)
                .is_none()
        );

        let mut outgoing_ciphertext = original.outgoing_ciphertext;
        outgoing_ciphertext[0] ^= 1;
        let tampered_outgoing_ciphertext = EncryptedNote {
            outgoing_ciphertext,
            ..original.clone()
        };
        assert!(
            outgoing
                .recover(action_nullifier, &tampered_outgoing_ciphertext)
                .is_none()
        );
    }

    #[test]
    fn public_output_parser_rejects_noncanonical_fields() {
        assert_eq!(
            EncryptedNote::from_parts(
                [0; 32],
                [0; 32],
                [0; 32],
                [0; NOTE_CIPHERTEXT_BYTES],
                [0; OUTGOING_CIPHERTEXT_BYTES],
            )
            .unwrap_err(),
            PrivacyError::InvalidEncryptedOutput
        );

        let (full_viewing_key, address, _incoming) = wallet();
        let mut rng = ChaCha20Rng::from_seed([14; 32]);
        let prepared = PreparedNoteOutput::create(
            &full_viewing_key,
            KeyScope::External,
            address,
            271,
            MAXIMUM_VALUE,
            nullifier(11),
            [3; MEMO_BYTES],
            &mut rng,
        )
        .unwrap();
        let output = prepared.encrypted_note();
        assert_eq!(
            EncryptedNote::from_parts(
                output.note_commitment,
                output.value_commitment,
                [0; 32],
                output.note_ciphertext,
                output.outgoing_ciphertext,
            )
            .unwrap_err(),
            PrivacyError::InvalidEncryptedOutput
        );
    }

    #[test]
    fn nullifier_is_deterministic_for_owner_and_note_but_keyed_by_account() {
        let (full_viewing_key, address, _incoming) = wallet();
        let mut rng = ChaCha20Rng::from_seed([11; 32]);
        let note = PrivateNote::create(address, 77, MAXIMUM_VALUE, nullifier(8), &mut rng).unwrap();
        let first = full_viewing_key.note_nullifier(&note).unwrap();
        let second = full_viewing_key.note_nullifier(&note).unwrap();
        assert_eq!(first, second);

        let other = VaultSpendingKey::derive(&[0x6B; 32], NETWORK_A, 0)
            .unwrap()
            .full_viewing_key();
        assert_ne!(first, other.note_nullifier(&note).unwrap());
    }

    #[test]
    fn invalid_boundaries_are_rejected() {
        assert_eq!(
            VaultSpendingKey::derive(&[1; 31], NETWORK_A, 0).unwrap_err(),
            PrivacyError::SeedTooShort
        );
        assert_eq!(
            VaultSpendingKey::derive(&WALLET_SEED, [0; 32], 0).unwrap_err(),
            PrivacyError::ZeroNetworkId
        );
        assert_eq!(
            ActionNullifier::from_bytes([0; 32]).unwrap_err(),
            PrivacyError::InvalidActionNullifier
        );

        let (_full_viewing_key, address, _incoming) = wallet();
        let mut rng = ChaCha20Rng::from_seed([12; 32]);
        assert_eq!(
            PrivateNote::create(address, 101, 100, nullifier(9), &mut rng).unwrap_err(),
            PrivacyError::NoteValueOutOfRange
        );
    }

    #[test]
    fn randomized_spend_authorization_is_network_and_transaction_bound() {
        let spending_key = VaultSpendingKey::derive(&WALLET_SEED, NETWORK_A, 0).unwrap();
        let other_spending_key = VaultSpendingKey::derive(&[0x6B; 32], NETWORK_A, 0).unwrap();
        let mut rng = ChaCha20Rng::from_seed([16; 32]);
        let prepared = spending_key.prepare_spend_authorization(&mut rng).unwrap();
        let digest = SpendAuthorizationDigest::derive(NETWORK_A, [0x31; 32]).unwrap();
        let other_transaction = SpendAuthorizationDigest::derive(NETWORK_A, [0x32; 32]).unwrap();
        let other_network = SpendAuthorizationDigest::derive(NETWORK_B, [0x31; 32]).unwrap();

        assert_eq!(
            other_spending_key.sign_spend_authorization(&prepared, digest, &mut rng),
            Err(PrivacyError::AuthorizationKeyMismatch)
        );
        let authorization = spending_key
            .sign_spend_authorization(&prepared, digest, &mut rng)
            .unwrap();
        assert_eq!(
            authorization.randomized_verification_key(),
            prepared.randomized_verification_key()
        );
        assert!(authorization.verify(digest));
        assert!(!authorization.verify(other_transaction));
        assert!(!authorization.verify(other_network));

        let mut signature = authorization.signature();
        signature[0] ^= 1;
        let tampered =
            SpendAuthorization::from_parts(authorization.randomized_verification_key(), signature)
                .unwrap();
        assert!(!tampered.verify(digest));
        assert_eq!(
            SpendAuthorization::from_parts([0; 32], [0; 64]).unwrap_err(),
            PrivacyError::InvalidSpendAuthorization
        );
    }

    #[test]
    fn every_spend_uses_a_fresh_randomized_validating_key() {
        let spending_key = VaultSpendingKey::derive(&WALLET_SEED, NETWORK_A, 0).unwrap();
        let mut rng = ChaCha20Rng::from_seed([17; 32]);
        let first = spending_key.prepare_spend_authorization(&mut rng).unwrap();
        let second = spending_key.prepare_spend_authorization(&mut rng).unwrap();
        assert_ne!(
            first.randomized_verification_key(),
            second.randomized_verification_key()
        );
        assert_ne!(*first.randomizer(), *second.randomizer());
    }
}
