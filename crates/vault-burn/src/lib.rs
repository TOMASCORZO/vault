//! Production-intent 64-byte additively homomorphic burn ciphertexts.
//!
//! The construction is exponential ElGamal over Pallas:
//!
//! ```text
//! C1 = [r]G
//! C2 = [burn]H + [r]PK_epoch
//! ```
//!
//! `G` is the Pallas generator and `H` is independently derived with
//! hash-to-curve under a Vault domain. Ciphertexts aggregate by point addition.
//! The transfer circuit must prove these equations with the same hidden burn
//! used by conservation and the burn commitment.
//!
//! This crate validates a DKG result and implements zeroized secret-share
//! import, publicly verifiable aggregate decryption shares, and interpolation.
//! It does not implement the DKG network protocol, consensus publication, or
//! bounded discrete-log recovery. Those remain prerequisites before activation
//! with real funds.

use std::fmt;

use ff::{Field, FromUniformBytes, PrimeField};
use pasta_curves::{
    arithmetic::CurveExt,
    group::{Group, GroupEncoding},
    pallas,
};
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

#[cfg(test)]
const SCHEME_ID_DOMAIN: &str = "vault.burn.pallas-threshold-elgamal-v1.id.2026-08-22";
const KEY_ID_DOMAIN: &str = "vault.burn.pallas-threshold-elgamal-v1.epoch-key.2026-08-22";
const DECRYPTION_SHARE_DOMAIN: &str =
    "vault.burn.pallas-threshold-elgamal-v1.decryption-share.2026-08-22";
const MESSAGE_GENERATOR_DOMAIN: &str = "vault.burn.pallas-threshold-elgamal-v1.message";
const MESSAGE_GENERATOR_INPUT: &[u8] = b"VLT burn amount generator";
const MAXIMUM_RANDOMNESS_ATTEMPTS: usize = 1 << 16;

/// Exact wire size: two canonical compressed Pallas points.
pub const BURN_CIPHERTEXT_BYTES: usize = 64;
/// Defensive bound on one epoch validator set.
pub const MAX_BURN_PARTICIPANTS: usize = 512;
/// Frozen identifier of the exact Pallas exponential-ElGamal construction.
pub const BURN_ENCRYPTION_SCHEME_ID: [u8; 32] = [
    0x97, 0x9c, 0x61, 0xf6, 0xd1, 0x2a, 0x25, 0xda, 0x66, 0xd5, 0xcf, 0xfc, 0x65, 0x9c, 0xb9, 0x96,
    0xd6, 0xf2, 0xcb, 0x12, 0x91, 0xad, 0x31, 0xce, 0x9d, 0xc0, 0xe9, 0x31, 0x46, 0x99, 0x6f, 0x82,
];

/// Validation and construction failures for the burn-encryption suite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BurnEncryptionError {
    /// Threshold is below two or exceeds the participant count.
    InvalidThreshold,
    /// Participant IDs are empty, zero, repeated, unsorted, or over the bound.
    InvalidParticipants,
    /// Feldman coefficient commitments are malformed or inconsistent.
    InvalidKeyCommitments,
    /// A requested amount exceeds the caller's monetary-policy bound.
    AmountOutOfRange,
    /// Ciphertext point bytes are non-canonical or `C1` is the identity.
    InvalidCiphertext,
    /// Random sampling failed to produce a canonical non-degenerate ciphertext.
    EncryptionFailed,
    /// No ciphertexts were supplied for aggregation.
    EmptyAggregation,
    /// Secret share is non-canonical or inconsistent with the epoch DKG.
    InvalidSecretShare,
    /// A decryption share or its DLEQ proof is malformed or invalid.
    InvalidDecryptionShare,
    /// Decryption did not contain exactly the sorted threshold subset.
    InvalidDecryptionShareSet,
}

impl fmt::Display for BurnEncryptionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidThreshold => "invalid burn-key threshold",
            Self::InvalidParticipants => "invalid burn-key participant set",
            Self::InvalidKeyCommitments => "invalid burn-key coefficient commitments",
            Self::AmountOutOfRange => "burn amount exceeds the policy bound",
            Self::InvalidCiphertext => "invalid burn ciphertext",
            Self::EncryptionFailed => "failed to construct burn ciphertext",
            Self::EmptyAggregation => "cannot aggregate an empty ciphertext set",
            Self::InvalidSecretShare => "invalid epoch burn secret share",
            Self::InvalidDecryptionShare => "invalid burn decryption share",
            Self::InvalidDecryptionShareSet => "invalid burn decryption share set",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for BurnEncryptionError {}

/// Public epoch key produced by a reviewed verifiable DKG.
///
/// `coefficient_commitments[j] = [a_j]G` commits to a degree `threshold - 1`
/// Shamir polynomial. Participant `i` has verification key
/// `sum_j [i^j] coefficient_commitments[j]`. This representation lets every
/// decryption share be checked against the exact DKG result without trusting a
/// separately supplied share key.
#[derive(Clone, Eq, PartialEq)]
pub struct EpochBurnPublicKey {
    epoch: u64,
    threshold: u16,
    participants: Vec<u16>,
    coefficient_commitments: Vec<[u8; 32]>,
    encryption_key: [u8; 32],
    key_id: [u8; 32],
}

impl fmt::Debug for EpochBurnPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EpochBurnPublicKey")
            .field("epoch", &self.epoch)
            .field("threshold", &self.threshold)
            .field("participants", &self.participants)
            .field("key_id", &HexPrefix(&self.key_id[..6]))
            .finish_non_exhaustive()
    }
}

impl EpochBurnPublicKey {
    /// Parses and validates a canonical DKG result.
    pub fn from_parts(
        epoch: u64,
        threshold: u16,
        participants: Vec<u16>,
        coefficient_commitments: Vec<[u8; 32]>,
    ) -> Result<Self, BurnEncryptionError> {
        let threshold_usize = usize::from(threshold);
        if threshold < 2
            || threshold_usize > participants.len()
            || coefficient_commitments.len() != threshold_usize
        {
            return Err(BurnEncryptionError::InvalidThreshold);
        }
        if participants.is_empty()
            || participants.len() > MAX_BURN_PARTICIPANTS
            || participants[0] == 0
            || participants.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(BurnEncryptionError::InvalidParticipants);
        }

        let commitments = coefficient_commitments
            .iter()
            .map(parse_point)
            .collect::<Result<Vec<_>, _>>()?;
        if bool::from(commitments[0].is_identity())
            || participants.iter().any(|participant| {
                bool::from(evaluate_commitments(&commitments, *participant).is_identity())
            })
        {
            return Err(BurnEncryptionError::InvalidKeyCommitments);
        }

        let encryption_key = commitments[0].to_bytes();
        let key_id = derive_key_id(epoch, threshold, &participants, &coefficient_commitments);
        Ok(Self {
            epoch,
            threshold,
            participants,
            coefficient_commitments,
            encryption_key,
            key_id,
        })
    }

    /// Epoch selected by the transaction burn payload.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Number of valid shares required for aggregate decryption.
    #[must_use]
    pub const fn threshold(&self) -> u16 {
        self.threshold
    }

    /// Canonically sorted, non-zero Shamir evaluation points.
    #[must_use]
    pub fn participants(&self) -> &[u16] {
        &self.participants
    }

    /// Digest committed by transfer-v2 `burn_key_id`.
    #[must_use]
    pub const fn key_id(&self) -> [u8; 32] {
        self.key_id
    }

    /// Canonical epoch ElGamal public key `[a_0]G`.
    #[must_use]
    pub const fn encryption_key(&self) -> [u8; 32] {
        self.encryption_key
    }

    /// Canonical Feldman commitments in increasing polynomial degree.
    #[must_use]
    pub fn coefficient_commitments(&self) -> &[[u8; 32]] {
        &self.coefficient_commitments
    }

    /// Derives one participant's public share-verification key from the DKG
    /// coefficient commitments.
    #[must_use]
    pub fn participant_verification_key(&self, participant: u16) -> Option<[u8; 32]> {
        self.participants.binary_search(&participant).ok()?;
        let commitments = self
            .coefficient_commitments
            .iter()
            .map(parse_point)
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        Some(evaluate_commitments(&commitments, participant).to_bytes())
    }

    fn encryption_point(&self) -> pallas::Point {
        parse_point(&self.encryption_key).expect("epoch key is validated at construction")
    }
}

/// One validator's zeroized Shamir share for an epoch burn key.
pub struct EpochBurnSecretShare {
    participant: u16,
    scalar: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for EpochBurnSecretShare {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EpochBurnSecretShare")
            .field("participant", &self.participant)
            .field("scalar", &"REDACTED")
            .finish()
    }
}

impl EpochBurnSecretShare {
    /// Imports a canonical non-zero share and verifies `[share]G` against the
    /// DKG coefficient commitments before retaining it.
    pub fn from_bytes(
        participant: u16,
        mut scalar: [u8; 32],
        epoch_key: &EpochBurnPublicKey,
    ) -> Result<Self, BurnEncryptionError> {
        let parsed = Option::<pallas::Scalar>::from(pallas::Scalar::from_repr(scalar));
        let Some(parsed) = parsed.filter(|value| !bool::from(value.is_zero())) else {
            scalar.zeroize();
            return Err(BurnEncryptionError::InvalidSecretShare);
        };
        let Some(expected) = epoch_key.participant_verification_key(participant) else {
            scalar.zeroize();
            return Err(BurnEncryptionError::InvalidSecretShare);
        };
        if (pallas::Point::generator() * parsed).to_bytes() != expected {
            scalar.zeroize();
            return Err(BurnEncryptionError::InvalidSecretShare);
        }
        Ok(Self {
            participant,
            scalar: Zeroizing::new(scalar),
        })
    }

    /// Participant evaluation point committed by the epoch key.
    #[must_use]
    pub const fn participant(&self) -> u16 {
        self.participant
    }

    /// Produces a share for the aggregate only, with a Fiat-Shamir
    /// Chaum-Pedersen proof that the same secret exponent underlies the public
    /// share key and decryption share.
    pub fn create_decryption_share<R: RngCore + CryptoRng>(
        &self,
        epoch_key: &EpochBurnPublicKey,
        ciphertext: AggregatedBurnCiphertext,
        rng: &mut R,
    ) -> Result<BurnDecryptionShare, BurnEncryptionError> {
        let scalar = parse_scalar(&self.scalar)?;
        let verification_key = parse_point(
            &epoch_key
                .participant_verification_key(self.participant)
                .ok_or(BurnEncryptionError::InvalidSecretShare)?,
        )?;
        if (pallas::Point::generator() * scalar) != verification_key {
            return Err(BurnEncryptionError::InvalidSecretShare);
        }
        let (c1, _) = ciphertext.points();
        let share = c1 * scalar;

        for _ in 0..MAXIMUM_RANDOMNESS_ATTEMPTS {
            let nonce = pallas::Scalar::random(&mut *rng);
            if bool::from(nonce.is_zero()) {
                continue;
            }
            let announcement_g = pallas::Point::generator() * nonce;
            let announcement_c1 = c1 * nonce;
            let challenge = decryption_share_challenge(
                epoch_key,
                ciphertext,
                self.participant,
                verification_key,
                share,
                announcement_g,
                announcement_c1,
            );
            let response = nonce + challenge * scalar;
            return Ok(BurnDecryptionShare {
                participant: self.participant,
                share: share.to_bytes(),
                challenge: challenge.to_repr(),
                response: response.to_repr(),
            });
        }
        Err(BurnEncryptionError::EncryptionFailed)
    }
}

/// Canonical individual 64-byte burn ciphertext.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct BurnCiphertext([u8; BURN_CIPHERTEXT_BYTES]);

impl fmt::Debug for BurnCiphertext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("BurnCiphertext")
            .field(&HexPrefix(&self.0[..6]))
            .finish()
    }
}

impl BurnCiphertext {
    /// Parses two canonical Pallas points and rejects identity `C1`.
    pub fn from_bytes(bytes: [u8; BURN_CIPHERTEXT_BYTES]) -> Result<Self, BurnEncryptionError> {
        let c1 = parse_ciphertext_point(&bytes[..32].try_into().expect("fixed slice length"))?;
        parse_ciphertext_point(&bytes[32..].try_into().expect("fixed slice length"))?;
        if bool::from(c1.is_identity()) {
            return Err(BurnEncryptionError::InvalidCiphertext);
        }
        Ok(Self(bytes))
    }

    /// Exact `(C1, C2)` compressed encoding.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; BURN_CIPHERTEXT_BYTES] {
        self.0
    }

    /// Reconstructs the exact circuit-compatible ciphertext from a private
    /// amount and randomness opening. Reference proof backends use this to
    /// enforce the same ElGamal equations as the specialized Halo2 gadget.
    pub fn derive_opening(
        amount: u64,
        maximum_amount: u64,
        epoch_key: &EpochBurnPublicKey,
        randomness: [u8; 32],
    ) -> Result<Self, BurnEncryptionError> {
        if amount > maximum_amount || randomness == [0; 32] {
            return Err(BurnEncryptionError::AmountOutOfRange);
        }
        let randomness_base = Option::<pallas::Base>::from(pallas::Base::from_repr(randomness))
            .ok_or(BurnEncryptionError::InvalidCiphertext)?;
        if bool::from(randomness_base.is_zero()) {
            return Err(BurnEncryptionError::InvalidCiphertext);
        }
        let randomness =
            Option::<pallas::Scalar>::from(pallas::Scalar::from_repr(randomness_base.to_repr()))
                .ok_or(BurnEncryptionError::InvalidCiphertext)?;
        let c1 = pallas::Point::generator() * randomness;
        let c2 = burn_message_generator() * pallas::Scalar::from(amount)
            + epoch_key.encryption_point() * randomness;
        if bool::from(c2.is_identity()) {
            return Err(BurnEncryptionError::InvalidCiphertext);
        }
        Self::from_bytes(encode_points(c1, c2))
    }

    fn points(self) -> (pallas::Point, pallas::Point) {
        (
            parse_ciphertext_point(&self.0[..32].try_into().expect("fixed slice length"))
                .expect("ciphertext is validated at construction"),
            parse_ciphertext_point(&self.0[32..].try_into().expect("fixed slice length"))
                .expect("ciphertext is validated at construction"),
        )
    }
}

/// Secret prover package linking the exact burn amount and ElGamal randomness.
pub struct PreparedBurnCiphertext {
    amount: u64,
    randomness: Zeroizing<[u8; 32]>,
    ciphertext: BurnCiphertext,
}

impl fmt::Debug for PreparedBurnCiphertext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedBurnCiphertext(REDACTED)")
    }
}

impl Drop for PreparedBurnCiphertext {
    fn drop(&mut self) {
        self.amount.zeroize();
    }
}

impl PreparedBurnCiphertext {
    /// Encrypts an amount under the exact epoch key with fresh non-zero
    /// randomness. `maximum_amount` must match the activated monetary bound.
    pub fn encrypt<R: RngCore + CryptoRng>(
        amount: u64,
        maximum_amount: u64,
        epoch_key: &EpochBurnPublicKey,
        rng: &mut R,
    ) -> Result<Self, BurnEncryptionError> {
        if amount > maximum_amount {
            return Err(BurnEncryptionError::AmountOutOfRange);
        }
        let public_key = epoch_key.encryption_point();
        let message = burn_message_generator() * pallas::Scalar::from(amount);
        for _ in 0..MAXIMUM_RANDOMNESS_ATTEMPTS {
            let randomness_base = pallas::Base::random(&mut *rng);
            if bool::from(randomness_base.is_zero()) {
                continue;
            }
            let randomness = Option::<pallas::Scalar>::from(pallas::Scalar::from_repr(
                randomness_base.to_repr(),
            ))
            .expect("every canonical Pallas base element fits its scalar field");
            let c1 = pallas::Point::generator() * randomness;
            let c2 = message + public_key * randomness;
            // C2 identity is valid in the abstract scheme but rejecting it
            // produces a unique non-degenerate wire policy with negligible
            // resampling probability.
            if bool::from(c2.is_identity()) {
                continue;
            }
            let ciphertext = BurnCiphertext::from_bytes(encode_points(c1, c2))?;
            return Ok(Self {
                amount,
                randomness: Zeroizing::new(randomness_base.to_repr()),
                ciphertext,
            });
        }
        Err(BurnEncryptionError::EncryptionFailed)
    }

    /// Hidden amount consumed by the specialized circuit witness.
    #[must_use]
    pub const fn amount(&self) -> u64 {
        self.amount
    }

    /// Returns a zeroizing copy of the circuit's encryption-randomness witness.
    #[must_use]
    pub fn randomness(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.randomness)
    }

    /// Public 64-byte payload included in transfer-v2.
    #[must_use]
    pub const fn ciphertext(&self) -> BurnCiphertext {
        self.ciphertext
    }
}

/// Homomorphic sum of one or more validated burn ciphertexts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregatedBurnCiphertext([u8; BURN_CIPHERTEXT_BYTES]);

impl AggregatedBurnCiphertext {
    /// Restores a persisted aggregate from two canonical point encodings.
    /// Identity components are allowed because valid component sums can cancel.
    pub fn from_bytes(bytes: [u8; BURN_CIPHERTEXT_BYTES]) -> Result<Self, BurnEncryptionError> {
        parse_ciphertext_point(&bytes[..32].try_into().expect("fixed slice length"))?;
        parse_ciphertext_point(&bytes[32..].try_into().expect("fixed slice length"))?;
        Ok(Self(bytes))
    }

    /// Adds ciphertext components without decrypting individual burn amounts.
    pub fn aggregate(ciphertexts: &[BurnCiphertext]) -> Result<Self, BurnEncryptionError> {
        let first = ciphertexts
            .first()
            .ok_or(BurnEncryptionError::EmptyAggregation)?;
        let (mut c1, mut c2) = first.points();
        for ciphertext in &ciphertexts[1..] {
            let (next_c1, next_c2) = ciphertext.points();
            c1 += next_c1;
            c2 += next_c2;
        }
        Ok(Self(encode_points(c1, c2)))
    }

    /// Exact aggregate `(sum C1, sum C2)` encoding.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; BURN_CIPHERTEXT_BYTES] {
        self.0
    }

    fn points(self) -> (pallas::Point, pallas::Point) {
        (
            parse_ciphertext_point(&self.0[..32].try_into().expect("fixed slice length"))
                .expect("aggregate contains sums of canonical points"),
            parse_ciphertext_point(&self.0[32..].try_into().expect("fixed slice length"))
                .expect("aggregate contains sums of canonical points"),
        )
    }
}

/// One publicly verifiable threshold decryption share for an aggregate.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BurnDecryptionShare {
    participant: u16,
    share: [u8; 32],
    challenge: [u8; 32],
    response: [u8; 32],
}

impl fmt::Debug for BurnDecryptionShare {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BurnDecryptionShare")
            .field("participant", &self.participant)
            .field("share", &HexPrefix(&self.share[..6]))
            .field("proof", &"Chaum-Pedersen 64 bytes")
            .finish()
    }
}

impl BurnDecryptionShare {
    /// Parses canonical point/scalar encodings. Cryptographic validity is
    /// checked separately by [`Self::verify`] against an epoch and aggregate.
    pub fn from_parts(
        participant: u16,
        share: [u8; 32],
        challenge: [u8; 32],
        response: [u8; 32],
    ) -> Result<Self, BurnEncryptionError> {
        parse_ciphertext_point(&share)?;
        parse_scalar(&challenge)?;
        parse_scalar(&response)?;
        if participant == 0 {
            return Err(BurnEncryptionError::InvalidDecryptionShare);
        }
        Ok(Self {
            participant,
            share,
            challenge,
            response,
        })
    }

    /// Shamir evaluation point of the validator producing this share.
    #[must_use]
    pub const fn participant(&self) -> u16 {
        self.participant
    }

    /// Canonical decryption-share point `[share_i]C1`.
    #[must_use]
    pub const fn share(&self) -> [u8; 32] {
        self.share
    }

    /// Canonical `(challenge, response)` Chaum-Pedersen proof.
    #[must_use]
    pub const fn proof(&self) -> [u8; 64] {
        let mut proof = [0; 64];
        let mut index = 0;
        while index < 32 {
            proof[index] = self.challenge[index];
            proof[index + 32] = self.response[index];
            index += 1;
        }
        proof
    }

    /// Verifies equality of discrete logarithms between `(G, Y_i)` and
    /// `(aggregate.C1, share_i)` without revealing the secret share.
    #[must_use]
    pub fn verify(
        &self,
        epoch_key: &EpochBurnPublicKey,
        ciphertext: AggregatedBurnCiphertext,
    ) -> bool {
        let Some(verification_key) = epoch_key
            .participant_verification_key(self.participant)
            .and_then(|bytes| parse_point(&bytes).ok())
        else {
            return false;
        };
        let Ok(share) = parse_ciphertext_point(&self.share) else {
            return false;
        };
        let Ok(challenge) = parse_scalar(&self.challenge) else {
            return false;
        };
        let Ok(response) = parse_scalar(&self.response) else {
            return false;
        };
        let (c1, _) = ciphertext.points();
        let announcement_g = pallas::Point::generator() * response - verification_key * challenge;
        let announcement_c1 = c1 * response - share * challenge;
        decryption_share_challenge(
            epoch_key,
            ciphertext,
            self.participant,
            verification_key,
            share,
            announcement_g,
            announcement_c1,
        ) == challenge
    }
}

/// Decrypted group encoding `[aggregate_burn]H`.
///
/// Converting this point to an integer requires the separately bounded
/// discrete-log recovery step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveredBurnMessage([u8; 32]);

impl RecoveredBurnMessage {
    /// Canonical Pallas group encoding of the aggregate burn message.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Native oracle used by tests and bounded recovery implementations.
    #[must_use]
    pub fn matches_amount(self, amount: u64) -> bool {
        parse_ciphertext_point(&self.0)
            .is_ok_and(|message| message == burn_message_generator() * pallas::Scalar::from(amount))
    }
}

/// Verifies exactly `threshold` sorted shares, interpolates them at zero, and
/// removes the aggregate ElGamal mask.
pub fn recover_aggregate_message(
    epoch_key: &EpochBurnPublicKey,
    ciphertext: AggregatedBurnCiphertext,
    shares: &[BurnDecryptionShare],
) -> Result<RecoveredBurnMessage, BurnEncryptionError> {
    if shares.len() != usize::from(epoch_key.threshold)
        || shares
            .windows(2)
            .any(|pair| pair[0].participant >= pair[1].participant)
        || shares
            .iter()
            .any(|share| !share.verify(epoch_key, ciphertext))
    {
        return Err(BurnEncryptionError::InvalidDecryptionShareSet);
    }

    let mut mask = pallas::Point::identity();
    for (index, share) in shares.iter().enumerate() {
        let x_i = pallas::Scalar::from(u64::from(share.participant));
        let mut numerator = pallas::Scalar::ONE;
        let mut denominator = pallas::Scalar::ONE;
        for (other_index, other) in shares.iter().enumerate() {
            if other_index == index {
                continue;
            }
            let x_j = pallas::Scalar::from(u64::from(other.participant));
            numerator *= -x_j;
            denominator *= x_i - x_j;
        }
        let Some(inverse) = Option::<pallas::Scalar>::from(denominator.invert()) else {
            return Err(BurnEncryptionError::InvalidDecryptionShareSet);
        };
        let lagrange = numerator * inverse;
        let share_point = parse_ciphertext_point(&share.share)?;
        mask += share_point * lagrange;
    }

    let (_, c2) = ciphertext.points();
    Ok(RecoveredBurnMessage((c2 - mask).to_bytes()))
}

/// Digest of the exact curve, generators, equations, and wire encoding.
#[must_use]
pub fn burn_encryption_scheme_id() -> [u8; 32] {
    BURN_ENCRYPTION_SCHEME_ID
}

/// Canonical compressed Pallas point `H` used to encode burn amounts.
///
/// Circuit parameter generation consumes this exact point rather than
/// reinterpreting a textual scheme label.
#[must_use]
pub fn burn_message_generator_bytes() -> [u8; 32] {
    burn_message_generator().to_bytes()
}

#[cfg(test)]
fn derive_burn_encryption_scheme_id() -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(SCHEME_ID_DOMAIN);
    hasher.update(b"Pallas");
    hasher.update(&pallas::Point::generator().to_bytes());
    hasher.update(&burn_message_generator().to_bytes());
    hasher.update(
        b"C1=[r]G;C2=[burn]H+[r]PK;r=uniform-nonzero-Fp-embedded-in-Fq;compressed-pallas-le;64-bytes",
    );
    *hasher.finalize().as_bytes()
}

fn burn_message_generator() -> pallas::Point {
    pallas::Point::hash_to_curve(MESSAGE_GENERATOR_DOMAIN)(MESSAGE_GENERATOR_INPUT)
}

fn parse_point(bytes: &[u8; 32]) -> Result<pallas::Point, BurnEncryptionError> {
    Option::<pallas::Point>::from(pallas::Point::from_bytes(bytes))
        .ok_or(BurnEncryptionError::InvalidKeyCommitments)
}

fn parse_ciphertext_point(bytes: &[u8; 32]) -> Result<pallas::Point, BurnEncryptionError> {
    Option::<pallas::Point>::from(pallas::Point::from_bytes(bytes))
        .ok_or(BurnEncryptionError::InvalidCiphertext)
}

fn parse_scalar(bytes: &[u8; 32]) -> Result<pallas::Scalar, BurnEncryptionError> {
    Option::<pallas::Scalar>::from(pallas::Scalar::from_repr(*bytes))
        .ok_or(BurnEncryptionError::InvalidDecryptionShare)
}

#[allow(clippy::too_many_arguments)]
fn decryption_share_challenge(
    epoch_key: &EpochBurnPublicKey,
    ciphertext: AggregatedBurnCiphertext,
    participant: u16,
    verification_key: pallas::Point,
    share: pallas::Point,
    announcement_g: pallas::Point,
    announcement_c1: pallas::Point,
) -> pallas::Scalar {
    let mut hasher = blake3::Hasher::new_derive_key(DECRYPTION_SHARE_DOMAIN);
    hasher.update(&BURN_ENCRYPTION_SCHEME_ID);
    hasher.update(&epoch_key.key_id);
    hasher.update(&ciphertext.0);
    hasher.update(&participant.to_le_bytes());
    hasher.update(&verification_key.to_bytes());
    hasher.update(&share.to_bytes());
    hasher.update(&announcement_g.to_bytes());
    hasher.update(&announcement_c1.to_bytes());
    let mut uniform = [0; 64];
    hasher.finalize_xof().fill(&mut uniform);
    pallas::Scalar::from_uniform_bytes(&uniform)
}

fn evaluate_commitments(commitments: &[pallas::Point], participant: u16) -> pallas::Point {
    let x = pallas::Scalar::from(u64::from(participant));
    commitments
        .iter()
        .fold(
            (pallas::Point::identity(), pallas::Scalar::ONE),
            |(sum, power), commitment| (sum + commitment * power, power * x),
        )
        .0
}

fn derive_key_id(
    epoch: u64,
    threshold: u16,
    participants: &[u16],
    coefficient_commitments: &[[u8; 32]],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(KEY_ID_DOMAIN);
    hasher.update(&burn_encryption_scheme_id());
    hasher.update(&epoch.to_le_bytes());
    hasher.update(&threshold.to_le_bytes());
    hasher.update(&(participants.len() as u64).to_le_bytes());
    for participant in participants {
        hasher.update(&participant.to_le_bytes());
    }
    for commitment in coefficient_commitments {
        hasher.update(commitment);
    }
    *hasher.finalize().as_bytes()
}

fn encode_points(c1: pallas::Point, c2: pallas::Point) -> [u8; BURN_CIPHERTEXT_BYTES] {
    let mut bytes = [0; BURN_CIPHERTEXT_BYTES];
    bytes[..32].copy_from_slice(&c1.to_bytes());
    bytes[32..].copy_from_slice(&c2.to_bytes());
    bytes
}

struct HexPrefix<'a>(&'a [u8]);

impl fmt::Debug for HexPrefix<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str("…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

    const MAXIMUM_AMOUNT: u64 = 21_000_000 * 1_000_000_000;

    fn epoch_key() -> (EpochBurnPublicKey, [pallas::Scalar; 2]) {
        let coefficients = [pallas::Scalar::from(7), pallas::Scalar::from(11)];
        let commitments =
            coefficients.map(|coefficient| (pallas::Point::generator() * coefficient).to_bytes());
        (
            EpochBurnPublicKey::from_parts(9, 2, vec![1, 2, 3], commitments.to_vec()).unwrap(),
            coefficients,
        )
    }

    fn decrypt_message(
        bytes: [u8; BURN_CIPHERTEXT_BYTES],
        secret: pallas::Scalar,
    ) -> pallas::Point {
        let c1 = Option::<pallas::Point>::from(pallas::Point::from_bytes(
            &bytes[..32].try_into().unwrap(),
        ))
        .unwrap();
        let c2 = Option::<pallas::Point>::from(pallas::Point::from_bytes(
            &bytes[32..].try_into().unwrap(),
        ))
        .unwrap();
        c2 - c1 * secret
    }

    #[test]
    fn encryption_and_aggregation_preserve_the_hidden_sum() {
        let (key, coefficients) = epoch_key();
        let mut rng = ChaCha20Rng::from_seed([0x81; 32]);
        let first = PreparedBurnCiphertext::encrypt(50, MAXIMUM_AMOUNT, &key, &mut rng).unwrap();
        let second = PreparedBurnCiphertext::encrypt(25, MAXIMUM_AMOUNT, &key, &mut rng).unwrap();

        assert_eq!(
            decrypt_message(first.ciphertext().to_bytes(), coefficients[0]),
            burn_message_generator() * pallas::Scalar::from(50)
        );
        let aggregate =
            AggregatedBurnCiphertext::aggregate(&[first.ciphertext(), second.ciphertext()])
                .unwrap();
        assert_eq!(
            AggregatedBurnCiphertext::from_bytes(aggregate.to_bytes()).unwrap(),
            aggregate
        );
        assert_eq!(
            decrypt_message(aggregate.to_bytes(), coefficients[0]),
            burn_message_generator() * pallas::Scalar::from(75)
        );
        assert_ne!(first.ciphertext(), second.ciphertext());
        assert_eq!(first.amount(), 50);
        assert_ne!(*first.randomness(), [0; 32]);
        assert_eq!(
            derive_burn_encryption_scheme_id(),
            BURN_ENCRYPTION_SCHEME_ID
        );
        assert_eq!(
            key.key_id(),
            [
                0x91, 0xec, 0xb3, 0x2e, 0xf0, 0xde, 0x69, 0x60, 0x41, 0xe2, 0x52, 0x6e, 0x1b, 0xa5,
                0xe3, 0xd0, 0xd8, 0x45, 0x49, 0x18, 0x59, 0x13, 0xe8, 0x17, 0x63, 0xed, 0x15, 0xaa,
                0xe3, 0xa4, 0x2e, 0x78,
            ]
        );
        assert_eq!(
            first.ciphertext().to_bytes(),
            [
                0xda, 0xfb, 0x41, 0xe1, 0x54, 0xc5, 0xb3, 0x04, 0xc5, 0x03, 0xeb, 0x78, 0x82, 0x26,
                0xeb, 0xc4, 0x82, 0x06, 0x27, 0x53, 0xb7, 0xae, 0xe3, 0x8f, 0x56, 0xc4, 0xee, 0x87,
                0x02, 0xb9, 0x4d, 0xae, 0x76, 0xa5, 0xfe, 0x49, 0x7f, 0x7d, 0xf8, 0x93, 0xc6, 0x91,
                0x65, 0x78, 0x0c, 0xb1, 0x7f, 0xf0, 0xbb, 0x8b, 0xd5, 0x27, 0x9b, 0xd9, 0x26, 0xb6,
                0x10, 0x36, 0xf7, 0x31, 0x4e, 0xe8, 0x31, 0xa2,
            ]
        );
    }

    #[test]
    fn key_descriptor_is_canonical_and_derives_share_keys() {
        let (key, _) = epoch_key();
        assert_eq!(key.epoch(), 9);
        assert_eq!(key.threshold(), 2);
        assert_eq!(key.participants(), &[1, 2, 3]);
        assert_ne!(key.key_id(), [0; 32]);
        assert_ne!(key.encryption_key(), [0; 32]);
        assert!(key.participant_verification_key(2).is_some());
        assert!(key.participant_verification_key(4).is_none());

        let commitments = vec![pallas::Point::generator().to_bytes(); 2];
        assert_eq!(
            EpochBurnPublicKey::from_parts(1, 1, vec![1, 2], commitments.clone()),
            Err(BurnEncryptionError::InvalidThreshold)
        );
        assert_eq!(
            EpochBurnPublicKey::from_parts(1, 2, vec![2, 1], commitments),
            Err(BurnEncryptionError::InvalidParticipants)
        );
    }

    #[test]
    fn malformed_ciphertexts_and_bounds_fail_closed() {
        let (key, _) = epoch_key();
        let mut rng = ChaCha20Rng::from_seed([0x82; 32]);
        assert_eq!(
            PreparedBurnCiphertext::encrypt(MAXIMUM_AMOUNT + 1, MAXIMUM_AMOUNT, &key, &mut rng)
                .unwrap_err(),
            BurnEncryptionError::AmountOutOfRange
        );
        assert_eq!(
            BurnCiphertext::from_bytes([0; BURN_CIPHERTEXT_BYTES]),
            Err(BurnEncryptionError::InvalidCiphertext)
        );
        assert_eq!(
            BurnCiphertext::from_bytes([0xff; BURN_CIPHERTEXT_BYTES]),
            Err(BurnEncryptionError::InvalidCiphertext)
        );
        assert_eq!(
            AggregatedBurnCiphertext::aggregate(&[]),
            Err(BurnEncryptionError::EmptyAggregation)
        );
    }

    #[test]
    fn dleq_shares_verify_and_recover_only_the_aggregate_message() {
        let (key, coefficients) = epoch_key();
        let mut encryption_rng = ChaCha20Rng::from_seed([0x83; 32]);
        let first =
            PreparedBurnCiphertext::encrypt(50, MAXIMUM_AMOUNT, &key, &mut encryption_rng).unwrap();
        let second =
            PreparedBurnCiphertext::encrypt(25, MAXIMUM_AMOUNT, &key, &mut encryption_rng).unwrap();
        let aggregate =
            AggregatedBurnCiphertext::aggregate(&[first.ciphertext(), second.ciphertext()])
                .unwrap();

        let scalar_for = |participant: u16| {
            coefficients[0] + coefficients[1] * pallas::Scalar::from(u64::from(participant))
        };
        let secret_1 = EpochBurnSecretShare::from_bytes(1, scalar_for(1).to_repr(), &key).unwrap();
        let secret_2 = EpochBurnSecretShare::from_bytes(2, scalar_for(2).to_repr(), &key).unwrap();
        let mut share_rng_1 = ChaCha20Rng::from_seed([0x84; 32]);
        let mut share_rng_2 = ChaCha20Rng::from_seed([0x85; 32]);
        let share_1 = secret_1
            .create_decryption_share(&key, aggregate, &mut share_rng_1)
            .unwrap();
        let share_2 = secret_2
            .create_decryption_share(&key, aggregate, &mut share_rng_2)
            .unwrap();

        assert!(share_1.verify(&key, aggregate));
        assert!(share_2.verify(&key, aggregate));
        let recovered = recover_aggregate_message(&key, aggregate, &[share_1, share_2]).unwrap();
        assert!(recovered.matches_amount(75));
        assert!(!recovered.matches_amount(74));

        let mut tampered = share_1;
        tampered.response[0] ^= 1;
        assert!(!tampered.verify(&key, aggregate));
        assert_eq!(
            recover_aggregate_message(&key, aggregate, &[share_2, share_1]),
            Err(BurnEncryptionError::InvalidDecryptionShareSet)
        );
        assert_eq!(
            recover_aggregate_message(&key, aggregate, &[share_1]),
            Err(BurnEncryptionError::InvalidDecryptionShareSet)
        );
        assert_eq!(
            EpochBurnSecretShare::from_bytes(1, pallas::Scalar::from(99).to_repr(), &key)
                .unwrap_err(),
            BurnEncryptionError::InvalidSecretShare
        );
    }
}
