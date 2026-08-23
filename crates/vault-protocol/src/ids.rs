use std::fmt;

fn write_hex(bytes: &[u8], formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

macro_rules! fixed_bytes_type {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Creates a value from its canonical 32-byte representation.
            #[must_use]
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Returns the canonical byte representation.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// Consumes the value and returns its bytes.
            #[must_use]
            pub const fn into_bytes(self) -> [u8; 32] {
                self.0
            }

            /// Whether every byte is zero, which is reserved as invalid in v1.
            #[must_use]
            pub fn is_zero(&self) -> bool {
                self.0.iter().all(|byte| *byte == 0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, concat!(stringify!($name), "("))?;
                write_hex(&self.0[..4], formatter)?;
                write!(formatter, "…)")
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write_hex(&self.0, formatter)
            }
        }
    };
}

fixed_bytes_type!(ChainId, "Domain identifier for one Vault network.");
fixed_bytes_type!(
    CircuitId,
    "Identifier of an accepted proof program and version."
);
fixed_bytes_type!(
    StateRoot,
    "Root of an authenticated shielded-state snapshot."
);
fixed_bytes_type!(
    Nullifier,
    "Unique public marker for one consumed private note."
);
fixed_bytes_type!(
    NoteCommitment,
    "Hiding commitment to one private output note."
);
fixed_bytes_type!(
    BalanceCommitment,
    "Hiding commitment to a transaction value balance."
);
fixed_bytes_type!(
    BurnCommitment,
    "Hiding commitment to the mandatory VLT burn."
);
fixed_bytes_type!(
    EphemeralKey,
    "Ephemeral public key used to encrypt an output note."
);
fixed_bytes_type!(
    PublicInputDigest,
    "Digest bound as the proof's public statement."
);
fixed_bytes_type!(
    TransactionId,
    "Content-derived identifier for a shielded transaction."
);
