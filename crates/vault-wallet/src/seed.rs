//! Checked BIP-39 seed import boundary for wallet recovery.

use core::fmt;
use std::borrow::Cow;

use bip39::{Language, Mnemonic};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

/// Validated English BIP-39 mnemonic.
///
/// New mnemonics always contain 24 words backed by 256 bits of OS entropy.
/// Import accepts only the standard 12/15/18/21/24 word counts and verifies the
/// BIP-39 checksum. The wrapped library is built with NFKD normalization and
/// zeroization support.
pub struct WalletMnemonic(Mnemonic);

impl WalletMnemonic {
    /// Generates a new 24-word English mnemonic from 256 bits of OS entropy.
    pub fn generate() -> Result<Self, WalletMnemonicError> {
        let mut entropy = Zeroizing::new([0; 32]);
        OsRng
            .try_fill_bytes(&mut *entropy)
            .map_err(|_| WalletMnemonicError::EntropyUnavailable)?;
        Mnemonic::from_entropy_in(Language::English, entropy.as_ref())
            .map(Self)
            .map_err(|_| WalletMnemonicError::InvalidMnemonic)
    }

    /// Imports an English BIP-39 phrase with checksum and NFKD validation.
    ///
    /// Ownership of the input string is taken so its allocation is zeroized on
    /// return. Callers remain responsible for UI/widget/clipboard copies.
    pub fn parse(phrase: String) -> Result<Self, WalletMnemonicError> {
        let phrase = Zeroizing::new(phrase);
        let mnemonic = Mnemonic::parse_in(Language::English, phrase.as_str())
            .map_err(|_| WalletMnemonicError::InvalidMnemonic)?;
        if !matches!(mnemonic.word_count(), 12 | 15 | 18 | 21 | 24) {
            return Err(WalletMnemonicError::UnsupportedWordCount);
        }
        Ok(Self(mnemonic))
    }

    /// Number of validated BIP-39 words.
    #[must_use]
    pub fn word_count(&self) -> usize {
        self.0.word_count()
    }

    /// Produces an explicitly exposed zeroizing phrase for a confirmation or
    /// offline-backup ceremony.
    #[must_use]
    pub fn expose_phrase(&self) -> Zeroizing<String> {
        Zeroizing::new(self.0.to_string())
    }

    /// Derives the canonical 64-byte BIP-39 seed using the explicit passphrase.
    #[must_use]
    pub fn derive_seed(&self, passphrase: &WalletMnemonicPassphrase) -> WalletSeed {
        let mut normalized = Cow::Borrowed(passphrase.0.as_str());
        Mnemonic::normalize_utf8_cow(&mut normalized);
        let seed = match normalized {
            Cow::Borrowed(value) => self.0.to_seed_normalized(value),
            Cow::Owned(value) => {
                let value = Zeroizing::new(value);
                self.0.to_seed_normalized(value.as_str())
            }
        };
        WalletSeed(Zeroizing::new(seed))
    }
}

impl fmt::Debug for WalletMnemonic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalletMnemonic(REDACTED)")
    }
}

/// Explicit BIP-39 passphrase, including the deliberate empty choice.
///
/// Every passphrase produces a valid but different wallet. No checksum can
/// detect a typo, so product confirmation is mandatory before accepting funds.
pub struct WalletMnemonicPassphrase(Zeroizing<String>);

impl WalletMnemonicPassphrase {
    /// Takes ownership of a passphrase so the allocation is zeroized on drop.
    #[must_use]
    pub fn new(passphrase: String) -> Self {
        Self(Zeroizing::new(passphrase))
    }

    /// Explicitly selects the ordinary empty-passphrase BIP-39 profile.
    #[must_use]
    pub fn empty() -> Self {
        Self::new(String::new())
    }

    /// Whether the deliberately selected passphrase is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for WalletMnemonicPassphrase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalletMnemonicPassphrase(REDACTED)")
    }
}

/// Canonical 64-byte BIP-39 output consumed by Vault account derivation.
pub struct WalletSeed(Zeroizing<[u8; 64]>);

impl WalletSeed {
    /// Borrows the seed only for bounded account derivation.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl fmt::Debug for WalletSeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalletSeed(REDACTED)")
    }
}

/// Checked mnemonic generation/import failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalletMnemonicError {
    /// Operating-system entropy was unavailable.
    EntropyUnavailable,
    /// Words, language, normalization, or checksum are invalid.
    InvalidMnemonic,
    /// Word count is outside the BIP-39 12/15/18/21/24 profile.
    UnsupportedWordCount,
}

impl fmt::Display for WalletMnemonicError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EntropyUnavailable => "wallet mnemonic entropy is unavailable",
            Self::InvalidMnemonic => "wallet mnemonic is invalid",
            Self::UnsupportedWordCount => "wallet mnemonic word count is unsupported",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for WalletMnemonicError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_bip39_vector_and_checksum_gate_match() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = WalletMnemonic::parse(phrase.to_owned()).unwrap();
        assert_eq!(mnemonic.word_count(), 12);
        assert_eq!(format!("{mnemonic:?}"), "WalletMnemonic(REDACTED)");
        let passphrase = WalletMnemonicPassphrase::new("TREZOR".to_owned());
        let seed = mnemonic.derive_seed(&passphrase);
        let expected_hex = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
        let expected = expected_hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(seed.as_bytes().as_slice(), expected.as_slice());
        assert_eq!(format!("{seed:?}"), "WalletSeed(REDACTED)");

        let invalid = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert_eq!(
            WalletMnemonic::parse(invalid.to_owned()).unwrap_err(),
            WalletMnemonicError::InvalidMnemonic
        );
    }

    #[test]
    fn generated_profile_is_24_word_english_and_round_trips() {
        let generated = WalletMnemonic::generate().unwrap();
        assert_eq!(generated.word_count(), 24);
        let phrase = generated.expose_phrase();
        let reparsed = WalletMnemonic::parse(phrase.to_string()).unwrap();
        let empty = WalletMnemonicPassphrase::empty();
        assert!(empty.is_empty());
        assert_eq!(
            generated.derive_seed(&empty).as_bytes(),
            reparsed.derive_seed(&empty).as_bytes()
        );
    }
}
