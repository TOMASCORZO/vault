# Vault BIP-39 seed import and confirmation v1

**Status:** production-intent English BIP-39 generation/import boundary and
official vector implemented; platform input/confirmation UX, hardware import,
memory-lock/crash-dump controls, and independent review remain open
**Last updated:** 2026-08-27

## 1. Selected profile

Vault adopts [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
as the human mnemonic transport for H1-A2. It does not invent a word list or
accept a user-created sentence as seed material. The selected implementation is
the pinned `bip39 = 2.2.2` Rust crate with only `std`, NFKD normalization, and
zeroization enabled.

New wallets generate exactly 256 bits from the operating-system CSPRNG and
encode them as 24 English words. English is the only enabled list because the
BIP recommends it for interoperability. Import accepts checksum-valid English
BIP-39 sentences of 12, 15, 18, 21, or 24 words so existing standard backups
are not rejected merely because they use 128..224 bits of source entropy.
Unknown words, bad checksum, invalid count, and invalid normalization fail
before any Vault account is derived.

BIP-39 converts the NFKD mnemonic plus the explicit NFKD passphrase through
PBKDF2-HMAC-SHA512 with 2048 iterations into 64 bytes. Vault feeds exactly those
64 bytes into its existing network/account-separated
`VaultSpendingKey::derive`; it does not apply BIP-32/BIP-44 or reinterpret the
mnemonic entropy directly.

## 2. Secret-memory boundary

`WalletMnemonic` does not implement `Display` or `Clone`; `Debug` is redacted,
and the pinned crate zeroizes its word-index array on drop. Phrase exposure is
an explicit `expose_phrase()` operation returning a zeroizing string.
`WalletMnemonic::parse` takes ownership of the input allocation and zeroizes it
on return. `WalletMnemonicPassphrase` owns and zeroizes the deliberate empty or
non-empty choice. Any NFKD allocation created for a passphrase is explicitly
wrapped and zeroized. `WalletSeed` is a non-cloneable redacted zeroizing
64-byte value and is borrowed only for bounded account derivation.

These controls cannot erase copies retained by UI widgets, IMEs, accessibility
services, clipboard managers, screenshots, swap, hibernation, crash dumps,
debuggers, allocator history, or privileged processes. Platform adapters must
minimize and test those copies; the core types are not a memory-isolation claim.

## 3. Mandatory product ceremony

Generation:

1. generate only inside a local secret-entry surface with screen capture,
   telemetry, logging, autocomplete, and clipboard disabled where supported;
2. clearly label the 24 words as spend authority, never as the database key;
3. require offline recording and randomized word-position confirmation after
   clearing the initial display;
4. if a passphrase is selected, require it twice and warn that every typo
   produces a different valid wallet with no checksum failure;
5. derive the first account and require an address/fingerprint confirmation
   after the backup re-entry; and
6. do not accept funds until the backup confirmation succeeds.

Import:

1. label the input explicitly as English BIP-39 and never accept an arbitrary
   password or prose sentence;
2. normalize and checksum-validate before deriving any account;
3. make empty versus non-empty passphrase an explicit choice, never a hidden
   default carried over from another wallet;
4. show no definitive balance during recovery; use the typed states from
   [`WALLET_RECOVERY_V1.md`](WALLET_RECOVERY_V1.md);
5. confirm the expected first address/fingerprint when the user has one; and
6. on mismatch, stop and let the user correct mnemonic/passphrase/birthday
   instead of expanding account ranges blindly.

Clipboard/paste may be offered only when the platform threat model explicitly
accepts it. The core API neither reads nor writes the clipboard.

## 4. Passphrase semantics

Empty passphrase is represented by `WalletMnemonicPassphrase::empty()`; a
non-empty passphrase must be explicitly constructed. BIP-39 provides no
passphrase checksum: all strings map to valid seeds. Vault must therefore never
claim that a successfully parsed mnemonic proves the passphrase is correct.
Passphrase loss is seed loss, and plausible-deniability behavior is not a
backup substitute.

The passphrase is not used to encrypt the mnemonic or database. Database
encryption uses the independent random root key in
[`WALLET_CUSTODY_V1.md`](WALLET_CUSTODY_V1.md).

## 5. Evidence and exclusions

Automated tests reproduce the official 12-word `TREZOR` BIP-39 seed vector,
reject a checksum-invalid sentence, generate a 24-word profile, round-trip its
canonical phrase, and prove mnemonic/passphrase/seed diagnostics are redacted.
The fresh dependency graph passes the enforced offline RustSec audit.

Not selected or implemented by this profile:

- non-English generation/import;
- arbitrary raw user passwords, brainwallets, or unchecked phrases;
- SLIP-39/social recovery, Codex32, multisignature, or seed splitting;
- hardware-wallet mnemonic entry or non-exportable derivation;
- cloud mnemonic storage, automatic seed backup, or recovery escrow; and
- migration of another wallet's non-BIP-39 derivation path.

Those capabilities require separate reviewed formats and vectors; they are not
silently inferred from a successful BIP-39 parse. No real funds are authorized
until platform ceremonies and wider H1 gates pass.
