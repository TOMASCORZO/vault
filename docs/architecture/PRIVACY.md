# Vault Privacy Architecture

**Maturity:** production-intent foundation; not mainnet-eligible.
**Priority:** private transfers before private contracts.
**Last updated:** 2026-09-02.

## 1. Meaning of the privacy target

Vault targets confidentiality and unlinkability against defined adversaries;
it does not use "100% anonymous" as an unauditable promise. A release can claim
a property only when its assumptions, observable metadata, anonymity set, and
failure cases are documented and measured.

The target covers four separate surfaces:

1. **Chain privacy:** hide sender, recipient, amount, change classification,
   memo, asset details where supported, and private contract state.
2. **Transaction-graph privacy:** prevent note and nullifier linkage, normalize
   transaction shape, and avoid amount or burn side channels.
3. **Network privacy:** prevent validators, RPC providers, and passive observers
   from learning transaction origin through IP address, timing, or peer topology.
4. **Endpoint privacy:** protect keys, wallet scanning, proving inputs, backups,
   view capabilities, merchant data, and local metadata.

Compromise of a device, voluntary identity disclosure, physical delivery data,
or correlation with a transparent external chain remains outside a mathematical
zero-knowledge guarantee. These cases require product and network controls.

## 2. Accepted on-chain foundation

Vault adopts the Ironwood V3 instantiation of the Orchard protocol as the
reviewed base for native VLT notes. The production-intent implementation is
isolated in `vault-privacy` and pins:

- `orchard = 0.15.5`; its circuit graph is disabled by default and enabled only
  by the isolated `zk/halo2` workspace;
- `zcash_note_encryption = 0.4.2`;
- Ironwood V3 note plaintexts and the hardened `PostNu6_3` Action circuit.

Vault does not use the post-NU6.3 Orchard pool instantiation: it deliberately
restricts cross-address payments. Ironwood V3 reuses the corrected Action
circuit and permits normal cross-address transfers. This selection also avoids
the historically insecure pre-NU6.2 variable-base multiplication circuit.

The selected construction provides:

- Pallas diversified payment addresses;
- separate spending, full-viewing, incoming-viewing, and outgoing-viewing
  capabilities;
- Sinsemilla binding note commitments;
- deterministic keyed nullifiers tied to the note commitment and unique `rho`;
- hiding Pedersen value commitments;
- per-spend RedPallas authorization under a fresh randomized validating key;
- fixed-size authenticated recipient ciphertext and sender-recovery ciphertext;
- commitment and ephemeral-key validation during trial decryption;
- a fixed-depth Sinsemilla commitment tree with deterministic roots,
  restorable frontier snapshots, and native membership-path verification;
- bounded batched incoming-note scanning for multiple local viewing keys.

Primary specifications and implementation:

- [ZIP 224: Orchard Shielded Protocol](https://zips.z.cash/zip-0224)
- [ZIP 229: Ironwood pool and transaction format](https://zips.z.cash/zip-0229)
- [Orchard keys](https://zcash.github.io/orchard/design/keys.html)
- [Orchard commitments](https://zcash.github.io/orchard/design/commitments.html)
- [Orchard nullifiers](https://zcash.github.io/orchard/design/nullifiers.html)
- [Orchard implementation](https://github.com/zcash/orchard)

Vault does not claim that dependency reuse transfers Zcash's audit status to
Vault. Integration, Vault-specific key derivation, transaction statements, and
release builds require Vault-specific adversarial and conformance suites.

## 3. Vault domain separation

Wallet seeds are transformed into Orchard-valid spending-key material using
BLAKE3 derive-key mode with the frozen context:

```text
vault.privacy.orchard-v1.spending-key.2026-08-21
```

The input is encoded as:

```text
network_id[32] || account_le_u32 || rejection_counter_le_u32 ||
seed_length_le_u64 || seed
```

Seed inputs shorter than 32 bytes, larger than 4096 bytes, and the zero network
ID are rejected. The network ID prevents accidental reuse of the same Orchard
receiver across Vault networks or another protocol when wallets follow this
derivation. A deterministic key/address vector is enforced in unit tests.

The production-intent wallet entry point narrows this low-level primitive to a
typed, non-clonable, zeroizing 32-byte seed. Interactive/file recovery imports
use the exact checksum-protected `VSEED001` package specified in
[`WALLET_RECOVERY_V1.md`](../specs/WALLET_RECOVERY_V1.md); concrete platform and
hardware custody remain activation gates.

The final user-facing address codec is not frozen. Raw 43-byte addresses MUST
NOT be presented to users until a checksummed, network-specific encoding is
specified and tested.

## 4. Output construction

One encrypted output currently has the following fixed public fields:

```text
note_commitment:      32 bytes
value_commitment:     32 bytes
ephemeral_key:        32 bytes
note_ciphertext:     580 bytes
outgoing_ciphertext:  80 bytes
```

The ciphertext sizes never vary with the amount, address, or memo. The private
prover package retains the note plaintext and value-commitment trapdoor. Secret
key material, note randomness, amounts, memos, and trapdoors use redacted debug
formatting and best-effort zeroization.

The output note's `rho` is the canonical nullifier of the spend paired with the
same action. Consensus uniqueness of that public nullifier and the proof's
derivation constraints are mandatory for Faerie resistance. A wallet API alone
cannot enforce this consensus property.

The note tree is the Orchard depth-32 append-only construction. Each append
returns the new leaf position, post-append anchor, and an initial membership
path. That path is valid for that root only; wallets must update witnesses as
later commitments arrive. Frontier snapshots are validated and roots are
recomputed rather than trusted from storage.

Each spend prepares a fresh non-zero scalar `alpha` and publishes only the
randomized validating key `rk = ak + [alpha]G`. The signer uses the matching
randomized authorizing key and signs a BLAKE3-derived digest separated by Vault
network and transaction effects. The transfer proof must show that `ak` belongs
to the input note owner and that public `rk` uses the witnessed `alpha`; signature
verification alone cannot establish note ownership.

## 5. Proof obligations before activation

The first specialized layer now uses the pinned Ironwood `PostNu6_3` Action
circuit and proves membership, ownership, nullifier derivation, randomized
authorization, input/output note openings, output `rho`, 64-bit action values,
and the net-value commitment. Its canonical two-action proof is 7,264 bytes.
It cannot authorize consensus alone.

The `vault-privacy` implementation MUST NOT be connected to real funds until
the composite transfer circuit, signer protocol, and consensus codec jointly
prove and enforce:

1. canonical action fields and a non-identity randomized authorization key;
2. membership of every real input note in the anchored commitment tree;
3. knowledge of spending authorization for every real input;
4. correct derivation of every input nullifier;
5. output `rho` equality to its paired action nullifier;
6. exact opening of every note and value commitment;
7. recipient versus internal-change ownership without a prover-selected label;
8. per-asset conservation, native VLT gas, and exact hidden burn;
9. encryption consistency for note commitment, ephemeral key, recipient
   ciphertext, and outgoing recovery policy through the reviewed independent
   signer mechanism specified in
   [`NOTE_CIPHERTEXT_POLICY.md`](NOTE_CIPHERTEXT_POLICY.md);
10. fixed action count or an audited padding policy with indistinguishable dummy
    actions;
11. binding of all public fields, ciphertexts, chain ID, circuit ID, and version
    into the proven transcript;
12. canonical proof encoding, bounded verification cost, and fail-closed
    activation and deactivation.

The existing `transfer-v1` envelope and accounting-only RISC Zero statement do
not meet these obligations. The production-intent transfer-v2 codec and real
Halo2 Action proof are specified in [`../specs/TRANSFER_V2.md`](../specs/TRANSFER_V2.md)
and [`TRANSFER_V2_CIRCUIT.md`](TRANSFER_V2_CIRCUIT.md). The composite verifier
requires a second accounting/burn verifier and ships no permissive
implementation. Consensus meaning is not changed silently under the v1
identifier.

## 6. Network and wallet work required

On-chain zero knowledge does not conceal transaction origin. Before public
privacy claims, Vault still needs:

- private compact-block retrieval and resistance to query fingerprinting;
- transaction diffusion or mix routing with explicit timing and global-passive
  adversary analysis;
- cover-traffic and low-volume behavior measurements;
- local proving by default, with an authenticated confidential protocol for any
  delegated prover;
- hardware-backed spending authorization and hardware/keychain custody of
  wallet-database keys plus monotonic rollback state;
- metadata-minimized logs, crash reports, telemetry, backups, and clipboard
  handling;
- fixed-shape or padded transactions benchmarked against fee and DoS costs;
- privacy regression tests using simulated chain and network observers.

Tor alone is not treated as proof against timing correlation. Cross-chain entry
and exit routes need batching, delayed settlement, and sufficient liquidity;
an isolated BTC deposit can otherwise be correlated with a Vault receipt.

## 7. Known implementation limitations

- The current crate supports native VLT note values, not private multi-asset or
  contract notes.
- Amounts are `u64` inside Orchard notes; Vault monetary policy must set a lower
  consensus maximum and use identical atomic-unit bounds everywhere.
- The Vault seed transformation and its integration have not been independently
  reviewed.
- Best-effort zeroization cannot guarantee removal of compiler, operating-system,
  swap, crash-dump, or transient dependency copies.
- Bounded batched trial decryption is now integrated with a canonical full-output
  compact block, finalized-header commitment boundary, strict chain continuity,
  and independent note-tree replay. Full scan accounts cover external and
  internal scopes and derive owned future nullifiers. The first Unix encrypted
  transactional SQLite/ShardTree backend now atomically persists marks,
  checkpoints, notes, spends, and the finalized tip; authenticates reopen;
  reconciles owned rows against tree marks; and extracts verified current spend
  witnesses. Its authenticated backup encrypts persistent wallet identity,
  exact snapshot size, policy, and tip; only a 1 MiB size bucket remains public,
  and non-empty restore revalidates the complete database before publication.
  Explicit birthday recovery binds the imported frontier to a finalized header,
  retains witness-critical ommers as references, and stores its origin encrypted.
  Deterministic recovery derives up to 64 contiguous seed accounts without
  retaining spending keys, scans all bounded capability groups through an exact
  finalized target, and persists fail-closed progress plus a conservative
  trailing-account gap. Its bounded coordinator now authenticates hostile
  compact bytes against externally verified finalized headers and resumes from
  durable state, but does not yet supply the consensus-verifying or private
  network adapter. The typed/checksummed seed-import boundary is implemented;
  distinct threshold-authenticated birthday and target distribution now require
  independently finalized matching headers; concrete platform/hardware custody,
  publisher-policy delivery and rollback protection, policy above the current
  range, backup operations, migrations, secure key and
  rollback-counter storage, long-history
  pruning/growth, private retrieval, crash injection, benchmarks, and
  side-channel review remain open.
- Spend authorization signatures and their `rk`/note ownership relation are
  implemented and constrained by the Action circuit.
- Accounting, dummy zeroing, gas, exact burn, conservation, burn commitment,
  and burn ciphertext equations are implemented in a real Halo2 proof shape,
  and the frozen non-activated monolithic circuit links them to Action values,
  derived dummy state, private exact-receiver change classification, the
  activated epoch descriptor, and the complete canonical effects digest.
  Independent local signer reconstruction of note ciphertexts and the
  policy-bound transfer-v2 signing session are implemented. Confirmed Noise XX
  pairing, encrypted revocation/rotation state, and the registry-gated KK
  channel bind those checks to an authenticated anti-replay transcript backed
  by a crash-consistent Unix store. Independent review, keychain and active-session
  adapters, host-rollback-resistant/non-Unix state, hardware/multiparty adapters,
  network relays, and complete wallet recovery/durability operations are not
  implemented.

Private smart contracts remain blocked behind completion of the project security
gates for the private-transfer path. Contract state will extend this note model only
after its base invariants and metadata behavior are demonstrated.
