# Vault Threat Model — Draft 0.1

## Status and scope

This document defines intended properties, not properties already delivered by
the code. H1 validates shielded transaction structure and proof-verifier
integration. The production-intent privacy crate now constructs commitments,
nullifiers, diversified keys, and authenticated encrypted notes. Transfer-v2
now canonically connects those public types to an atomic state transition. Its
frozen non-activated monolithic circuit constrains Action ownership and note openings,
private accounting, exact burn encryption, the activated epoch key, and the
complete effects digest, but no consensus verifier or signer-complete wallet
flow is activated. A canonical local signing session independently reconstructs
every Ironwood output and pins the complete transfer policy before signing, but
hardware, multiparty, and delegated-prover transports are not yet implemented
or reviewed. Pinned Noise XX first contact, explicit fingerprint confirmation,
the paired Noise KK channel, a channel-bound one-shot request flow, and a
crash-consistent Unix replay store are now implemented. Independent review,
host-rollback-resistant state, non-Unix/hardware adapters, and confirmation and
revocation UX remain open. The finalized compact-block scanner authenticates
header-bound block/tree metadata, replays every commitment, and trial-decrypts
all outputs locally; its durable encrypted witness database and private network
retrieval remain open. The repository remains unaudited.

## Assets to protect

- Spending keys and view capabilities.
- Ownership, sender/recipient linkage, amounts, and private contract state.
- Integrity of the capped supply and mandatory burn.
- Availability and correct ordering of transactions.
- Funds locked during cross-chain settlement.
- Durable application manifests and stored content.

## Adversaries

- Passive chain observers and analytics companies.
- RPC operators correlating IP addresses and transaction timing.
- Malicious provers submitting invalid state transitions.
- Validators censoring, equivocating, or attempting reorganization.
- Solvers refusing to complete cross-chain trades.
- Compromised bridge contracts or external-chain validators.
- Spam senders consuming proving, validation, or storage resources.
- Malicious applications, wallet extensions, gateways, and sellers.

## Intended protections

- A proof cannot create value above the permitted issuance or avoid the burn.
- A nullifier cannot be accepted twice.
- Ciphertexts and commitments do not expose private values without view keys.
- Consensus remains safe below its documented Byzantine voting threshold.
- Atomic swaps either settle both assets or provide bounded-time refunds.
- Each bridge adapter has isolated limits and cannot mint native VLT.
- Resource metering prevents unbounded contract execution.

## Explicit non-guarantees

Vault cannot guarantee anonymity when:

- a device, seed, wallet, or browser is compromised;
- a user identifies themselves to a counterparty;
- physical delivery information is shared with a seller;
- a low-volume cross-chain trade is correlated with its public source-chain leg;
- network timing or IP metadata bypasses privacy relays;
- a view capability is disclosed;
- stored content itself contains identifying information.

“Private” must never be marketed as “impossible to trace.” Privacy claims will
be stated against concrete adversaries and measured anonymity sets.

## Highest-risk components

1. Zero-knowledge circuits and their implementation.
2. Wallet key management and delegated proving.
3. Consensus and validator economics.
4. Bitcoin atomic swaps and refund paths.
5. Bridges and wrapped assets.
6. Supply/burn aggregation.
7. Durable-storage incentives.

Each requires independent review, adversarial tests, and an audit before
mainnet. Cross-chain adapters also require per-chain caps, pause-only circuit
breakers, monitoring, and delayed limit increases.

## H1 implementation defenses already present

- Chain IDs and circuit IDs are proof-bound to prevent cross-domain replay.
- Only recent state roots may anchor membership proofs.
- Nullifiers and output commitments are checked for local and global reuse.
- Proofs and ciphertexts are size-limited before expensive verification.
- Invalid proofs cannot mutate shielded state.
- The production crate contains no accepting mock verifier.
- Public gas parameters are checked before proof verification.
- Vault-domain-separated keys derive diversified external and internal
  addresses and separate incoming/outgoing viewing capabilities.
- Fixed-size note and outgoing ciphertexts authenticate successful decryption
  against the note commitment and ephemeral key.
- Transfer-v2 rejects non-canonical privacy fields, alternate action ordering,
  reused randomized/ephemeral keys, truncation, trailing bytes, and oversized
  allocation before proof verification.
- Every transfer-v2 action signature binds the chain and complete public
  effects; successful proof verification atomically derives the next note-tree
  root and records all nullifiers.
- The hardened Action circuit has generated a real proof of membership,
  ownership, nullifiers, note openings, and net commitments.
- The second circuit shape has generated a real proof of range-constrained gas,
  exact burn, conservation, the burn commitment, and both threshold-ElGamal
  equations from one shared burn cell.
- The monolithic shape directly equates Action note-value cells with accounting,
  derives dummy state, and permits zero-tax change only to the exact private
  expanded receiver of the paired input.
- Validators reconstruct `scheme_id`, `key_id`, epoch, and `PK_epoch` from the
  activated DKG descriptor rather than accepting arbitrary prover coordinates.
- The complete effects digest is represented losslessly by two constrained
  128-bit public limbs; a note-ciphertext or network-domain mutation changes the
  proof statement.
- The production-intent prover wrapper rejects effects whose encrypted output
  differs from the one constructed with the witnessed private note.
- The private fixed-size `VAOP` v1 packet reconstructs the exact note,
  commitments, ephemeral key, and both ciphertexts against trusted intent
  before producing an opaque account-bound output token.
- The transfer-v2 signing session consumes one exact token per sorted action
  and pins network, circuit, burn descriptor, action shape, gas, and fee
  ceilings; mutation, reordering, missing tokens, wrong accounts, and wrong
  randomized keys fail before signing.
- Pre-paired signer peers use a pinned Noise KK profile with dedicated X25519
  identities. Vault binds Noise's handshake hash, a signer challenge, durable
  counter, policy, effects, and ordered packet digests into one transcript;
  authenticated framing rejects tampering, replay, and reordering.
- First contact uses pinned Noise XX and cannot produce a KK-capable record
  until the complete transcript-derived 128-bit fingerprint is confirmed over
  an independent path. The canonical record revalidates its keys, network,
  role, handshake hash, and fingerprint before use.
- Confirmed records live in a fixed-size XChaCha20-Poly1305 registry bound to a
  random registry ID, network, role, and local transport identity. Permanent
  tombstones block reuse of revoked static keys; peer rotation revokes the old
  and installs a separately confirmed fresh identity in one durable generation.
  Public KK construction is gated on an active registry entry. Normal opening
  fails when the registry is missing and cannot silently recreate an empty
  lifecycle; credential reset is a separate trusted recovery ceremony.
- The Unix software signer reserves each exact challenge before exposure and
  consumes it before signing through an exclusive, owner-only, checksummed,
  atomic-rename-and-directory-sync store. Corruption, symlinks, hardlinks,
  concurrent access, challenge substitution, and uncertain persistence fail
  closed. Explicit creation and normal opening are separate, so missing state
  cannot silently reset the counter.
- Canonical bounded request and response codecs cover all activated action
  buckets. Signing is one-shot per action, incomplete sessions release nothing,
  and the coordinator re-verifies transcript, effects digest, `rk`, and every
  returned RedPallas signature.
- Finalized wallet discovery accepts only a compact block matched to
  caller-verified finalized-header fields, then replays every output commitment
  to the exact post-state root and trial-decrypts every full output locally.
  Wrong network/height/parent/tree state, selective omission, substitution, and
  resource-bound violations fail before a durable store mutation. Match counts
  and positions are redacted from default diagnostics. Full scan accounts cover
  both recipient and change scopes and derive future spend nullifiers locally.
- The first Unix wallet database commits note discovery, spend status, finalized
  tip, and ShardTree marks/checkpoints atomically. Private rows use fresh-nonce
  XChaCha20-Poly1305, nullifier lookups are keyed, open reconstructs the tree
  root/position and reconciles unspent note rows with effective marks, and a
  caller-provided monotonic height rejects snapshots below its secure floor.
  Its streaming backup hides chain/wallet/database identity, exact snapshot
  size, configuration, and tip in an authenticated manifest; all data and
  random padding chunks are authenticated, and non-empty restore validates the
  complete database before no-clobber publication. Backup existence and its 1
  MiB size bucket, file size, row counts, checkpoint/shard indices, I/O timing,
  a stale external rollback floor, memory copies, storage-provider metadata,
  and compact-block retrieval remain observable or open; row/container
  encryption is not endpoint/network anonymity.
- Birthday recovery requires the imported frontier to match an independently
  finalized header, inserts it through ShardTree with reference retention, and
  persists the origin authenticated and encrypted. Seed recovery derives a
  contiguous account set without retaining spending keys, scans up to 64
  accounts in fixed primitive batches, and binds every committed block to the
  exact ordered IDs and viewing keys. An exact finalized target and encrypted
  activity mask drive durable incomplete/complete/range-exhausted phases;
  incomplete state cannot release spend witnesses. This prevents frontier,
  fork-target, key-set, and ordinary-API substitution, but cannot detect a user
  or compromised coordinator choosing a birthday after the first wallet output
  or an insufficient policy above the bounded account range. Conservative
  checkpoint provenance, reviewed gap assumptions, and incomplete-recovery UX
  remain mandatory. Live checkpoint identifiers and the retrieval interval can
  reveal birthday/target timing despite encrypted record contents.
- The bounded recovery coordinator requests exactly the next durable height,
  requires an externally consensus-verified finalized header, bounds compact
  reads, authenticates hostile bytes, commits one height before requesting the
  next, and resumes from authenticated storage rather than provider cursors.
  Wrong height, chain, header commitment, parent, bytes, account set, or target
  fails closed. This boundary does not implement or replace consensus: a real
  full-node/light-client adapter, anti-eclipse policy, deadlines/retry budgets,
  and private/padded transport remain mandatory. A provider can still observe
  IP, height interval, timing, retries, and bandwidth.

These implemented proof components remain deliberately disconnected from an
activatable verifier. Independent pairing/store review, host-rollback-resistant
hardware state, keychain and active-session lifecycle adapters, non-Unix stores,
hardware/multiparty adapters and trusted-intent UX, corpus vectors and
benchmarks, DKG lifecycle, wallet security, and
external review remain mandatory before activation. A spending owner can always
authorize an unavailable output or disclose its own information; Vault therefore
treats successful recipient decryption as a precondition for payment acceptance
and signer verification as a critical security boundary. See
[`architecture/NOTE_CIPHERTEXT_POLICY.md`](architecture/NOTE_CIPHERTEXT_POLICY.md).
