# Vault paired signer transport v1

**Status:** production-intent XX pairing, encrypted peer lifecycle, KK channel,
active-session shutdown, Unix replay store, protected key/replay contracts,
request/response codecs, and bound session implemented; concrete
UX/hardware/review gates open
**Last updated:** 2026-08-28

## 1. Security scope

This profile carries the private `VAOP` packets between a transaction
coordinator and a software or hardware signer. It is outside consensus and
MUST never be exposed through a node RPC, mempool, block, log, crash report, or
analytics channel.

The selected paired-peer protocol is exactly:

```text
Noise_KK_25519_ChaChaPoly_BLAKE2s
```

Both X25519 static public keys MUST already be mutually authenticated by the
first-contact ceremony in section 2. KK is forbidden for first-contact pairing.
Vault transport identities are generated independently and MUST NOT be derived from
or reused as VLT spending, full-viewing, incoming-viewing, or outgoing-viewing
keys.

Delegated proving is not an extension of this signer channel. Its frozen
profile requires a separate prover identity, per-job channel and committed
witness package; signer transport keys and pairing records MUST NOT be reused.
See [`DELEGATED_PROVING_V1.md`](DELEGATED_PROVING_V1.md).

The Noise prologue commits to the fixed Vault signer domain, network ID, and
initiator/responder static public keys. Empty handshake payloads are mandatory.
After the two-message KK handshake, the 32-byte Noise handshake hash `h` is the
Vault channel binding. The Noise specification explicitly defines the
handshake hash as the post-handshake channel-binding value; Vault never uses
the chaining key `ck` for this purpose.

Implementations use an ordered stateful Noise transport. Authentication,
canonical-codec, replay, or ordering failure poisons the connection. One
handshake carries one signing attempt, at most four messages per direction,
and is closed after response or abort.

## 2. First-contact pairing

Vault pairing fixes the coordinator as initiator, the signer as responder, and
uses exactly:

```text
Noise_XX_25519_ChaChaPoly_BLAKE2s
```

The three XX flights carry empty payloads. Its prologue is the ASCII domain
`vault.signer.noise-xx.prologue.v1` followed by the 32-byte network ID. Every
flight is bounded at 256 bytes. A wrong network, invalid state transition,
oversized message, authentication failure, or non-empty payload poisons the
ceremony.

XX proves possession of the exchanged static keys but does **not** identify a
first-contact peer by itself. After XX completes, both devices derive the same
128-bit short authentication string:

```text
BLAKE3-DERIVE(
  "vault.signer.pairing-fingerprint.v1",
  noise_protocol || network_id || xx_handshake_hash ||
  coordinator_static || signer_static
)[0..16]
```

The canonical display is four groups of eight uppercase hexadecimal digits,
for example `551A6C4D-BC8529A4-1203AE7D-E8D629D2`. The user MUST compare the
complete value on both trusted displays, or authenticate the same bytes over an
independent channel. A QR code is only a rendering of those 16 bytes; scanning
through the same untrusted coordinator is not independent authentication.

The API returns `UnconfirmedSignerPairing` after XX. That type cannot open a KK
channel. Its only public conversion consumes a `TrustedPairingConfirmation`
adapter, gives that adapter the exact role/network/static-key/fingerprint
facts, and constant-time compares the independently returned value before
producing `PairedSignerRecord`. The crate provides no echo/auto-approve adapter.
The record contains no private key and has this fixed 152-byte codec:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | magic ASCII `VSPR` |
| 4 | 2 | version `1` |
| 6 | 1 | local role: coordinator `0`, signer `1` |
| 7 | 1 | reserved zero |
| 8 | 32 | network ID |
| 40 | 32 | local static public key |
| 72 | 32 | remote static public key |
| 104 | 32 | XX handshake hash |
| 136 | 16 | confirmed fingerprint |

The decoder rejects alternate lengths, reserved roles/bits, zero or equal
keys, zero domains, and a fingerprint inconsistent with the transcript. This
unkeyed consistency check does not authenticate storage: the record MUST be
stored together with its lifecycle/revocation metadata inside the wallet's
authenticated encrypted store. The separate local X25519 private key MUST stay
in protected key storage. Every later connection checks that local key against
the confirmed record before creating KK.

The protected identity record supplied to platform adapters is exactly 136
bytes:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | magic ASCII `VSKM` |
| 4 | 2 | version `1` |
| 6 | 1 | local role: coordinator `0`, signer `1` |
| 7 | 1 | reserved zero |
| 8 | 32 | non-zero network ID |
| 40 | 32 | dedicated X25519 transport private key |
| 72 | 32 | independent peer-registry storage key |
| 104 | 32 | independent registry ID |

`SignerProtectedKeyMaterial` is non-`Clone`, redacts diagnostics, and zeroizes
both private keys on drop. `SignerProtectedKeyStore::create` MUST be durable and
no-clobber and MUST bind the record to the intended application, user and
wallet/signer slot. `ProtectedSignerKeys::enroll` reads back and constant-time
checks the complete newly stored record. Normal opening fails when the slot is
missing; it never generates a replacement identity. Platform adapters MUST
document authentication prompts, lock state, synchronization, backup,
recovery, process-memory exposure and crash-dump behavior. A plain file or a
password-derived record does not satisfy this protected-storage contract.

## 3. Encrypted peer lifecycle registry

Confirmed records are persisted only through `EncryptedPeerRegistry`. A
dedicated uniformly random 256-bit `PeerRegistryStorageKey` MUST come from an OS
keychain, secure enclave, or equivalent protected key store. Vault does not
derive this key from a password; a password-backed adapter requires a separately
specified memory-hard KDF. Each registry also has a random non-zero 32-byte
`PeerRegistryId` retained in protected wallet metadata. This ID prevents valid
ciphertext substitution between different registry slots that share a storage
key, network, role, and local transport identity.

The XChaCha20-Poly1305 key is:

```text
BLAKE3-DERIVE(
  "vault.signer.peer-registry.aead-key.v1",
  storage_key || network_id || local_role || local_static || registry_id
)
```

Every rewrite uses a fresh random non-zero 24-byte nonce. The outer `VPSE`
envelope is exactly 51,878 bytes:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | magic ASCII `VPSE` |
| 4 | 2 | version `1` |
| 6 | 1 | algorithm `1`: XChaCha20-Poly1305 |
| 7 | 1 | reserved zero |
| 8 | 24 | random nonce |
| 32 | 4 | fixed plaintext length `51,826` |
| 36 | 51,826 | encrypted fixed-size registry plaintext |
| 51,862 | 16 | Poly1305 tag |

The complete 36-byte header is associated data. The fixed ciphertext length
hides the number of active and revoked peers from filesystem size observers.
The authenticated plaintext begins:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | magic ASCII `VPRG` |
| 4 | 2 | version `1` |
| 6 | 8 | non-zero mutation generation |
| 14 | 32 | network ID |
| 46 | 1 | local role |
| 47 | 1 | reserved zero |
| 48 | 32 | local static public key |
| 80 | 32 | registry ID |
| 112 | 2 | entry count, at most 256 |
| 114 | variable | canonically sorted 202-byte entries |
| after entries | remaining | mandatory zero padding to 51,826 bytes |

Each entry contains the derived 32-byte peer ID, lifecycle byte, reserved zero,
created generation, revoked generation, and the exact 152-byte `VSPR` record.
Entries are strictly sorted by peer ID. At most 16 may be active and 256 may be
retained over the registry lifetime. Duplicate peer IDs or remote static keys
are rejected even when the older entry is revoked.

Adding a peer requires an OOB-confirmed record. Revocation and rotation have no
raw public mutation entry point: both require `TrustedPeerConfirmation` over
the authenticated network, local role, current fingerprint, optional
replacement fingerprint, and registry generation. Rejection changes neither
the lifecycle state nor active sessions. After confirmation, revocation
increments the generation and atomically writes a permanent tombstone. Rotation
performs one atomic transition: the old active identity is tombstoned and a
separately confirmed record with a fresh remote static key is installed at the
same generation. Re-pairing a revoked static key is forbidden. Records cannot
be extracted from the registry to construct KK: the public API opens a
handshake only after finding an active entry and matching the protected local
key. The lower-level KK constructors are crate-private.

Revocation prevents future handshakes; it is not retroactive cryptographic
erasure of keys or ciphertexts already held by a compromised peer. Every
registry-issued handshake and transport carries a shared peer lifecycle gate.
Each Noise operation holds the gate for the complete state transition.
Revocation and rotation shut the old gate before the durable registry rewrite,
waiting for an operation already in flight and rejecting every later operation
with the opaque `Closed` error. Therefore no new local operation can cross a
successfully committed revocation boundary. An uncertain persistence failure
poisons the registry and shuts every active gate. Each Vault transport is also
independently limited to one signing attempt and four messages per direction.

The registry reuses the same Unix locked atomic-file primitive as `VSRG`:
absolute path, protected parent, stable exclusive lock, `0600`, `O_NOFOLLOW`,
hardlink rejection, same-directory temporary write, file sync, atomic rename,
and parent-directory sync. Any uncertain persistence failure poisons the open
handle. AEAD detects wrong keys/scopes and modified bytes, but a valid older
encrypted snapshot remains indistinguishable without external monotonic state.

Initialization and normal opening are intentionally separate operations.
`EncryptedPeerRegistry::create` succeeds only when the state file is absent;
`EncryptedPeerRegistry::open` succeeds only when it already exists. Creation
never overwrites bytes, and opening a missing file returns `StoreMissing`
instead of silently creating an empty registry. A missing registry, lost
storage key, or lost registry ID is a security recovery event: normal wallet
startup MUST stop before pairing or signing. Creating a replacement registry
is permitted only through an explicit new-wallet/credential-reset ceremony
that warns that prior revocation tombstones cannot be recovered.

## 4. Vault transport frame

The encrypted Noise plaintext has this exact little-endian encoding:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | magic ASCII `VST1` |
| 4 | 2 | version `1` |
| 6 | 1 | kind: challenge `0`, request `1`, response `2`, abort `3` |
| 7 | 8 | per-direction sequence, beginning at zero |
| 15 | 4 | payload length |
| 19 | variable | exact application payload |

Plaintext is bounded at 61,440 bytes, including the 19-byte header. The Noise
Poly1305 tag produces at most 61,456 ciphertext bytes, below Noise's 65,535-byte
message limit. Decoders allocate only after checking these bounds.

## 5. Signer challenge

The signer creates a fresh challenge after the authenticated handshake. Its
fixed 110-byte codec is:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | magic ASCII `VSCH` |
| 4 | 2 | version `1` |
| 6 | 32 | Vault network ID |
| 38 | 32 | exact Noise handshake hash `h` |
| 70 | 32 | random non-zero session ID from a CSPRNG |
| 102 | 8 | non-zero durable monotonic signer counter |

The coordinator echoes the complete challenge inside its request. The signer
compares it byte-for-byte with the locally retained challenge and checks that
the channel binding is from the active Noise connection.

Before exposing a signing session, a `DurableReplayGuard` MUST atomically
persist consumption of `(session_id, counter)`. It MUST reject reused or
non-increasing counters, survive process/device restart, detect storage
rollback according to its platform threat model, and fail closed on I/O. The
crate supplies no volatile or permissive production guard.

The implemented Unix software profile uses one explicit absolute state path
and a stable sibling `.lock` file. It takes a non-blocking exclusive advisory
lock for the handle lifetime. The canonical parent directory cannot be writable
by group or others; state/lock paths cannot be symlinks or hardlinks; opens use
`O_NOFOLLOW`; and both files are owner-only (`0600`). These checks assume the
wallet controls its storage directory and do not defend against a malicious
process running as the same OS account.

`CrashConsistentReplayStore::create` is restricted to explicit initialization
and rejects an existing state file. Normal startup uses
`CrashConsistentReplayStore::open`, which rejects a missing file with
`StateMissing`; it never resets the counter. Missing state therefore enters
wallet recovery instead of silently weakening replay protection.

The state is exactly 160 bytes:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | magic ASCII `VSRG` |
| 4 | 2 | version `1` |
| 6 | 1 | pending flag `0` or `1` |
| 7 | 1 | reserved zero |
| 8 | 8 | highest durably issued counter |
| 16 | 8 | highest durably consumed counter |
| 24 | 32 | pending network ID, or zero |
| 56 | 32 | pending channel binding, or zero |
| 88 | 32 | pending random session ID, or zero |
| 120 | 8 | pending counter, or zero |
| 128 | 32 | domain-separated BLAKE3 checksum of bytes `0..128` |

Before returning a challenge, the store advances `highest_issued` and persists
the complete pending challenge. Issuing again advances the counter again and
invalidates an abandoned pending challenge. Before signing, only the byte-exact
pending network, channel, session, and counter can be consumed; the cleared
state is persisted before success returns. Each transition writes a fresh
owner-only temporary file in the same directory, syncs it, atomically renames
it, syncs the resulting file, and syncs the parent directory. Any uncertain
write/sync/rename failure permanently poisons that open handle.

This is a crash-consistent Unix filesystem profile, not a secure monotonic
counter. Its checksum detects torn or corrupted bytes but cannot distinguish a
valid older snapshot restored by an attacker. Wallet backup/restore MUST treat
the counter state as non-rollback state. Devices whose threat model includes
host-controlled rollback still require a secure-element monotonic counter. The
non-Unix durability and anti-rollback profiles remain activation gates.
`CrashConsistentReplayStore::open` therefore rejects non-Unix targets instead
of silently weakening this contract.

For devices whose threat model includes host-controlled rollback, the
platform-neutral protected profile stores this complete 136-byte logical state:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | magic ASCII `VSRS` |
| 4 | 2 | version `1` |
| 6 | 1 | pending flag `0` or `1` |
| 7 | 1 | reserved zero |
| 8 | 8 | non-zero secure transition generation |
| 16 | 8 | highest durably issued challenge counter |
| 24 | 8 | highest durably consumed challenge counter |
| 32 | 32 | pending network ID, or zero |
| 64 | 32 | pending channel binding, or zero |
| 96 | 32 | pending random session ID, or zero |
| 128 | 8 | pending challenge counter, or zero |

With no pending challenge, issued and consumed counters MUST be equal and the
pending area MUST be zero. With a pending challenge, every binding MUST be
non-zero, its counter MUST equal the highest issued counter, and it MUST exceed
the highest consumed counter. The transition generation increments on every
issue and every consumption, including when a new issue invalidates an
abandoned pending challenge.

`SignerSecureReplayStore` MUST bind one instance to one protected signer slot
and atomically compare-and-swap this complete state. It MUST survive process
and device restart plus power loss and reject host-controlled restoration of
an older valid state. A file, checksum, database transaction or volatile lock
does not satisfy that interface. A secure-element adapter MAY combine a
hardware monotonic counter with an authenticated sealed record, but MUST expose
the same atomic semantics and specify counter endurance and exhaustion.

`RollbackProtectedReplayStore::enroll` refuses an occupied slot and `open`
refuses a missing one. Issuance persists the exact pending challenge before
returning it; consumption persists its removal before success. A CAS mismatch
or adapter error permanently poisons the handle, including when the adapter may
have committed before reporting failure. Reopening loads whichever complete
state the protected adapter durably committed. The crate deliberately provides
no permissive or filesystem implementation of this secure trait.

## 6. Authorization request

The complete request is one encrypted `AuthorizationRequest` payload:

| Field | Bytes |
|---|---:|
| magic ASCII `VSRQ` | 4 |
| version `1` | 2 |
| complete `VSCH` challenge | 110 |
| canonical signer-policy digest | 32 |
| effects length | 4 |
| canonical `TransferV2Effects` | declared length, max 13,919 |
| packet count | 1 |
| ordered `VAOP` packets | count × 1,455 |

The maximum request is 37,352 bytes for 16 actions, so every activated
2/4/8/16 bucket fits one bounded Noise message. The packet count MUST equal the
canonical action count. Effects and every packet are decoded independently;
truncation, trailing bytes, alternate encodings, malformed cryptographic
fields, or count mismatch abort the session.

`prepare_confirmed_request` first checks the exact challenge, policy digest and
all public effects against the locally stored `TransferV2SignerPolicy`. Only
then does it call `TrustedTransferIntentSource` with the network, circuit, burn
scheme/key/epoch, padded action count, gas/fee, effects digest and transcript
ID. The adapter supplies recipient, amount, classification and memo as
zeroizing `ApprovedOutputIntent` values from an independent source; those
private facts are never derived from coordinator packets for confirmation. The
signer binds them to each canonical action and reconstructs every Ironwood
output as specified by `OUTPUT_AUTHORIZATION_V1`, then derives:

```text
transcript_id = BLAKE3-DERIVE(
  "vault.signer.transfer-v2.transcript.v1",
  challenge || policy_digest || effects_digest || action_count ||
  ordered_packet_digests
)
```

The packet digest has its own domain and covers all 1,455 private bytes. The
signer UI and coordinator MUST compare the exact transcript ID. A session signs
each action at most once and cannot finish until all required actions have
valid RedPallas authorizations.

## 7. Authorization response

The encrypted response codec is:

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | magic ASCII `VSRP` |
| 4 | 2 | version `1` |
| 6 | 32 | signing transcript ID |
| 38 | 32 | canonical effects/public-input digest |
| 70 | 1 | authorization count |
| 71 | count × 64 | ordered RedPallas signatures |

The maximum is 1,095 bytes. Before accepting it, the coordinator verifies the
expected transcript, effects digest, action count, each action's exact `rk`,
and every signature. Failure returns no partial authorization set.

## 8. Implemented evidence and remaining gates

The `vault-signer` crate implements the bounded XX ceremony, type-level
unconfirmed/confirmed transition, canonical paired record, fixed-size
XChaCha20-Poly1305 peer registry, permanent revocation tombstones, atomic peer
rotation, registry-gated KK handshake, revocation/rotation shutdown of active
handshakes and transports, all-session shutdown on uncertain registry
persistence, mandatory trusted-confirmation traits with no permissive default,
channel binding, poison-on-failure transport,
challenge/request/response codecs, Unix crash-consistent replay store,
protected signer-key and rollback-resistant replay adapter contracts,
canonical exact-threshold multisignature policy/agreement and nonce-lifecycle
contracts with a final standard-signature gate,
independent packet reconstruction, one-shot action state, and a complete
encrypted round trip that produces a valid transfer-v2 using the real stores.
Tests reject wrong pairing/transport
networks and identities, fingerprint mismatch, record mutation, symlink and
hardlink state, concurrent ownership, wrong registry key/scope/slot, AEAD and
plaintext-codec mutation, duplicate/revoked identities, invalid rotation,
capacity overflow, missing-state opening, duplicate initialization,
corrupt/truncated files, abandoned and replayed challenges,
uncertain persistence, MITM/ciphertext mutation,
reordering, cross-channel challenges, altered policies/effects/packets,
duplicate action signing, incomplete responses, transcript/signature mutation,
and malformed lengths. All action buckets fit the fixed bound.

This is not yet hardware-wallet-ready. Activation still requires:

- independent cryptographic/security review of the implemented XX/KK profiles,
  pairing lifecycle, filesystem store, dependency surfaces, and test corpus;
- production durable counter/replay stores for every additional software and
  hardware platform, including power-loss, backup, migration, and rollback tests;
- keychain/secure-enclave adapters, hardware adapters, concrete independently
  reviewed trusted-display/input implementations of the confirmation traits,
  and a reviewed FROST implementation of the frozen multisignature profile;
- a dedicated delegated-prover transport, rollback-resistant policy/job store,
  suite adapters implementing the separately frozen `DELEGATED_PROVING_V1`
  contract, plus rate limits and privacy-safe diagnostics;
- sustained target-platform parser fuzzing and latency/memory measurements,
  dependency provenance, and external review. The deterministic local
  transport/request/response corpus and bounded runners are frozen in
  [`SIGNER_CORPUS_V1.md`](SIGNER_CORPUS_V1.md).

Until those gates close, the implementation must not protect real funds.

## 9. References

- [Noise Protocol Framework revision 34](https://noiseprotocol.org/noise.html)
- [Snow Rust implementation](https://github.com/mcginty/snow)
- [RustCrypto ChaCha20Poly1305](https://docs.rs/chacha20poly1305/0.10.1/chacha20poly1305/)
- [`fs2` advisory file-lock API](https://docs.rs/fs2/0.4.3/fs2/trait.FileExt.html)
- [`tempfile` persistence API](https://docs.rs/tempfile/3.27.0/tempfile/struct.NamedTempFile.html)
- [`OUTPUT_AUTHORIZATION_V1.md`](OUTPUT_AUTHORIZATION_V1.md)
- [`DELEGATED_PROVING_V1.md`](DELEGATED_PROVING_V1.md)
- [`TRANSFER_V2.md`](TRANSFER_V2.md)
