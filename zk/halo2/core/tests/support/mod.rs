#![allow(dead_code, reason = "shared by the vector generator and verifier test")]

use ff::PrimeField;
use halo2_proofs::{
    pasta::EqAffine,
    plonk::{
        BatchVerifier, ProvingKey, SingleVerifier, VerifyingKey, create_proof, keygen_pk,
        keygen_vk, verify_proof,
    },
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use incrementalmerkletree::{Hashable, Level};
use orchard::{
    Anchor,
    note::ExtractedNoteCommitment,
    tree::{MerkleHashOrchard, MerklePath},
};
use pasta_curves::{
    group::{Group, GroupEncoding},
    pallas,
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use vault_burn::{EpochBurnPublicKey, PreparedBurnCiphertext};
use vault_privacy::{
    ActionNullifier, KeyScope, MEMO_BYTES, NoteMembershipPath, NoteTreeRoot,
    OutputAuthorizationPacket, OutputKind, PreparedBurnCommitment, PreparedNetValueCommitment,
    PreparedNoteOutput, PrivateNote, RandomizedSpendValidatingKey, VaultFullViewingKey,
    VaultSpendingKey, circuit::PreparedActionCircuit,
};
use vault_protocol::{
    ChainId, EncryptedBurnV2, GasParameters, TransferV2Action, TransferV2Effects,
};
use vault_zk_halo2_core::{
    accounting::{AccountingActionWitness, PreparedAccountingArithmetic},
    burn_binding::PreparedAccountingBurn,
    delegated_witness::{DelegatedActionWitness, DelegatedTransferWitness},
    suite::VaultTransferSuite,
    transfer_circuit::{PreparedVaultTransfer, VaultTransferCircuit},
};

const NETWORK: [u8; 32] = [0x31; 32];
const MAXIMUM_VALUE: u64 = 21_000_000 * 1_000_000_000;
const GAS_UNITS: u64 = 2;
const FEE_PER_GAS: u64 = 13;
const FIXTURE_SEED: [u8; 32] = [0x71; 32];
const VECTOR_MAGIC: [u8; 4] = *b"H2V1";
const VECTOR_VERSION: u16 = 1;
const WITNESS_MAGIC: [u8; 4] = *b"H2W1";
const INSTANCE_MAGIC: [u8; 4] = *b"H2I1";
const SECTION_DIGEST_CONTEXT: &str = "vault.zk.halo2.transfer-v2-vector-section.v1";
const PARAMETER_DIGEST_CONTEXT: &str = "vault.zk.halo2.parameters.v1";
const VERIFYING_KEY_DIGEST_CONTEXT: &str = "vault.zk.halo2.verifying-key.v1";

fn setup_fingerprint(context: &str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn parameter_bytes(params: &Params<EqAffine>) -> Vec<u8> {
    let mut bytes = Vec::new();
    params.write(&mut bytes).unwrap();
    bytes
}

fn material_matches_suite(
    suite: VaultTransferSuite,
    params: &Params<EqAffine>,
    vk: &VerifyingKey<EqAffine>,
) -> bool {
    let serialized_params = parameter_bytes(params);
    let pinned_vk = format!("{:?}", vk.pinned());
    setup_fingerprint(PARAMETER_DIGEST_CONTEXT, &serialized_params) == suite.parameter_digest()
        && setup_fingerprint(VERIFYING_KEY_DIGEST_CONTEXT, pinned_vk.as_bytes())
            == suite.verifying_key_digest()
}

pub struct ConformanceFixture<const N: usize> {
    pub prepared: PreparedVaultTransfer<N>,
    pub effects: TransferV2Effects,
    pub epoch_key: EpochBurnPublicKey,
    pub witness: Vec<u8>,
    pub delegated_witness: Option<Vec<u8>>,
}

struct ActionEntry {
    nullifier: ActionNullifier,
    circuit: PreparedActionCircuit,
    public: TransferV2Action,
    accounting: AccountingActionWitness,
    input_note: Vec<u8>,
    membership_path: NoteMembershipPath,
    authorization_randomizer: [u8; 32],
    net_value_trapdoor: [u8; 32],
    output_packet: Vec<u8>,
    input_value: u64,
    output_value: u64,
    taxable: bool,
}

pub fn conformance_fixture<const N: usize>() -> ConformanceFixture<N> {
    build_conformance_fixture(false)
}

pub fn delegated_conformance_fixture<const N: usize>() -> ConformanceFixture<N> {
    build_conformance_fixture(true)
}

fn build_conformance_fixture<const N: usize>(
    strict_change_recipient: bool,
) -> ConformanceFixture<N> {
    let suite = VaultTransferSuite::for_action_count(N).expect("canonical conformance bucket");
    let spending_key = VaultSpendingKey::derive(&[0xA5; 32], NETWORK, 0).unwrap();
    let full_viewing_key = spending_key.full_viewing_key();
    let input_address = full_viewing_key.address_at(0, KeyScope::External);
    let internal_address = full_viewing_key.address_at(0, KeyScope::Internal);
    let external_recipient = VaultSpendingKey::derive(&[0xB6; 32], NETWORK, 0)
        .unwrap()
        .full_viewing_key()
        .address_at(0, KeyScope::External);
    let mut rng = ChaCha20Rng::from_seed(FIXTURE_SEED);

    let mut inputs = Vec::with_capacity(N);
    for index in 0..N {
        let value = match index {
            0 => 5_051,
            1 => 1_000,
            _ => 0,
        };
        inputs.push(
            PrivateNote::create(
                input_address,
                value,
                MAXIMUM_VALUE,
                seeded_rho(index),
                &mut rng,
            )
            .unwrap(),
        );
    }
    let real_commitments = [
        inputs[0].commitment().unwrap(),
        inputs[1].commitment().unwrap(),
    ];
    let (anchor, real_paths) = two_leaf_paths(real_commitments);

    let mut entries = Vec::with_capacity(N);
    for (index, input) in inputs.iter().enumerate() {
        let (recipient, output_value, kind, taxable) = match index {
            0 => (external_recipient, 5_000, OutputKind::ExternalPayment, true),
            1 => (
                if strict_change_recipient {
                    internal_address
                } else {
                    input_address
                },
                1_000,
                OutputKind::InternalChange,
                false,
            ),
            _ => (
                if strict_change_recipient {
                    internal_address
                } else {
                    input_address
                },
                0,
                OutputKind::Dummy,
                false,
            ),
        };
        let membership_path = match index {
            0 => real_paths[0].clone(),
            1 => real_paths[1].clone(),
            _ => real_paths[0].clone(),
        };
        let action_nullifier = full_viewing_key.note_nullifier(input).unwrap();
        let output = PreparedNoteOutput::create(
            &full_viewing_key,
            KeyScope::External,
            recipient,
            output_value,
            MAXIMUM_VALUE,
            action_nullifier,
            [u8::try_from(index).unwrap(); MEMO_BYTES],
            &mut rng,
        )
        .unwrap();
        let authorization = spending_key.prepare_spend_authorization(&mut rng).unwrap();
        let net_value =
            PreparedNetValueCommitment::create(input.value(), output_value, &mut rng).unwrap();
        let circuit = PreparedActionCircuit::new(
            &full_viewing_key,
            input,
            &membership_path,
            &output,
            &authorization,
            &net_value,
            anchor,
        )
        .unwrap();
        let public = TransferV2Action::new(
            action_nullifier,
            RandomizedSpendValidatingKey::from_bytes(authorization.randomized_verification_key())
                .unwrap(),
            net_value.commitment(),
            output.encrypted_note().clone(),
        );
        let accounting = if kind == OutputKind::Dummy {
            AccountingActionWitness::dummy()
        } else {
            AccountingActionWitness::enabled(input.value(), output_value, taxable)
        };
        entries.push(ActionEntry {
            nullifier: action_nullifier,
            circuit,
            public,
            accounting,
            input_note: input.encode_private().to_vec(),
            membership_path,
            authorization_randomizer: *authorization.randomizer(),
            net_value_trapdoor: *net_value.trapdoor(),
            output_packet: output
                .authorization_packet(NETWORK, kind)
                .unwrap()
                .encode()
                .to_vec(),
            input_value: input.value(),
            output_value,
            taxable,
        });
    }
    entries.sort_by_key(|entry| entry.nullifier);

    let accounting_actions = entries
        .iter()
        .map(|entry| entry.accounting)
        .collect::<Vec<_>>();
    let accounting_actions: [AccountingActionWitness; N] = match accounting_actions.try_into() {
        Ok(actions) => actions,
        Err(_) => unreachable!("fixture entry count matches const bucket"),
    };
    let arithmetic =
        PreparedAccountingArithmetic::new(accounting_actions, GAS_UNITS, FEE_PER_GAS).unwrap();
    let epoch_key = epoch_key();
    let burn = arithmetic.burn();
    let burn_commitment = PreparedBurnCommitment::create(burn, MAXIMUM_VALUE, &mut rng).unwrap();
    let burn_ciphertext =
        PreparedBurnCiphertext::encrypt(burn, MAXIMUM_VALUE, &epoch_key, &mut rng).unwrap();
    let accounting =
        PreparedAccountingBurn::new(arithmetic, &burn_commitment, &burn_ciphertext, &epoch_key)
            .unwrap();
    let burn_payload = EncryptedBurnV2::from_threshold_ciphertext(
        &epoch_key,
        burn_commitment.commitment(),
        burn_ciphertext.ciphertext(),
    )
    .unwrap();
    let effects = TransferV2Effects::new(
        ChainId::new(NETWORK),
        suite.circuit_id(),
        anchor,
        burn_payload,
        GasParameters {
            units: GAS_UNITS,
            fee_per_gas: FEE_PER_GAS,
        },
        entries.iter().map(|entry| entry.public.clone()).collect(),
    )
    .unwrap();
    let witness = encode_witness(
        suite,
        &full_viewing_key.export(),
        anchor,
        &entries,
        &epoch_key,
        burn,
        *burn_commitment.trapdoor(),
        *burn_ciphertext.randomness(),
    );
    let delegated_witness = strict_change_recipient.then(|| {
        let delegated_actions: [DelegatedActionWitness; N] = entries
            .iter()
            .map(|entry| {
                DelegatedActionWitness::new(
                    PrivateNote::decode_private(
                        entry
                            .input_note
                            .as_slice()
                            .try_into()
                            .expect("fixed private note bytes"),
                        MAXIMUM_VALUE,
                    )
                    .unwrap(),
                    entry.membership_path.clone(),
                    entry.authorization_randomizer,
                    entry.net_value_trapdoor,
                    OutputAuthorizationPacket::decode(&entry.output_packet).unwrap(),
                )
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap_or_else(|_| unreachable!("fixture entry count matches const bucket"));
        DelegatedTransferWitness::new(
            &effects,
            MAXIMUM_VALUE,
            VaultFullViewingKey::from_bytes(*full_viewing_key.export()).unwrap(),
            delegated_actions,
            epoch_key.clone(),
            *burn_commitment.trapdoor(),
            *burn_ciphertext.randomness(),
        )
        .unwrap()
        .encode()
        .to_vec()
    });
    let prepared = PreparedVaultTransfer::new(
        entries.into_iter().map(|entry| entry.circuit).collect(),
        accounting,
        &effects,
        &epoch_key,
    )
    .unwrap();

    ConformanceFixture {
        prepared,
        effects,
        epoch_key,
        witness,
        delegated_witness,
    }
}

fn seeded_rho(index: usize) -> ActionNullifier {
    let byte = u8::try_from(index + 2).expect("maximum fixture bucket fits u8");
    ActionNullifier::from_bytes([byte; 32]).expect("fixture rho is canonical")
}

fn two_leaf_paths(commitments: [[u8; 32]; 2]) -> (NoteTreeRoot, [NoteMembershipPath; 2]) {
    let commitments = commitments.map(|bytes| {
        Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&bytes))
            .unwrap()
    });
    let leaves = commitments.map(|cmx| MerkleHashOrchard::from_cmx(&cmx));
    let paths = [0_u32, 1_u32].map(|position| {
        let mut nodes = [MerkleHashOrchard::empty_leaf(); 32];
        nodes[0] = leaves[1 - position as usize];
        for level in 1_u8..32 {
            nodes[usize::from(level)] = MerkleHashOrchard::empty_root(Level::from(level));
        }
        let orchard_path = MerklePath::from_parts(position, nodes);
        let root = orchard_path.root(commitments[position as usize]);
        let path =
            NoteMembershipPath::from_parts(position, nodes.map(|node| node.to_bytes())).unwrap();
        (root, path)
    });
    assert_eq!(paths[0].0, paths[1].0);
    (
        NoteTreeRoot::from_bytes(paths[0].0.to_bytes()).unwrap(),
        [paths[0].1.clone(), paths[1].1.clone()],
    )
}

fn epoch_key() -> EpochBurnPublicKey {
    let coefficients = [pallas::Scalar::from(7), pallas::Scalar::from(11)];
    let commitments = coefficients.map(|value| (pallas::Point::generator() * value).to_bytes());
    EpochBurnPublicKey::from_parts(9, 2, vec![1, 2, 3], commitments.to_vec()).unwrap()
}

#[allow(clippy::too_many_arguments)]
fn encode_witness(
    suite: VaultTransferSuite,
    full_viewing_key: &[u8; 96],
    anchor: NoteTreeRoot,
    entries: &[ActionEntry],
    epoch_key: &EpochBurnPublicKey,
    burn: u64,
    burn_commitment_trapdoor: [u8; 32],
    burn_encryption_randomness: [u8; 32],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&WITNESS_MAGIC);
    bytes.extend_from_slice(&VECTOR_VERSION.to_le_bytes());
    bytes.push(suite.action_count());
    bytes.extend_from_slice(suite.circuit_id().as_bytes());
    bytes.extend_from_slice(&NETWORK);
    bytes.extend_from_slice(&MAXIMUM_VALUE.to_le_bytes());
    bytes.extend_from_slice(&FIXTURE_SEED);
    bytes.extend_from_slice(full_viewing_key);
    bytes.extend_from_slice(&anchor.to_bytes());
    for entry in entries {
        bytes.extend_from_slice(&entry.nullifier.to_bytes());
        bytes.extend_from_slice(&entry.input_note);
        bytes.extend_from_slice(&entry.membership_path.position().to_le_bytes());
        for node in entry.membership_path.auth_path() {
            bytes.extend_from_slice(node);
        }
        bytes.extend_from_slice(&entry.authorization_randomizer);
        bytes.extend_from_slice(&entry.net_value_trapdoor);
        push_len(&mut bytes, entry.output_packet.len());
        bytes.extend_from_slice(&entry.output_packet);
        bytes.extend_from_slice(&entry.input_value.to_le_bytes());
        bytes.extend_from_slice(&entry.output_value.to_le_bytes());
        bytes.push(u8::from(entry.taxable));
    }
    bytes.extend_from_slice(&epoch_key.epoch().to_le_bytes());
    bytes.extend_from_slice(&epoch_key.threshold().to_le_bytes());
    push_len(&mut bytes, epoch_key.participants().len());
    for participant in epoch_key.participants() {
        bytes.extend_from_slice(&participant.to_le_bytes());
    }
    push_len(&mut bytes, epoch_key.coefficient_commitments().len());
    for commitment in epoch_key.coefficient_commitments() {
        bytes.extend_from_slice(commitment);
    }
    bytes.extend_from_slice(&burn.to_le_bytes());
    bytes.extend_from_slice(&burn_commitment_trapdoor);
    bytes.extend_from_slice(&burn_encryption_randomness);
    bytes
}

pub fn encode_instances<const N: usize>(fixture: &ConformanceFixture<N>) -> Vec<u8> {
    let columns = fixture.prepared.public_inputs();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&INSTANCE_MAGIC);
    bytes.extend_from_slice(&VECTOR_VERSION.to_le_bytes());
    bytes.push(u8::try_from(N).unwrap());
    bytes.push(u8::try_from(columns.len()).unwrap());
    for column in columns {
        push_len(&mut bytes, column.len());
        for value in column {
            bytes.extend_from_slice(value.to_repr().as_ref());
        }
    }
    bytes
}

pub fn mutated_effects(effects: &TransferV2Effects) -> TransferV2Effects {
    let empty_anchor = NoteTreeRoot::from_bytes(Anchor::empty_tree().to_bytes()).unwrap();
    assert_ne!(effects.anchor(), empty_anchor);
    TransferV2Effects::new(
        effects.chain_id(),
        effects.circuit_id(),
        empty_anchor,
        effects.burn().clone(),
        effects.gas(),
        effects.actions().to_vec(),
    )
    .unwrap()
}

pub fn create_real_proof<const N: usize>(
    fixture: &ConformanceFixture<N>,
    seed: [u8; 32],
) -> Vec<u8> {
    ProverMaterial::<N>::build().prove(fixture, seed)
}

pub struct ProverMaterial<const N: usize> {
    params: Params<EqAffine>,
    pk: ProvingKey<EqAffine>,
}

impl<const N: usize> ProverMaterial<N> {
    pub fn build() -> Self {
        let suite = VaultTransferSuite::for_action_count(N).unwrap();
        let params: Params<EqAffine> = Params::new(suite.k());
        let empty = VaultTransferCircuit::<N>::empty().unwrap();
        let vk = keygen_vk(&params, &empty).unwrap();
        assert!(material_matches_suite(suite, &params, &vk));
        let pk = keygen_pk(&params, vk, &empty).unwrap();
        Self { params, pk }
    }

    pub fn prove(&self, fixture: &ConformanceFixture<N>, seed: [u8; 32]) -> Vec<u8> {
        let circuit = fixture.prepared.circuit();
        let public = fixture.prepared.public_inputs();
        let public_columns = public.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let proof_instances = [&public_columns[..]];
        let mut transcript =
            Blake2bWrite::<Vec<u8>, EqAffine, Challenge255<EqAffine>>::init(Vec::new());
        create_proof(
            &self.params,
            &self.pk,
            &[circuit],
            &proof_instances,
            ChaCha20Rng::from_seed(seed),
            &mut transcript,
        )
        .unwrap();
        let proof = transcript.finalize();
        verify_with::<N>(
            &self.params,
            self.pk.get_vk(),
            &fixture.effects,
            &fixture.epoch_key,
            &proof,
        )
        .unwrap();
        proof
    }
}

pub struct VerifierMaterial<const N: usize> {
    params: Params<EqAffine>,
    vk: VerifyingKey<EqAffine>,
}

impl<const N: usize> VerifierMaterial<N> {
    pub fn build() -> Self {
        let suite = VaultTransferSuite::for_action_count(N).unwrap();
        let params = Params::new(suite.k());
        let empty = VaultTransferCircuit::<N>::empty().unwrap();
        let vk = keygen_vk(&params, &empty).unwrap();
        assert!(material_matches_suite(suite, &params, &vk));
        Self { params, vk }
    }

    pub fn parameter_bytes(&self) -> Vec<u8> {
        parameter_bytes(&self.params)
    }

    pub fn build_from_parameter_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        let suite = VaultTransferSuite::for_action_count(N).ok_or("unsupported action count")?;
        if setup_fingerprint(PARAMETER_DIGEST_CONTEXT, bytes) != suite.parameter_digest() {
            return Err("unexpected Halo2 parameter fingerprint");
        }
        let mut reader = bytes;
        let params = Params::read(&mut reader).map_err(|_| "invalid Halo2 parameters")?;
        if !reader.is_empty() || params.k() != suite.k() {
            return Err("wrong Halo2 parameter identity");
        }
        let empty = VaultTransferCircuit::<N>::empty().map_err(|_| "invalid transfer shape")?;
        let vk = keygen_vk(&params, &empty).map_err(|_| "invalid transfer verifying key")?;
        if !material_matches_suite(suite, &params, &vk) {
            return Err("unexpected transfer verifying-key fingerprint");
        }
        Ok(Self { params, vk })
    }

    pub fn verify(
        &self,
        effects: &TransferV2Effects,
        epoch_key: &EpochBurnPublicKey,
        proof: &[u8],
    ) -> bool {
        verify_with::<N>(&self.params, &self.vk, effects, epoch_key, proof).is_ok()
    }

    pub fn verify_batch(
        &self,
        effects: &TransferV2Effects,
        epoch_key: &EpochBurnPublicKey,
        proof: &[u8],
        batch_size: usize,
    ) -> bool {
        let Some(suite) = VaultTransferSuite::for_action_count(N) else {
            return false;
        };
        if batch_size == 0
            || effects.actions().len() != N
            || effects.circuit_id() != suite.circuit_id()
        {
            return false;
        }
        let Ok(public) =
            vault_zk_halo2_core::transfer_circuit::VaultTransferPublicInputs::<N>::from_effects(
                effects, epoch_key,
            )
        else {
            return false;
        };
        let public = public.to_columns();
        let mut batch = BatchVerifier::new();
        for _ in 0..batch_size {
            batch.add_proof(vec![public.clone()], proof.to_vec());
        }
        batch.finalize(&self.params, &self.vk)
    }
}

fn verify_with<const N: usize>(
    params: &Params<EqAffine>,
    vk: &VerifyingKey<EqAffine>,
    effects: &TransferV2Effects,
    epoch_key: &EpochBurnPublicKey,
    proof: &[u8],
) -> Result<(), ()> {
    let suite = VaultTransferSuite::for_action_count(N).ok_or(())?;
    if effects.actions().len() != N || effects.circuit_id() != suite.circuit_id() {
        return Err(());
    }
    let public =
        vault_zk_halo2_core::transfer_circuit::VaultTransferPublicInputs::<N>::from_effects(
            effects, epoch_key,
        )
        .map_err(|_| ())?
        .to_columns();
    let public_columns = public.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let proof_instances = [&public_columns[..]];
    let strategy = SingleVerifier::new(params);
    let mut transcript = Blake2bRead::<&[u8], EqAffine, Challenge255<EqAffine>>::init(proof);
    verify_proof(params, vk, strategy, &proof_instances, &mut transcript).map_err(|_| ())
}

#[derive(Debug)]
pub struct VectorBundle {
    pub action_count: u8,
    pub k: u32,
    pub suite_id: [u8; 32],
    pub proof_seed: [u8; 32],
    pub witness: Vec<u8>,
    pub effects: Vec<u8>,
    pub instances: Vec<u8>,
    pub proof: Vec<u8>,
    pub mutated_effects: Vec<u8>,
    pub proof_mutation_offset: usize,
    pub proof_mutation_xor: u8,
    pub expected: [u8; 3],
}

impl VectorBundle {
    pub fn new<const N: usize>(
        fixture: &ConformanceFixture<N>,
        proof_seed: [u8; 32],
        proof: Vec<u8>,
    ) -> Self {
        let suite = VaultTransferSuite::for_action_count(N).unwrap();
        Self {
            action_count: u8::try_from(N).unwrap(),
            k: suite.k(),
            suite_id: suite.circuit_id().into_bytes(),
            proof_seed,
            witness: fixture.witness.clone(),
            effects: fixture.effects.encode_canonical(),
            instances: encode_instances(fixture),
            proof_mutation_offset: proof.len() / 2,
            proof_mutation_xor: 1,
            proof,
            mutated_effects: mutated_effects(&fixture.effects).encode_canonical(),
            expected: [1, 0, 0],
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let sections = [
            (b"witness".as_slice(), self.witness.as_slice()),
            (b"effects".as_slice(), self.effects.as_slice()),
            (b"instances".as_slice(), self.instances.as_slice()),
            (b"proof".as_slice(), self.proof.as_slice()),
            (
                b"mutated-effects".as_slice(),
                self.mutated_effects.as_slice(),
            ),
        ];
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&VECTOR_MAGIC);
        bytes.extend_from_slice(&VECTOR_VERSION.to_le_bytes());
        bytes.push(self.action_count);
        bytes.extend_from_slice(&self.k.to_le_bytes());
        bytes.extend_from_slice(&self.suite_id);
        bytes.extend_from_slice(&self.proof_seed);
        for (tag, section) in sections {
            push_len(&mut bytes, section.len());
            bytes.extend_from_slice(&vector_section_digest(tag, section));
        }
        bytes.extend_from_slice(
            &u32::try_from(self.proof_mutation_offset)
                .unwrap()
                .to_le_bytes(),
        );
        bytes.push(self.proof_mutation_xor);
        bytes.extend_from_slice(&self.expected);
        for (_, section) in sections {
            bytes.extend_from_slice(section);
        }
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        let mut reader = Reader::new(bytes);
        if reader.take::<4>()? != VECTOR_MAGIC
            || u16::from_le_bytes(reader.take()?) != VECTOR_VERSION
        {
            return Err("wrong vector header");
        }
        let action_count = reader.take::<1>()?[0];
        let k = u32::from_le_bytes(reader.take()?);
        let suite_id = reader.take()?;
        let proof_seed = reader.take()?;
        let mut lengths = [0_usize; 5];
        let mut digests = [[0_u8; 32]; 5];
        for index in 0..5 {
            lengths[index] = usize::try_from(u32::from_le_bytes(reader.take()?))
                .map_err(|_| "invalid section length")?;
            digests[index] = reader.take()?;
        }
        let proof_mutation_offset =
            usize::try_from(u32::from_le_bytes(reader.take()?)).map_err(|_| "invalid offset")?;
        let proof_mutation_xor = reader.take::<1>()?[0];
        let expected = reader.take()?;
        let mut sections = Vec::with_capacity(5);
        for length in lengths {
            sections.push(reader.take_slice(length)?.to_vec());
        }
        if !reader.is_empty() {
            return Err("trailing vector bytes");
        }
        let tags: [&[u8]; 5] = [
            b"witness",
            b"effects",
            b"instances",
            b"proof",
            b"mutated-effects",
        ];
        for index in 0..5 {
            if vector_section_digest(tags[index], &sections[index]) != digests[index] {
                return Err("vector section digest mismatch");
            }
        }
        if proof_mutation_xor == 0 || proof_mutation_offset >= sections[3].len() {
            return Err("invalid proof mutation");
        }
        Ok(Self {
            action_count,
            k,
            suite_id,
            proof_seed,
            witness: sections.remove(0),
            effects: sections.remove(0),
            instances: sections.remove(0),
            proof: sections.remove(0),
            mutated_effects: sections.remove(0),
            proof_mutation_offset,
            proof_mutation_xor,
            expected,
        })
    }
}

pub fn vector_section_digest(tag: &[u8], section: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(SECTION_DIGEST_CONTEXT);
    hasher.update(&(tag.len() as u16).to_le_bytes());
    hasher.update(tag);
    hasher.update(&(section.len() as u64).to_le_bytes());
    hasher.update(section);
    *hasher.finalize().as_bytes()
}

fn push_len(bytes: &mut Vec<u8>, length: usize) {
    bytes.extend_from_slice(&u32::try_from(length).unwrap().to_le_bytes());
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], &'static str> {
        self.take_slice(N)?
            .try_into()
            .map_err(|_| "invalid fixed vector field")
    }

    fn take_slice(&mut self, length: usize) -> Result<&'a [u8], &'static str> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or("vector length overflow")?;
        let value = self.bytes.get(self.offset..end).ok_or("truncated vector")?;
        self.offset = end;
        Ok(value)
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

pub fn effects_from_bytes(bytes: &[u8]) -> TransferV2Effects {
    TransferV2Effects::decode_canonical(bytes).expect("canonical committed vector effects")
}
