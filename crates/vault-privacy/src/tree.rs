//! Authenticated Ironwood/Orchard-compatible note commitment tree.

use std::fmt;

use incrementalmerkletree::{Hashable, Position, frontier::Frontier};
use orchard::{
    Anchor,
    note::ExtractedNoteCommitment,
    tree::{MerkleHashOrchard, MerklePath},
};

use crate::PrivacyError;

/// Fixed Ironwood/Orchard note-commitment tree depth.
pub const NOTE_TREE_DEPTH: u8 = 32;
const NOTE_TREE_CAPACITY: u64 = 1u64 << NOTE_TREE_DEPTH;

/// Canonical root of the Ironwood/Orchard-compatible depth-32 commitment tree.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NoteTreeRoot([u8; 32]);

impl fmt::Debug for NoteTreeRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "NoteTreeRoot(")?;
        for byte in &self.0[..6] {
            write!(formatter, "{byte:02x}")?;
        }
        write!(formatter, "…)")
    }
}

impl NoteTreeRoot {
    /// Parses a canonical Pallas base-field encoding.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, PrivacyError> {
        Option::<Anchor>::from(Anchor::from_bytes(bytes))
            .map(|_| Self(bytes))
            .ok_or(PrivacyError::InvalidNoteTreeRoot)
    }

    /// Canonical field encoding committed by consensus.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Consensus-state frontier for the append-only private note tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoteCommitmentTree {
    frontier: Frontier<MerkleHashOrchard, NOTE_TREE_DEPTH>,
}

impl Default for NoteCommitmentTree {
    fn default() -> Self {
        Self::new()
    }
}

impl NoteCommitmentTree {
    /// Creates the canonical empty depth-32 note tree.
    #[must_use]
    pub fn new() -> Self {
        Self {
            frontier: Frontier::empty(),
        }
    }

    /// Restores a frontier after validating its size, canonical nodes, and
    /// position-dependent ommer count.
    pub fn restore(snapshot: &NoteTreeSnapshot) -> Result<Self, PrivacyError> {
        if snapshot.tree_size > NOTE_TREE_CAPACITY {
            return Err(PrivacyError::InvalidNoteTreeSnapshot);
        }
        if snapshot.tree_size == 0 {
            if snapshot.leaf.is_some() || !snapshot.ommers.is_empty() {
                return Err(PrivacyError::InvalidNoteTreeSnapshot);
            }
            return Ok(Self::new());
        }

        let leaf = parse_tree_node(
            snapshot
                .leaf
                .as_ref()
                .ok_or(PrivacyError::InvalidNoteTreeSnapshot)?,
        )?;
        let ommers = snapshot
            .ommers
            .iter()
            .map(parse_tree_node)
            .collect::<Result<Vec<_>, _>>()?;
        let position = Position::from(snapshot.tree_size - 1);
        let frontier = Frontier::from_parts(position, leaf, ommers)
            .map_err(|_| PrivacyError::InvalidNoteTreeSnapshot)?;
        if frontier.tree_size() != snapshot.tree_size {
            return Err(PrivacyError::InvalidNoteTreeSnapshot);
        }

        Ok(Self { frontier })
    }

    /// Number of commitments appended to the tree.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.frontier.tree_size()
    }

    /// Canonical root used as the public anchor of a transfer proof.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        Anchor::from(self.frontier.root()).to_bytes()
    }

    /// Typed canonical root used by transfer-v2.
    #[must_use]
    pub fn typed_root(&self) -> NoteTreeRoot {
        NoteTreeRoot(self.root())
    }

    /// Appends one canonical extracted note commitment.
    ///
    /// The returned path witnesses the new tip at the returned post-append
    /// root. Wallets must update this path as later commitments are appended.
    pub fn append(&mut self, commitment: [u8; 32]) -> Result<NoteTreeAppend, PrivacyError> {
        if self.size() == NOTE_TREE_CAPACITY {
            return Err(PrivacyError::NoteTreeFull);
        }
        let cmx = parse_note_commitment(&commitment)?;
        let position = u32::try_from(self.size()).map_err(|_| PrivacyError::NoteTreeFull)?;
        let appended = self.frontier.append(MerkleHashOrchard::from_cmx(&cmx));
        if !appended {
            return Err(PrivacyError::NoteTreeFull);
        }

        // A frontier always contains the complete past for its tip; every
        // future node is the canonical empty root for that node's level.
        let path = self
            .frontier
            .witness(|address| Some(MerkleHashOrchard::empty_root(address.level())))
            .expect("a canonical frontier can witness its tip")
            .expect("the tree is non-empty immediately after append");
        let membership_path = NoteMembershipPath {
            position,
            auth_path: path
                .path_elems()
                .iter()
                .map(MerkleHashOrchard::to_bytes)
                .collect::<Vec<_>>()
                .try_into()
                .expect("depth-32 frontier returns 32 authentication nodes"),
        };
        let root = self.root();
        debug_assert!(membership_path.verify(commitment, root));

        Ok(NoteTreeAppend {
            position,
            root,
            membership_path,
        })
    }

    /// Serializes the minimal validated frontier needed to continue appending.
    #[must_use]
    pub fn snapshot(&self) -> NoteTreeSnapshot {
        self.frontier.value().map_or_else(
            || NoteTreeSnapshot {
                tree_size: 0,
                leaf: None,
                ommers: Vec::new(),
            },
            |frontier| NoteTreeSnapshot {
                tree_size: self.frontier.tree_size(),
                leaf: Some(frontier.leaf().to_bytes()),
                ommers: frontier
                    .ommers()
                    .iter()
                    .map(MerkleHashOrchard::to_bytes)
                    .collect(),
            },
        )
    }
}

/// Minimal persistent representation of an append-only note-tree frontier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoteTreeSnapshot {
    tree_size: u64,
    leaf: Option<[u8; 32]>,
    ommers: Vec<[u8; 32]>,
}

impl NoteTreeSnapshot {
    /// Constructs snapshot data. Validation occurs in
    /// [`NoteCommitmentTree::restore`].
    #[must_use]
    pub fn from_parts(tree_size: u64, leaf: Option<[u8; 32]>, ommers: Vec<[u8; 32]>) -> Self {
        Self {
            tree_size,
            leaf,
            ommers,
        }
    }

    /// Number of leaves represented by the frontier.
    #[must_use]
    pub const fn tree_size(&self) -> u64 {
        self.tree_size
    }

    /// Most recently appended leaf, if any.
    #[must_use]
    pub const fn leaf(&self) -> Option<[u8; 32]> {
        self.leaf
    }

    /// Past subtree roots required to resume deterministic appends.
    #[must_use]
    pub fn ommers(&self) -> &[[u8; 32]] {
        &self.ommers
    }
}

/// Result of one successful commitment-tree append.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoteTreeAppend {
    position: u32,
    root: [u8; 32],
    membership_path: NoteMembershipPath,
}

impl NoteTreeAppend {
    /// Zero-based leaf position.
    #[must_use]
    pub const fn position(&self) -> u32 {
        self.position
    }

    /// Post-append tree root.
    #[must_use]
    pub const fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Initial membership path at the post-append root.
    #[must_use]
    pub const fn membership_path(&self) -> &NoteMembershipPath {
        &self.membership_path
    }
}

/// Depth-32 private note membership witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoteMembershipPath {
    position: u32,
    auth_path: [[u8; 32]; NOTE_TREE_DEPTH as usize],
}

impl NoteMembershipPath {
    /// Parses a membership path with canonical authentication nodes.
    pub fn from_parts(
        position: u32,
        auth_path: [[u8; 32]; NOTE_TREE_DEPTH as usize],
    ) -> Result<Self, PrivacyError> {
        for node in &auth_path {
            parse_tree_node(node).map_err(|_| PrivacyError::InvalidMembershipPath)?;
        }
        Ok(Self {
            position,
            auth_path,
        })
    }

    /// Zero-based position whose direction bits select sibling ordering.
    #[must_use]
    pub const fn position(&self) -> u32 {
        self.position
    }

    /// Canonical authentication nodes from leaf level to root.
    #[must_use]
    pub const fn auth_path(&self) -> &[[u8; 32]; NOTE_TREE_DEPTH as usize] {
        &self.auth_path
    }

    /// Verifies this path against an extracted note commitment and expected
    /// anchor. This is a native check; the transfer circuit must enforce the
    /// same computation for a private spend.
    #[must_use]
    pub fn verify(&self, commitment: [u8; 32], expected_root: [u8; 32]) -> bool {
        let Some(cmx) = Option::<ExtractedNoteCommitment>::from(
            ExtractedNoteCommitment::from_bytes(&commitment),
        ) else {
            return false;
        };
        let Some(auth_path) = self
            .auth_path
            .iter()
            .map(|node| Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(node)))
            .collect::<Option<Vec<_>>>()
            .and_then(|nodes| nodes.try_into().ok())
        else {
            return false;
        };
        let path = MerklePath::from_parts(self.position, auth_path);
        path.root(cmx).to_bytes() == expected_root
    }
}

fn parse_note_commitment(commitment: &[u8; 32]) -> Result<ExtractedNoteCommitment, PrivacyError> {
    if commitment == &[0; 32] {
        return Err(PrivacyError::InvalidEncryptedOutput);
    }
    Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(commitment))
        .ok_or(PrivacyError::InvalidEncryptedOutput)
}

fn parse_tree_node(bytes: &[u8; 32]) -> Result<MerkleHashOrchard, PrivacyError> {
    Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(bytes))
        .ok_or(PrivacyError::InvalidNoteTreeSnapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commitment(byte: u8) -> [u8; 32] {
        let bytes = [byte; 32];
        assert!(
            Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&bytes))
                .is_some()
        );
        bytes
    }

    #[test]
    fn empty_root_matches_orchard_anchor() {
        let tree = NoteCommitmentTree::new();
        assert_eq!(tree.size(), 0);
        assert_eq!(tree.root(), Anchor::empty_tree().to_bytes());
    }

    #[test]
    fn append_returns_a_path_for_the_exact_post_append_root() {
        let mut tree = NoteCommitmentTree::new();
        let first_commitment = commitment(1);
        let first = tree.append(first_commitment).unwrap();
        assert_eq!(first.position(), 0);
        assert!(
            first
                .membership_path()
                .verify(first_commitment, first.root())
        );

        let second_commitment = commitment(2);
        let second = tree.append(second_commitment).unwrap();
        assert_eq!(second.position(), 1);
        assert!(
            second
                .membership_path()
                .verify(second_commitment, second.root())
        );
        assert_ne!(first.root(), second.root());
        assert!(
            !first
                .membership_path()
                .verify(first_commitment, second.root())
        );
    }

    #[test]
    fn frontier_snapshot_round_trip_preserves_future_roots() {
        let mut original = NoteCommitmentTree::new();
        original.append(commitment(3)).unwrap();
        original.append(commitment(4)).unwrap();
        let mut restored = NoteCommitmentTree::restore(&original.snapshot()).unwrap();

        assert_eq!(restored.root(), original.root());
        assert_eq!(restored.size(), original.size());
        let expected = original.append(commitment(5)).unwrap();
        let actual = restored.append(commitment(5)).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn malformed_snapshots_and_paths_fail_closed() {
        let snapshot = NoteTreeSnapshot::from_parts(1, Some(commitment(1)), vec![commitment(2)]);
        assert_eq!(
            NoteCommitmentTree::restore(&snapshot).unwrap_err(),
            PrivacyError::InvalidNoteTreeSnapshot
        );
        let noncanonical = [0xff; 32];
        let snapshot = NoteTreeSnapshot::from_parts(1, Some(noncanonical), vec![]);
        assert_eq!(
            NoteCommitmentTree::restore(&snapshot).unwrap_err(),
            PrivacyError::InvalidNoteTreeSnapshot
        );

        let mut tree = NoteCommitmentTree::new();
        let appended = tree.append(commitment(6)).unwrap();
        let mut path = *appended.membership_path().auth_path();
        path[0] = noncanonical;
        assert_eq!(
            NoteMembershipPath::from_parts(0, path).unwrap_err(),
            PrivacyError::InvalidMembershipPath
        );
    }
}
