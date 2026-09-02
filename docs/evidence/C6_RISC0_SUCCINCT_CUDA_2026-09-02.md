# C6 RISC Zero Succinct CUDA evidence — 2026-09-02

**Result:** pass for the isolated C6 classification measurement  
**Maturity:** non-activatable comparison evidence; synthetic fixture only

## Evidence

The published two-action Composite receipt was compressed to a real RISC Zero
Succinct receipt on an external RTX 5090. The test reopened and verified the
output, then rejected a wrong public-input digest, a changed proof byte, and a
truncated receipt.

| Field | Recorded value |
|---|---|
| Binary source commit | `b4482a961f95ac74f6bf981a080ab047604bb516` |
| Forward-PTX runner commit | `bfa534aae8387e9f1f97c06a9f6c4b744fc964e8` |
| Reviewed guest image ID | `85170f11445f10ba9b26e4ca96f29600fe4e30410081905f519a99449dd2d128` |
| Public inputs | `ad626fcc1292ab423bdfc773c568662c02aecd83f9b29481ea040a236b909454` |
| Input | Composite, 311,977,650 bytes |
| Input SHA-256 | `12c952e2da0466d7047586404b15c7ad6fa59675bb8c975019b4645dca7e6e96` |
| Output | Succinct, 223,530 bytes |
| Output SHA-256 | `a67162b1fe4f66e5033f407683b6dea264233cd553995de5596d529da724945a` |
| Protocol maximum | 2,097,152 bytes |
| Size decision | compatible |
| Compression elapsed | 660,343 ms (11 minutes 0.343 seconds) |
| Complete test | pass in 716.23 seconds (11 minutes 56.23 seconds) |
| Resource samples | 340 at two-second intervals |
| Peak GPU memory | 2,652 MiB |
| Peak host RSS | 2,059,940 KiB |
| GPU | NVIDIA GeForce RTX 5090, 32,607 MiB, `sm_120` |
| Driver | 580.159.03 |
| Host memory | 515,760 MiB |
| CUDA execution | forced forward PTX JIT from verified `compute_90` |

CI run
[`33672603880`](https://github.com/TOMASCORZO/vault/actions/runs/33672603880)
used CUDA 12.8.1 `cuobjdump` to confirm that the reviewed `sm_90` binary embeds
PTX before packaging the fail-closed `sm_120` runner. The input and bundle were
downloaded in parallel ranges on the paid host; no repository clone, package
installation, Rust installation, Cargo build, or CUDA compilation occurred
during the rental.

The receipt and its log, environment report, manifest, resource samples, and
complete checksum list are published in prerelease
[`c6-risc0-succinct-v1`](https://github.com/TOMASCORZO/vault/releases/tag/c6-risc0-succinct-v1).
The same files remain under `/Users/tomascorzo/vault-c6-evidence/`, and the
receipt hash was recomputed after transfer. Vast.ai instance `49678408` was
destroyed after verification; no instance or attached storage remains.

## Selection result and limits

The specialized Halo2 transfer circuit is selected as Vault's base-layer proof
candidate. RISC Zero 3.0.6 is rejected for base-layer activation. Succinct
wrapping resolves the measured envelope-size failure, but does not resolve the
1,329.338-second Composite base proof, the resolved host/guest RustSec
vulnerabilities, maintenance warnings, yanked dependency, or the absence of an
approved activatable verifier.

This was one two-action classification run using forward PTX JIT, not a native
Blackwell performance comparison or a claim about larger buckets. C6 permits a
rejected candidate to stop at the minimum bucket once hard protocol or
activation blockers are evidenced. The selected Halo2 candidate has the
required repeated all-bucket, key preparation, proving, verification, memory,
proof-size, and concurrency measurements.

No verifier is activated, and this evidence does not make Vault safe for real
funds.
