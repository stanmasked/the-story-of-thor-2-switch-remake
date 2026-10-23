# The Story of Thor 2 — Stage 101: targeted scan of oversized ISO containers

## Scope and storage

The original ISO was read locally and was not modified. Stage 100 had excluded three large CPK containers from its full code scan. This stage re-read those containers directly from their ISO extents and searched only for the exact byte sequence corresponding to the unresolved service-slot pointer and aligned SH-2 PC-relative `MOV.L` literals that resolve to it. The payloads were not extracted to standalone files, retained as artifacts, or published.

## Results

- `CPK0.BIN`: 29,484,064 bytes; zero exact pointer-byte-sequence occurrences and zero aligned PC-relative literal references resolving to the slot.
- `CPK1.BIN`: 36,248,008 bytes; zero exact pointer-byte-sequence occurrences and zero aligned PC-relative literal references resolving to the slot.
- `CPK2.BIN`: 30,512,196 bytes; zero exact pointer-byte-sequence occurrences and zero aligned PC-relative literal references resolving to the slot.
- Total targeted scan: 96,244,268 bytes across all three oversized containers.

The targeted scan closes one narrow coverage gap from Stage 100: the three containers contain no literal representation of this pointer slot under the tested byte order and instruction pattern. It is **not** a full disassembly of compressed resources, and it does not rule out split-address construction, a differently encoded initializer, or initialization by the Saturn BIOS/runtime outside the disc image.

## Implementation and tests

Added `tools/stage101_oversized_container_slot_scan.py` (JSON stage identifier: `stage101_oversized_container_slot_scan`). It resolves the slot using the established Stage 97–100 static chain, scans oversized ISO payloads one at a time, and emits only filenames, sizes, and aggregate match counts. It does not output pointer values, offsets, instruction bytes, hashes of private payloads, or raw data.

Added six synthetic tests for PC-relative literal detection, separation of raw byte occurrences from instruction references, multiple matches, aggregate-only summaries, no-match cases, and the output privacy contract. GitHub Actions results will be recorded in the private manifest after the run completes.

## Impact on the R13 conclusion

The Stage 99–100 conclusion does not change. The second control-byte store is statically equal to `1` only if the unresolved runtime callee reached through the low-memory slot preserves R13 and the loader wrapper returns via its normal success path. This scan does not identify that target or prove its calling convention at runtime.

## Next stage — Stage 102

1. Search the private Google Drive and ChatGPT Library for an existing Saturn BIOS, emulator configuration, runtime trace, or breakpoint/capture bundle before requesting or generating new evidence.
2. If authorized runtime material is already available, verify its completeness and SHA-256, preserve the original unchanged in private Drive, and save a separate manifest and analysis report before using it.
3. If no runtime evidence exists, keep the result explicitly conditional; do not claim the service target, runtime control-byte value, callback registration, overlay execution, DMA completion, or same-frame graphics timing.

**Boundary:** this stage proves only that the three oversized CPK payloads have zero matches for the exact pointer bytes and zero aligned PC-relative literal references resolving to the slot. Runtime initialization and target identity remain unresolved.