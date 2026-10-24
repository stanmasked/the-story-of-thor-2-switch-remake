# The Story of Thor 2 — Stage 115: attribution of R13 transitions and full-pipeline control-flow witness

## Current private attribution — safe summary

The pinned European ISO and BIOS were rechecked, and the root payload was re-extracted and compared byte-for-byte. The Stage114 A/B return windows and Stage113 A/B selected-opcode traces are byte-identical.

Inside the confirmed outer BSR-to-RTS window, 12 intermediate changes to R13 were recorded. Each changed value corresponds to a selected instruction word that matches the unchanged original payload. The safe family counts are:

- immediate move into R13: 2
- PC-relative word load into R13: 1
- PC-relative long load into R13: 2
- indirect long load into R13: 1
- stack post-increment long load into R13: 6

The outer call has equal R13 values at entry and the confirmed return boundary. The six nested frames inferred from the longer selected-opcode trace each contain two R13 transitions and matching entry/return values. This is useful attribution, but the Stage113 stack reconstruction is not independent full-pipeline proof: its selected-opcode stream lacks the complete PC_ID/PC_IF context for every nested event. Two additional static direct-call candidates were found, but neither was executed in the captured window.

## Stage115 public instrumentation

The new default-disabled observer captures bounded pre/post full-pipeline state for normal BSR, JSR and RTS dispatches, their delay slots, return-site follow-up steps, and every observed R13 change. Runtime trigger and output path are supplied only to private execution. Original game data, BIOS, private addresses, register values and raw traces are absent from public source and CI artifacts.

The strict gate checks row integrity, monotonic step order, delay-slot adjacency, call/return-token matching and nested stack closure. It emits only counts and booleans. Even a complete observed call path does not prove preservation on all alternate paths.

Eleven synthetic tests pass locally. The dedicated GitHub Actions workflow must now validate the actual source patch and compile the public-only emulator. No Stage115 runtime result is claimed until that exact-head build succeeds and two private A/B captures are completed and archived with SHA-256 readback.

## Remaining proof boundaries

- R13 is not unchanged throughout the observed call; the 12 transitions are real and attributed to instruction families.
- Equal entry/return values support the observed call-boundary property only.
- All-path R13 preservation is unproven.
- The BIOS target is not independently identified as SYS_CHGSCUIM.
- The two alternative direct BSR candidates still need runtime coverage if naturally reachable.
