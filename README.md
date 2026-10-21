# The Story of Thor 2 — Nintendo Switch Remake

Research and future native Nintendo Switch remake of The Story of Thor 2 / The Legend of Oasis for Sega Saturn.

**Status: Stage 22 — seven saved registers and an 88-byte local frame precede the writer; two directly recognizable stores target SP+80, while no direct stores to SP+20/SP+32 match our narrow patterns. Indirect writes and caller provenance remain open.** This repository contains research tools, not a playable game.

The original Saturn ISO is processed privately and locally. Do not publish game BIN/ISO/CUE, proprietary sprites, music, video, or other original game assets. Candidate preview PNGs and analysis JSON are local research artifacts and must not be committed.

## Repeat the metadata-only investigation

Python 3.11+ and only the standard library:

    python -m unittest discover -s tests -v
    python -m compileall -q tools
    python tools/inspect_saturn_iso.py "/private/The Story of Thor 2.iso" -o stage01.json
    python tools/stage02_probe.py "/private/The Story of Thor 2.iso" -o stage02.json
    python tools/stage03_index_tables.py "/private/The Story of Thor 2.iso" -o stage03.json
    python tools/stage04_record_layout.py "/private/The Story of Thor 2.iso" -o stage04.json
    python tools/stage05_field_profile.py "/private/The Story of Thor 2.iso" -o stage05.json
    python tools/stage06_target_window_probe.py "/private/The Story of Thor 2.iso" -o stage06.json
    python tools/stage07_geometry_probe.py "/private/The Story of Thor 2.iso" -o stage07.json
    python tools/stage08_texture_preview.py "/private/The Story of Thor 2.iso" --container P0.BIN --element 0 --bpp 4 --width 24 --height 32 --scale 6 -o /tmp/thor2-stage08-candidate.png
    python tools/stage09_nibble_structure_probe.py "/private/The Story of Thor 2.iso" -o stage09.json
    python tools/stage10_dimension_palette_probe.py "/private/The Story of Thor 2.iso" -o stage10.json
    python tools/stage11_exception_container_probe.py "/private/The Story of Thor 2.iso" -o stage11.json
    python tools/stage12_hardware_reference_probe.py "/private/The Story of Thor 2.iso" -o stage12.json
    python tools/stage13_sh2_literal_reference_probe.py "/private/The Story of Thor 2.iso" -o stage13.json
    python tools/stage14_vdp1_record_copy_probe.py "/private/The Story of Thor 2.iso" -o stage14.json
    python tools/stage15_vdp1_callsite_probe.py "/private/The Story of Thor 2.iso" -o stage15.json
    python tools/stage16_vdp1_descriptor_writer_probe.py "/private/The Story of Thor 2.iso" -o stage16.json
    python tools/stage17_writer_callsite_audit.py "/private/The Story of Thor 2.iso" -o stage17.json
    python tools/stage18_writer_guard_flow.py "/private/The Story of Thor 2.iso" -o stage18.json
    python tools/stage19_writer_argument_flow.py "/private/The Story of Thor 2.iso" -o stage19.json
    python tools/stage20_vdp1_product_flow.py "/private/The Story of Thor 2.iso" -o stage20.json
    python tools/stage21_vdp1_stack_sources.py "/private/The Story of Thor 2.iso" -o stage21.json
    python tools/stage22_vdp1_stack_store_audit.py "/private/The Story of Thor 2.iso" -o stage22.json

Stages 01–07 and 09–22 report structural metadata and aggregate statistics only. Stage 08 intentionally writes a local candidate PNG under explicit pixel-format/dimension assumptions; do not commit or publish previews.

## Verified progress

- **Stage 01:** verified Saturn MK-81302 ISO9660 structure with 33 files.
- **Stage 02:** identified 12 candidate three-section containers.
- **Stage 03:** validated 21 counted big-endian 16-bit index tables and nine six-byte record chains.
- **Stage 04:** validated 3,730 records across ten containers using the 6 + 8×N grammar; MONS.BIN and P4.BIN need separate handling.
- **Stage 05–06:** profiled candidate fields and compared byte offsets with the ×8 address hypothesis.
- **Stage 07:** found strong 32-byte texture-address alignment and candidate lists pointing to 14-byte records ending in 0x7FFF; record semantics remain unproven.
- **Stage 08:** added a local PNG previewer for 4/8/16bpp assumptions. Candidate dimensions and palette remain unknown.
- **Stage 09:** analyzed 13,574 candidate blocks; the median fraction of bytes with identical high/low nibbles is 68.23%, consistent with packed 4bpp or another nibble-structured encoding, not proof of raw 4bpp.
- **Stage 10:** confirmed that block lengths admit many dimension/format combinations and a broad RGB555-like scan produces too many palette candidates.
- **Stage 11:** characterized MONS.BIN and P4.BIN separately. Both have counted index tables, but their record headers mostly fail the Stage 04 counter rule.
- **Stage 12:** found exact Saturn VDP1/VDP2 address literals in 0TH2.BIN and some other files; literal presence alone does not prove executable code.
- **Stage 13:** found 46 candidate SH-2 MOV.L PC-relative references to known graphics-hardware constants, using 38 unique literal slots; code/data boundaries remain unverified.
- **Stage 14:** identified one exact SH-2 signature that copies eight longwords (32 bytes) per iteration to VDP1 VRAM. Two additional instruction sequences independently compute VDP1_BASE + index*8.
- **Stage 15:** resolved a PC-relative function-pointer literal to an indirect JSR call site; inferred an 8-byte descriptor (4-byte source address, 2-byte destination index, 2-byte per-source record count). The caller passes the staging buffer in R4 and a global total-copy budget in R5, guarded against zero and cleared after the call.
- **Stage 16:** identified a candidate descriptor writer with a 512-entry capacity guard, stores at descriptor offsets 0/4/6, one global-counter increment per descriptor, and an 8-byte pointer advance. The per-source count is input >> 3, so callers must be traced to validate how this agrees with the uploader's per-copy budget.
- **Stage 17:** found no direct BSR or PC-relative absolute writer-address literals targeting the capacity guard. That does not imply the writer is unused.
- **Stage 18:** verified a capacity BT branch and an earlier BF/S branch converging just after the 8-byte descriptor commit, demonstrating a conditionally executed writer block rather than a proven standalone routine entry.
- **Stage 19:** validated CMP/EQ #1,R0, BF/S with EXTU.W R5,R4 in its delay slot and three SHLR R2 before the count store. This derives the local count formula (R5 & 0xFFFF) >> 3. Runtime R5 values and the global copy-budget accounting remain unresolved.
- **Stage 20:** resolved the preceding EXTU.B R5,R5; EXTU.B R3,R3; MULU.W R3,R5; STS MACL,R5 chain. The per-source count follows (unsigned_byte_factor_A * unsigned_byte_factor_B) >> 3, gated by a stack byte at SP+80 equal to 1 and the capacity guard.
- **Stage 21:** located both unsigned-byte factor loads at SP+20 and SP+32, and the writer-enable flag at SP+80. The original provenance and runtime contents of these stack fields remain unknown.
- **Stage 22:** recognizes an 88-byte stack frame after seven saved registers and 18 narrow direct SP stores before the factor loads. Two stores cover the SP+80 flag; none of the strictly recognized stores cover SP+20/SP+32. This does not rule out indirect initialization.

Stages 10–22 add 142 synthetic-only tests beyond the Stage 09 suite. GitHub CI runs synthetic tests without access to the original disc.

Reports: Stage 22 (RU), Stage 21 (RU), Stage 20 (RU), Stage 19 (RU), Stage 18 (RU), Stage 17 (RU), Stage 16 (RU), Stage 15 (RU), Stage 14 (RU), Stage 13 (RU), Stage 12 (RU), Stage 11 (RU), Stage 10 (RU), Stage 09 (RU), Stage 08 (RU), Stage 07 (RU), Stage 06 (RU), and the Russian project roadmap are in docs.

**Not done:** confirmed pixel-format decoder, restored sprites, levels, combat, native C++/SDL2 game, Switch NRO, or full-game playthrough. Distribution of a remake incorporating protected game materials requires permission from the rights holders.
