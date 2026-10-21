# The Story of Thor 2 — Nintendo Switch Remake

Research and future native Nintendo Switch remake of The Story of Thor 2 / The Legend of Oasis for Sega Saturn.

**Status: Stage 35 — the previously unresolved R5=2 wrapper has one incoming BRA tail-call from another routine; the outer routine has an entry in a contiguous 68-pointer code table (slot 39, one-based). Four stored references each to the table base and this entry cell were found. This is static dispatch evidence, not runtime VDP1 decoding.** This repository contains research tools, not a playable game.

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
    python tools/stage23_vdp1_stack_alias_provenance.py "/private/The Story of Thor 2.iso" -o stage23.json
    python tools/stage24_loop_counter_probe.py "/private/The Story of Thor 2.iso" -o stage24.json
    python tools/stage25_r4_provenance_probe.py "/private/The Story of Thor 2.iso" -o stage25.json
    python tools/stage26_helper_r4_nested_pointer.py "/private/The Story of Thor 2.iso" -o stage26.json
    python tools/stage27_helper_zero_clear.py "/private/The Story of Thor 2.iso" -o stage27.json
    python tools/stage28_helper_nonzero_fields.py "/private/The Story of Thor 2.iso" -o stage28.json
    python tools/stage29_sh2_q8_converter.py "/private/The Story of Thor 2.iso" -o stage29.json
    python tools/stage30_field_consumer_audit.py "/private/The Story of Thor 2.iso" -o stage30.json
    python tools/stage31_entry_guard_audit.py "/private/The Story of Thor 2.iso" -o stage31.json
    python tools/stage32_field_consumer_callers.py "/private/The Story of Thor 2.iso" -o stage32.json
    python tools/stage33_r14_origin_audit.py "/private/The Story of Thor 2.iso" -o stage33.json
    python tools/stage34_r14_exit_delay_guards.py "/private/The Story of Thor 2.iso" -o stage34.json
    python tools/stage35_table_tail_link.py "/private/The Story of Thor 2.iso" -o stage35.json

Stages 01–07 and 09–35 report structural metadata and aggregate statistics only. Stage 08 intentionally writes a local candidate PNG under explicit pixel-format/dimension assumptions; do not commit or publish previews.

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
- **Stage 22:** recognizes an 88-byte stack frame after seven saved registers and 18 narrow direct SP stores before the factor loads. Two stores cover the SP+80 flag; none of the strictly recognized stores cover SP+20/SP+32.
- **Stage 23:** finds four pointer-mediated writes through temporary aliases of R15: two to SP+20, one to SP+32, and one to SP+56. Their candidate value sources include byte fields R4+2, R4+3, R4+1 and a separate conditional rewrite masking SP+20 with 0x3F.
- **Stage 24:** verifies one complete loop structure linking R4+1 to a byte counter at SP+56; after each pass it is decremented and checked as signed, with a backward BRA to the loop head and a NOP delay slot. A pure counter model is tested, not a measured game iteration count.
- **Stage 25:** confirms one function prologue saving the entry R4 pointer in R13 and a later BSR passing R13 back through R4 in its delay slot. One branch-free loop prefix leads to an AND 0x3F rewrite of SP+20.
- **Stage 26:** proves the Stage25 helper copies incoming R4 to R14, reads a 32-bit field at memory[R14+160] into R4 before its first conditional branch, tests for null, then restores PR/R12/R13/R14, but not R4, in its matched return.
- **Stage 27:** confirms a guarded fallback arm clearing seven bytes at +31..+37 in the original input structure: five byte stores, followed by a word store at +36 in the delay slot of BRA to the shared epilogue.
- **Stage 28:** validates the nonzero arm writing the same fields from nested data: byte order of +31/+32 reverses when the signed type byte is 3, source values for +35 and +36 are shifted left, and two conversion groups of 2 and 4 JSR @R13 calls are skipped separately when 16-bit fields +88/+90 equal 0x0100.
- **Stage 29:** resolves the PC-relative R13 function pointer for all six conversion sites to a five-instruction signed fixed-point multiplier. It implements `sign16((sign16(R4) * sign16(R5)) >> 8)`, and 0x0100 (256) is identity scale in Q8.8.
- **Stage 30:** found three ordered groups of SH-2 reads of fields +31..+34 relative to R4, one also reading byte +35 and word +36..+37; two groups use arithmetic involving R5 or R6 and one stores resulting words on the stack.
- **Stage 31:** all three candidate consumers have matched function prologues saving 5/7/7 registers and read a 16-bit word at R4+16 before +31..+34. The second reader gates field access on bit0 of R4+7 being clear; the first tests bit2 of R4+6 earlier, and the extended reader has no recognized branch in its initial prefix.
- **Stage 32:** verified two direct BSR callers (one for each of the first two consumers) and eight indirect JSR callers of the full seven-byte reader, all resolved via 32-bit PC-relative address literals. Nine pass R14 as R4 in a call delay slot; the eighth indirect caller sets R5=2 instead.
- **Stage 33:** among nine R14-to-R4 call sites, eight have a local R4-to-R14 save prologue: five have no recognized intervening R14 writes and three have ambiguous lexical restores from possible alternate paths. One direct caller lacks a nearby R14 origin. The exceptional indirect wrapper stores its incoming R4 at SP before JSR and sets R5=2 in the delay slot.
- **Stage 34:** resolves the three lexical R14 restore sites as exit-jump delay slots: one JMP @Rn, two BRA destinations beyond their local call sites. None is an ordinary fall-through update before the call. The exceptional wrapper has no found direct BSR or PC-relative MOV.L pointer references.
- **Stage 35:** proves one static BRA tail-call from an outer routine to the exceptional R5=2 wrapper. The outer routine appears as entry 39 of a 68-element contiguous function-pointer table, referenced via multiple PC-relative address loads. Runtime table selection, actual gameplay reachability and VDP1 output remain unknown.

Stages 10–35 add 412 synthetic-only tests beyond the Stage 09 suite. GitHub CI runs synthetic tests without access to the original disc.

Reports: Stage 35 (RU), Stage 34 (RU), Stage 33 (RU), Stage 32 (RU), Stage 31 (RU), Stage 30 (RU), Stage 29 (RU), Stage 28 (RU), Stage 27 (RU), Stage 26 (RU), Stage 25 (RU), Stage 24 (RU), Stage 23 (RU), Stage 22 (RU), Stage 21 (RU), Stage 20 (RU), Stage 19 (RU), Stage 18 (RU), Stage 17 (RU), Stage 16 (RU), Stage 15 (RU), Stage 14 (RU), Stage 13 (RU), Stage 12 (RU), Stage 11 (RU), Stage 10 (RU), Stage 09 (RU), Stage 08 (RU), Stage 07 (RU), Stage 06 (RU), and the Russian project roadmap are in docs.

**Not done:** confirmed pixel-format decoder, restored sprites, levels, combat, native C++/SDL2 game, Switch NRO, or full-game playthrough. Distribution of a remake incorporating protected game materials requires permission from the rights holders.
