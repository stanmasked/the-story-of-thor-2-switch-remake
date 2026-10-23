# The Story of Thor 2 — Nintendo Switch Remake

Research and future native Nintendo Switch remake of The Story of Thor 2 / The Legend of Oasis for Sega Saturn.

**Status: Stage 62 host sandbox plus Stage 66–90 static VDP1 research — the original-asset-free C++17 gameplay sandbox remains synthetic and is not a playable Nintendo Switch NRO. Stage71–72 verify the static callback registration and signed-status handshake. Stage73 traces the callback's signed-word length formula and special transfer path. Stage74 verifies a static D0EN write of `0x0101`, audits three transfer handlers, and records nine count-increment sites guarded by limits 508 or 460; two other increments follow local zero resets and one additional pattern remains unclassified. Stage75 traces both callback length-field assignments to the same global source word. One source writer has a zero-seeded R10 path; the other copies the current length/count word through R13. Stage76's direct SH-2 CFG walk, anchored at the complete routine prologue, confirms these facts along intraprocedural paths. Stage77 resolves the three direct BSR targets and one nested literal-backed indirect call; the five-function graph preserves R10/R13, including the wrapper's R13 save/restore paths. Stage78 finds two literal-backed indirect JSR call sites to the writer routine and two direct word store candidates in a bounded alias audit, with no additional ADD-immediate alias store candidates. An RTS separates one nearby call site from the submit gate, so physical code proximity does not imply runtime ordering. Stage79 expanded the local ISO audit across direct, predecrement, indexed, and displacement store modes: 24 nearby PC-literal candidates produced the same two direct MOV.W writer candidates, with no new additive aliases or unresolved indexed candidates in the bounded windows. This does not exhaust arbitrary dynamic aliases. Stage80's direct CFG walk visits 707 states in the writer routine: both known source-field stores are reached, and the observed RTS and tail-BRA exits occur after a store. Both literal-backed writer callsites are followed directly by callback ID 64 without an intervening branch. This proves only the analyzed static paths. Stage81 identifies four literal-backed callback ID 64 JSR sites: two follow a writer call, while two copy the source word into the length field in the callback delay slot without an immediately preceding writer call. All four match these known patterns, but table/computed targets and initialization before the two copy reads remain unproven; the global length bound also remains open. Runtime callback invocation, DMA completion and same-frame timing are not claimed. The original ISO and executable remain private; no runtime VDP1 capture is claimed.**

Stage 46 — verified one SH-2 submit gate supplying the Stage45 32-byte VRAM command copier. Stage66 statically cross-checked the descriptor consumer: each 8-byte record contains a 32-bit source address, an unsigned 16-bit VDP1 destination slot scaled by 8, and a signed 16-bit block count used for 32-byte transfers. The count must be positive for finite completion; zero/negative values are not empty transfers in the original do-while loop. The portable parser and tests use synthetic data only. Stage70 additionally finds a status-writer callback registration candidate under ID 64 and a pointer-derived PTMR=2 write; neither static finding proves runtime execution. Actual VDP1 execution and producer/submit same-frame timing remain unproven. This repository contains research tools, not a playable game.

The original Saturn ISO is processed privately and locally. Do not publish game BIN/ISO/CUE, proprietary sprites, music, video, or other original game assets. Candidate preview PNGs and analysis JSON are local research artifacts and must not be committed.

## Repeat the metadata-only investigation

Python 3.11+ and only the standard library:

    python -m unittest discover -s tests -v
    python -m compileall -q tools
    # Stage48 requires private VRAM snapshots; usage and manifest in docs/STAGE48_REPORT_RU.md
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
    python tools/stage36_dispatch_index_audit.py "/private/The Story of Thor 2.iso" -o stage36.json
    python tools/stage37_index_writer_type_guard.py "/private/The Story of Thor 2.iso" -o stage37.json
    python tools/stage38_constant_index_writer.py "/private/The Story of Thor 2.iso" -o stage38.json
    python tools/stage39_writer_function_dispatch.py "/private/The Story of Thor 2.iso" -o stage39.json
    python tools/stage40_pool_clone_audit.py "/private/The Story of Thor 2.iso" -o stage40.json
    python tools/stage41_pool_readers.py "/private/The Story of Thor 2.iso" -o stage41.json
    python tools/stage42_pool_dispatch_trace_contract.py "/private/The Story of Thor 2.iso" -o stage42.json
    python tools/stage43_private_watchpoints.py "/private/The Story of Thor 2.iso" --manifest-private /private/thor43.private-watchpoints.json -o /private/stage43_redacted.json
    python tools/stage44_vdp1_vram_audit.py "/private/The Story of Thor 2.iso" -o /private/stage44_static_summary.json
    python tools/stage45_vdp1_command_copy.py "/private/The Story of Thor 2.iso" -o /private/stage45_redacted.json
    python tools/stage46_vdp1_submit_gate.py "/private/The Story of Thor 2.iso" -o /private/stage46_redacted.json
    python tools/stage47_vdp1_producer_reconciliation.py "/private/The Story of Thor 2.iso" -o /private/stage47_redacted.json
    python tools/stage70_vdp1_status_trigger_audit.py "/private/The Story of Thor 2.iso" -o /private/stage70_redacted.json
    python tools/stage71_callback_dispatch_chain.py "/private/The Story of Thor 2.iso" -o /private/stage71_redacted.json
    python tools/stage72_status_producer_order.py "/private/The Story of Thor 2.iso" -o /private/stage72_redacted.json
    python tools/stage73_memory_path_audit.py "/private/The Story of Thor 2.iso" -o /private/stage73_redacted.json
    python tools/stage74_scu_dma_handler_audit.py "/private/The Story of Thor 2.iso" -o /private/stage74_redacted.json
    python tools/stage75_indirect_services_count_provenance.py "/private/The Story of Thor 2.iso" -o /private/stage75_redacted.json
    python tools/stage76_length_field_feedback_cfg.py "/private/The Story of Thor 2.iso" -o /private/stage76_redacted.json
    python tools/stage77_callee_register_preservation.py "/private/The Story of Thor 2.iso" -o /private/stage77_redacted.json
    python tools/stage78_writer_entry_and_alias_audit.py "/private/The Story of Thor 2.iso" -o /private/stage78_redacted.json
    python tools/stage79_expanded_store_alias_audit.py "/private/The Story of Thor 2.iso" -o /private/stage79_redacted.json
    python tools/stage80_source_field_init_order_cfg.py "/private/The Story of Thor 2.iso" -o /private/stage80_redacted.json
    python tools/stage81_callback64_callsite_census.py "/private/The Story of Thor 2.iso" -o /private/stage81_redacted.json
    python tools/stage82_low_module_callback_audit.py "/private/The Story of Thor 2.iso" -o /private/stage82_redacted.json
    python tools/stage83_unpaired_callback_context_audit.py "/private/The Story of Thor 2.iso" -o /private/stage83_redacted.json
    python tools/stage84_low_cfg_order_and_slot_alignment.py "/private/The Story of Thor 2.iso" -o /private/stage84_redacted.json
    python tools/stage85_disc_slot_writer_census.py "/private/The Story of Thor 2.iso" -o /private/stage85_redacted.json
    python tools/stage86_set_module_signature_audit.py "/private/The Story of Thor 2.iso" -o /private/stage86_redacted.json
    python tools/stage87_set_filename_loader_context.py "/private/The Story of Thor 2.iso" -o /private/stage87_redacted.json
    python tools/stage88_filename_helper_callchain.py "/private/The Story of Thor 2.iso" -o /private/stage88_redacted.json
    python tools/stage89_leaf_entry_shape_audit.py "/private/The Story of Thor 2.iso" -o /private/stage89_redacted.json
    python tools/stage90_leaf_entry_direct_cfg.py "/private/The Story of Thor 2.iso" -o /private/stage90_redacted.json

Analysis tools report structural metadata and aggregate statistics only unless their documentation says otherwise. Stage 70–72 deliberately redact status/global addresses and executable offsets. Stage 08 intentionally writes a local candidate PNG under explicit pixel-format/dimension assumptions; do not commit or publish previews.

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
- **Stage 35:** proves one static BRA tail-call from an outer routine to the exceptional R5=2 wrapper. The outer routine appears as entry 39 of a 68-element contiguous function-pointer table, referenced via multiple PC-relative address loads.
- **Stage 36:** identifies two indexed indirect JMPs into the same table. Both use a signed 16-bit word at R14+126 multiplied by four. The table-base variant selects slot 39 with index 38; the variant anchored at slot 39 selects it with index 0. Valid index ranges are mathematical constraints, not established runtime guards.
- **Stage 37:** isolates earlier tests of a **separate byte at R14+30**: two zero tests and one sequence comparing it with 1..6. Those tests do not bound the signed table index at R14+126. A conservative opcode census finds 460 candidate MOV.W stores through R14+126 and 106 through R4+126 in 0TH2.BIN.
- **Stage 38:** narrows the census to 193/39 stores immediately preceded by a constant assignment in the corresponding source register and verifies one longer seven-instruction sequence loading 38 into R3 before storing word [R14+126], along with updating byte [R14+7].
- **Stage 39:** links the constant-38 writer to one signed indexed JSR using R13+126, via slot 78 of a contiguous 116-code-pointer run (index 77). The writer preserves its input R4 as R13 but subsequently captures an R0 helper result in R14 using a BF/S delay slot.
- **Stage 40:** resolves the returned-R0 helper to a slot selector scanning up to 43 records of 276 bytes each. It checks each record's first word for zero, returns null if no slot remains, and returns the selected slot pointer otherwise. A second helper copies 69 long words (276 bytes) from saved input R13 to newly returned R14; afterwards the writer changes R14+7 and stores index 38 in R14+126.
- **Stage 41:** finds 57 PC-relative loads of the pool base and verifies four independent R4-relative readers of a first-word record marker and word field +126, advancing by the same 276-byte stride (11 comparisons against 4, 21 and 36). A second static function scans 43 slots for a free pointer without marking it.
- **Stage 42:** confirms the two 68-entry dispatcher entry prologues copy R4 into R14 before indexed lookup. No direct BSR/BRA/conditional/PC-literal reference to those exact entry points has established that the caller passes the Stage40 cloned pool object. Introduces a symbolic trace validator; no real emulator observations exist.
- **Stage 43:** derives seven PRIVATE debugger PC watchpoint roles directly from the original ISO (allocation return, copy entry, index store, both dispatch entries and both JMPs), writes a mode-0600 local manifest, and checks supplied physical pointer/register snapshots. No real emulator trace was obtained.
- **Stage 44:** finds six PC-relative loads of the VDP1 VRAM base and three of the VDP1 register base in the original executable. Adds a private offline VRAM command parser and before/after comparison; no live capture.
- **Stage 45:** verifies one concrete SH-2 VRAM command-copy procedure, sourced by a PC-relative VDP1-base load: an unsigned 16-bit index ×8 addresses VRAM, eight 32-bit writes copy exactly 32 bytes, and two signed BF loop targets advance command pointers.
- **Stage 46:** resolves the direct caller to a gated command submission routine: negative signed status flag, cleared before zero-count test; an 8-byte descriptor buffer from a PC-relative RAM literal in R4 and 16-bit record count in R5 feed Stage45's JSR; the pointer is recorded and count cleared after copying. Confirms one complete gate, two source-buffer pointer loads, 16 status pointer loads and seven count pointer loads. No runtime safety bounds or handler-39 link yet.

- **Stage 47:** cross-checks the prior Stage16 8-byte descriptor writer against the Stage46 gate and Stage15 address constants, audits the capacity-branch destination, and counts bounded direct status/count stores. All tests are synthetic; original ISO cross-stage matches and execution are not yet attested.

- **Stage 48:** adds a local-only VDP1 copy-witness validator: bounded manifest with status, pre/post pending count, destination indices and per-descriptor command counts; optional packed private source blocks; expected VRAM replay and byte-difference checks; no original assets or runtime attestation.

- **Stage 49:** adds a private JSONL SH-2 instruction-event witness comparing PC roles, Stage45 per-command eight 32-bit VDP1 stores, R5 count, negative submission flag, and optional exact source words. Not an authenticated Saturn trace. See docs/STAGE49_REPORT_RU.md.

- **Stage 50:** adds a private snapshot preflight that checks 12 Stage45/46 instruction-role signatures in a full 1-MiB SH-2 high-work-RAM dump and detects relocated/duplicated code images. Matching bytes do not establish runtime execution. See docs/STAGE50_REPORT_RU.md.

- **Stage 51:** validates Sega Saturn IP.BIN 1st-read transfer address, ISO9660 root file ordering and High Work RAM range against the exact original SHA-256. Also carries corrected Stage48/49 descriptor budgeting. See docs/STAGE51_REPORT_RU.md.

- **Stage 52:** adds a privacy-preserving joint Saturn capture-bundle audit using strict per-artifact SHA-256 and operator-declared emulator metadata. Combines 1-MiB High Work RAM, two 512-KiB VDP1 VRAM dumps, descriptor metadata, SH-2 JSONL trace and optional private source commands. See docs/STAGE52_REPORT_RU.md.

- **Stage 53:** generates a private original-specific Mednafen capture plan with 12 SH-2 PC breakpoints, 4 global status/buffer watch addresses, and manual 1-MiB RAM and two 512-KiB VDP1 dump recipes based on official debugger shortcuts; no runtime evidence is claimed. See docs/STAGE53_REPORT_RU.md.

- **Stage 54:** prepares a provisional adjacent private MODE1/2048 CUE from the pinned original region-E ISO, validates the Mednafen BIOS file hash when available, checks installed emulator binary presence without executing it, and rejects unsafe CUE paths. See docs/STAGE54_REPORT_RU.md.

- **Stage 55:** adds a ROM-free tested readiness checker for the official Yabause libretro HLE BIOS path. Original E-region Saturn ISO may be attempted directly in RetroArch without a proprietary Saturn BIOS or a provisional CUE; no real execution captured. See docs/STAGE55_REPORT_RU.md.

- **Stage 56:** adds an independent limited SH-2 opcode dataflow decoder for the eight VDP1 longword loads and stores. Reconstructs source/destination mapping from instruction bits, checks Stage49 PC roles and R2/R5 nested counters, and allows bounded private synthetic command reconstruction. See docs/STAGE56_REPORT_RU.md.

- **Stage 57:** decodes VDP1 sprite mode, width, height and source span directly from command metadata, with raw private 4/8/16bpp texel unpacking and no public pixel output. Addresses Stage10's size/depth ambiguity for future real VRAM command captures, not yet for ISO resources. See docs/STAGE57_REPORT_RU.md.

- **Stage 58:** interprets VDP1 SPD/ECD pixel policy, two end codes per source scanline, 16-color LUT records and raw color-bank codes. Color-bank codes require external VDP2 CRAM before RGB rendering; no original pixels exported. Also propagates corrected Stage57 END-bit sentinel handling. See docs/STAGE58_REPORT_RU.md.

- **Stage 59:** joins Stage58's raw VDP1 sprite pixel categories to mode-dependent VDP2 CRAM through documented RAMCTL, SPCTL and SPCAOS fields. Includes hardware-aligned RGB555/RGB888 decoding, 16-bit sprite-type palette bit widths and conservative unresolved cases, with aggregate-only private analysis. See docs/STAGE59_REPORT_RU.md.

- **Stage 60:** decodes priority/ratio selectors from documented 16-bit sprite types, resolves eight priority and eight color-ratio registers, identifies normal shadow reserved codes and conditional MSB shadow flags without claiming rasterization or authenticated execution. See docs/STAGE60_REPORT_RU.md.

- **Stage 61:** adds exact 256-KiB VDP1 draw-framebuffer inspection for five TVMR modes, safe write-register mirror contract and ROM-free 8/16-bit pixel classification. A new C++17 `native/vdp1_framebuffer.hpp` with host tests compiles separately in GitHub Actions, the first native code toward the Switch graphics layer. See docs/STAGE61_REPORT_RU.md.

- **Stage 62:** adds `native/gameplay.hpp`, `native/software_renderer.hpp` and a runnable host CLI `native/demo/sandbox_cli.cpp`; WASD, collision, collection, goal and text/PPM output with strictly synthetic art. A new GitHub Actions job compiles/tests gameplay and publishes a Linux demo executable plus PPM screenshot. See docs/STAGE62_REPORT_RU.md.

- **Stage 66:** confirms the 8-byte VDP1 transfer-descriptor contract against the 32-byte copier at the static-analysis level. Adds `native/vdp1_transfer_descriptor.hpp` and synthetic tests for big-endian fields, VDP1 destination mapping, signed block counts, overflow and VRAM bounds. The report explicitly separates static findings from unproven runtime behavior. See docs/STAGE66_REPORT_RU.md.

- **Stage 67:** traces the producer inputs back to the object and metadata record: source address `base + unsigned_index × 8`, destination slot from an object field, and block count `((byte2 & 0x3F) * byte3) >> 3` (maximum 2008). Adds ROM-free helper functions and synthetic tests. The source structure’s semantic names, runtime execution, and the invariant excluding zero counts remain unconfirmed. See docs/STAGE67_REPORT_RU.md.

- **Stage 68:** identifies two independent output streams in one object loop: opaque 32-byte command-like records and conditional 8-byte transfer descriptors, each with its own pointer/count pair. Adds `native/vdp1_stream_layout.hpp` and synthetic tests for independent strides, counters and bounds. Command field meanings and submit timing remain unverified. See docs/STAGE68_REPORT_RU.md.

- **Stage 69:** traces stream initialization and the command terminator. The 16-bit `0x8000` end marker occupies 4 bytes after 32-byte command records and does not increment the logical command count. Adds `reserve_raw_bytes()` and a synthetic test proving that pointer advancement and command count are independent. See docs/STAGE69_REPORT_RU.md.

- **Stage 70:** models the signed-status submit-gate condition: a negative status is cleared before the descriptor count is checked, including when the count is zero. The audit finds an explicit -1 store to the same status byte, a callback registration candidate under ID 64, and a pointer-derived PTMR=2 write (automatic drawing at frame start). See docs/STAGE70_REPORT_RU.md.
- **Stage 71:** statically verifies that the negative-status writer is registered under ID 64, that the matching six-byte thunk is present in a 256-entry wrapper table, and that the shared invoker reads the same callback slot and performs a guarded indirect call. See docs/STAGE71_REPORT_RU.md.
- **Stage 72:** verifies the callback's signed-status guard: a negative status skips the producer block; a nonnegative status reaches a helper call supplied with the VDP1 VRAM base and source buffer, then writes -1 to the same status byte consumed by the submit gate. See docs/STAGE72_REPORT_RU.md.
- **Stage 73:** traces the helper's range dispatch. The callback computes a byte length from a signed word as `value × 32 + 2`; this field is adjacent to, but distinct from, the submit gate's pending count. The actual arguments select a stateful video-memory path rather than the generic overlap-safe bytewise memmove. See docs/STAGE73_REPORT_RU.md.
- **Stage 74:** verifies the static dispatch to three in-image handler variants and a write of `0x0101` to SCU D0EN (enable + GO/start). Nine recognized count-increment paths have explicit limits of 508 or 460, and two increments follow a local zero reset. One additional increment-like sequence is separated from the reset by an RTS and remains unclassified. Two other count assignments also remain unresolved, so the global upper bound is not proven. The `+2` length is reconciled with the 16-bit `0x8000` END word while the buffer pointer reserves four bytes. Runtime callback invocation, DMA completion, effective D0R/D0W/D0C addresses and frame synchronization remain unproven. See docs/STAGE74_REPORT_RU.md.

- **Stage 78:** audits static entry pointers to the length-source writer routine. Two literal-backed indirect JSR sites are recognized, with no direct BSR/BRA to the entry; an RTS separates one nearby writer call site from the submit gate, preventing an unwarranted same-routine ordering claim. A bounded PC-literal ADD-immediate alias scan finds only the two previously studied word stores and no new additive alias store candidates. This is not an exhaustive writer census or runtime timing proof. See docs/STAGE78_REPORT_RU.md.

- **Stage 79:** expanded the private-ISO search to direct, predecrement, indexed-R0 and displacement store encodings, plus bounded ADD-immediate and register-copy aliases. Of 24 nearby PC-relative literal-load candidates, only the same two `MOV.W Rm,@Rn` stores matched the target field; no additional additive aliases or unresolved indexed stores were found in the bounded windows. This is not an exhaustive alias proof. See docs/STAGE79_REPORT_RU.md.

- **Stage 80:** the direct CFG walk of the length-source writer visits 707 states, reaches both known store sites, and finds one RTS exit plus one tail-BRA exit; both exit states follow a recognized source-field store. Both literal-backed writer callsites are immediately followed by callback ID 64 via straight-line code. This is not proof for all runtime callback paths, dynamic entries, DMA completion or same-frame timing. See docs/STAGE80_REPORT_RU.md.

- **Stage 81:** four literal-backed callback ID 64 JSR sites are classified: two follow the source-field writer; two copy the source word into the length/count field in the callback delay slot, without an immediately preceding writer. Stage82 expanded the census to `TH2.LOW`: 3 more writer JSRs, 8 callback JSRs and 3 additional writer→callback pairs. Across both files there are 5 pairs, 3 callback calls that write the length field in a delay slot, and 4 unpaired NOP-delay callback calls. `TH2.LOW` contains 38 raw big-endian occurrences of one service-slot address but no direct PC-relative literal load to that slot; this does not establish pointer registration. Source initialization before the two copy reads and table/computed callback targets remain unproven. See docs/STAGE81_REPORT_RU.md.

- **Stage 82:** extended callback/writer census from `0TH2.BIN` to `TH2.LOW`. The two files contain five literal-backed writer→callback pairs, three callback calls with length-field stores in the delay slot, and four other unpaired NOP-delay callback calls. `TH2.LOW` has 38 raw big-endian occurrences of one service-slot address but no direct PC-relative load to it; this is not proof of slot initialization. See docs/STAGE82_REPORT_RU.md.

- **Stage 83:** maps seven callback ID 64 sites without an immediate writer predecessor to candidate function intervals. Three are delay-slot length copies in intervals with no direct writer call; four are NOP-delay calls in `TH2.LOW`, one sharing an interval with a later writer callsite and three with no writer. This is a prologue-based context heuristic, not a full CFG or runtime proof. See docs/STAGE83_REPORT_RU.md.

- **Stage 84:** after fixing the any-path/all-path flag semantics, the private-ISO CFG was rerun: 722 states were visited and callback was reached only with `writer_seen=false`. The writer was reachable after the callback and on a separate path without the callback; no direct writer→callback path appeared in this bounded CFG. External initialization, alternate entries and computed dispatch remain unproven. All 38 raw service-slot-A byte matches are odd-offset, unaligned and absent from PC-relative literal pools, so they are not evidence of a pointer table. Stage85 scans 30 of 33 root files (three larger files are skipped): direct slot references appear only in `0TH2.BIN` and `SET07.BIN`, with 11/8 indirect-dispatch candidates for slots A/B and no bounded direct store candidates. `SET07.BIN`'s execution role is unconfirmed. See docs/STAGE85_REPORT_RU.md.

- **Stage 85:** scanned 30 of 33 ISO root files under a 5 MiB cap. Direct slot A/B references occur only in `0TH2.BIN` and `SET07.BIN`; 11/8 indirect-dispatch candidates were recognized, with no bounded direct store candidates. `SET07.BIN`'s execution role is not yet confirmed, and three larger files were skipped. See docs/STAGE85_REPORT_RU.md.

- **Stage 86:** the three large CPK files have `FILM` multimedia headers and were only prefix-scanned. All SET files contain many SH-2-like patterns; `SET07.BIN` is 96 KiB with 7/4 slot A/B literal references and 6/4 indirect-dispatch candidates. `TH2.LOW` contains the SET07 filename, but the file's load address and executable/overlay role remain unproven. See docs/STAGE86_REPORT_RU.md.

- **Stage 87:** `0TH2.BIN` contains one contiguous `SET00.BIN`–`SET06.BIN` table (10-byte stride) and one PC-relative reference to its first name. A nearby indirect call preserves the filename argument register and resolves to a same-executable function candidate, but its file-loader semantics are unconfirmed. `TH2.LOW` contains `SET07.BIN` without direct references under two candidate load bases. No SET file has a literal-backed direct JSR to the resolved writer or callback ID64 target. See docs/STAGE87_REPORT_RU.md.

- **Stage 88:** the candidate helper receiving the SET00 filename pointer has 7 literal-resolved JSR sites to 4 unique same-executable targets, all with frame-prologue signatures. Its first nested callee has 2 resolved JSR sites; one target lacks a prologue but has a short direct `RTS` path, so Stage89 treats it as a leaf-function candidate rather than assuming it is internal. The next layer has 5 resolved JSR sites to 5 targets, three with frame prologues; the other two have early-return patterns (one straight-line, one conditional) and may be separate leaf functions. R1 is not explicitly overwritten before the first JSR in each candidate interval, but this is not proof of file I/O semantics or complete interprocedural data flow. See docs/STAGE88_REPORT_RU.md.

- **Stage 89:** reclassified no-prologue call targets using early-`RTS` shape. The first nested helper has one short straight-line leaf-return target; the next layer has another straight-line leaf-return target and one conditional early-return target. Prologue-bounded interval membership alone does not prove that these targets belong to the same function. File-I/O semantics remain unconfirmed. See docs/STAGE89_REPORT_RU.md.

- **Stage 90:** direct CFG analysis of three no-prologue targets, including SH-2 delay slots. Two short targets reach one RTS each with no cycle (9 and 4 reachable instruction addresses); the conditional target reaches two RTS sites over 31 addresses but has a cycle, so all-path termination is not proven. Indirect jumps and out-of-bound exits are reported rather than guessed. See docs/STAGE90_REPORT_RU.md.

Stages 10–66 use synthetic-only GitHub CI; original assets stay private. Original Saturn material is never uploaded.

Reports: Stage 90 (RU), Stage 89 (RU), Stage 88 (RU), Stage 87 (RU), Stage 86 (RU), Stage 85 (RU), Stage 84 (RU), Stage 83 (RU), Stage 82 (RU), Stage 81 (RU), Stage 80 (RU), Stage 79 (RU), Stage 78 (RU), Stage 77 (RU), Stage 76 (RU), Stage 75 (RU), Stage 74 (RU), Stage 73 (RU), Stage 72 (RU), Stage 71 (RU), Stage 70 (RU), Stage 69 (RU), Stage 68 (RU), Stage 67 (RU), Stage 66 (RU), Stage 62 (RU), Stage 61 (RU), Stage 60 (RU), Stage 59 (RU), Stage 58 (RU), Stage 57 (RU), Stage 56 (RU), Stage 55 (RU), Stage 54 (RU), Stage 53 (RU), Stage 52 (RU), Stage 51 (RU), Stage 50 (RU), Stage 49 (RU), Stage 48 (RU), Stage 47 (RU), Stage 46 (RU), Stage 45 (RU), Stage 44 (RU), Stage 43 (RU), Stage 42 (RU), Stage 41 (RU), Stage 40 (RU), Stage 39 (RU), Stage 38 (RU), Stage 37 (RU), Stage 36 (RU), Stage 35 (RU), Stage 34 (RU), Stage 33 (RU), Stage 32 (RU), Stage 31 (RU), Stage 30 (RU), Stage 29 (RU), Stage 28 (RU), Stage 27 (RU), Stage 26 (RU), Stage 25 (RU), Stage 24 (RU), Stage 23 (RU), Stage 22 (RU), Stage 21 (RU), Stage 20 (RU), Stage 19 (RU), Stage 18 (RU), Stage 17 (RU), Stage 16 (RU), Stage 15 (RU), Stage 14 (RU), Stage 13 (RU), Stage 12 (RU), Stage 11 (RU), Stage 10 (RU), Stage 09 (RU), Stage 08 (RU), Stage 07 (RU), Stage 06 (RU), and the Russian project roadmap are in docs.

**Not done:** authenticated original sprite/level reconstruction, story/boss/combat logic, native SDL/libnx frontend, Switch NRO, or full-game playthrough. Stage62's runnable C++ host sandbox uses exclusively original synthetic placeholders and is NOT the Saturn game's gameplay. Distribution of a remake incorporating protected game materials requires permission from the rights holders.
