# The Story of Thor 2 — Nintendo Switch Remake

Research and future native Nintendo Switch remake of *The Story of Thor 2* / *The Legend of Oasis* for Sega Saturn.

**Status: Stage 09 — nibble-structure statistics support a 4bpp hypothesis, but no pixel format is confirmed.** This repository contains reverse-engineering tools, **not a playable game**.

The original Saturn ISO is processed privately and locally. Do not publish game BIN/ISO/CUE, proprietary sprites, music, video or other original game assets. Candidate preview PNGs are local research artifacts and must not be committed.

## Repeat the metadata-only investigation

Python 3.11+ and only the standard library:

\`\`\`sh
python -m unittest discover -s tests -v
python -m compileall -q tools
python tools/inspect_saturn_iso.py '/private/The Story of Thor 2.iso' -o stage01.json
python tools/stage02_probe.py '/private/The Story of Thor 2.iso' -o stage02.json
python tools/stage03_index_tables.py '/private/The Story of Thor 2.iso' -o stage03.json
python tools/stage04_record_layout.py '/private/The Story of Thor 2.iso' -o stage04.json
python tools/stage05_field_profile.py '/private/The Story of Thor 2.iso' -o stage05.json
python tools/stage06_target_window_probe.py '/private/The Story of Thor 2.iso' -o stage06.json
python tools/stage07_geometry_probe.py '/private/The Story of Thor 2.iso' -o stage07.json
python tools/stage09_nibble_structure_probe.py '/private/The Story of Thor 2.iso' -o stage09.json
\`\`\`

The Stage01–07 and Stage09 scripts report structural metadata and aggregate statistics only. Stage08 intentionally writes a local candidate PNG under explicit pixel-format/dimension assumptions; do not commit or publish those previews.

Example candidate preview:

\`\`\`sh
python tools/stage08_texture_preview.py '/private/The Story of Thor 2.iso' \\
  --container P0.BIN --element 0 --bpp 4 --width 24 --height 32 \\
  --scale 6 -o /tmp/thor2-stage08-candidate.png
\`\`\`

## Verified progress

- **Stage 01:** verified Saturn \`MK-81302\` ISO9660 structure with 33 files.
- **Stage 02:** identified 12 candidate three-section containers.
- **Stage 03:** validated 21 counted big-endian 16-bit index tables and nine six-byte record chains.
- **Stage 04:** validated 3,730 records across ten containers using the \`6 + 8×N\` grammar; two containers need separate analysis.
- **Stage 05–06:** profiled candidate fields and compared byte offsets with the ×8 address hypothesis.
- **Stage 07:** all 32,832 non-null first-field references become 32-byte-aligned after multiplying by 8; P0–P3 contain candidate lists referencing 14-byte records ending in \`0x7FFF\`.
- **Stage 08:** added a standard-library local PNG previewer for 4/8/16bpp hypotheses. Dimensions and palette remain unknown.
- **Stage 09:** analyzed 13,574 candidate blocks. The median fraction of bytes with identical high/low nibbles is 68.23%, consistent with packed 4bpp or another nibble-structured encoding; not proof of raw 4bpp.
- **85 synthetic-only unit tests passed locally**; CI does not need the original disc.

Reports: [Stage 09 (RU)](docs/STAGE09_REPORT_RU.md) · [Stage 08](docs/STAGE08_REPORT_RU.md) · [Stage 07](docs/STAGE07_REPORT_RU.md) · [Stage 06](docs/STAGE06_REPORT_RU.md) · [Roadmap](docs/ROADMAP_RU.md)

**Not done:** confirmed pixel-format decoder, restored sprites, levels, combat, native C++/SDL2 game, Switch NRO or full-game playthrough. Distribution of a remake incorporating protected game materials would require permission from the rights holders.
