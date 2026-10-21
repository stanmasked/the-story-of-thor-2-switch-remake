# The Story of Thor 2 — Nintendo Switch Remake

Research and future native Nintendo Switch remake of *The Story of Thor 2* / *The Legend of Oasis* for Sega Saturn.

**Status: Stage 08 — exploratory local texture previewer added.** This repository contains reverse-engineering tools, **not a playable game**.

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
\`\`\`

The Stage01–07 scripts report structural metadata and aggregate statistics only. Stage08 is intentionally different: it writes a local candidate PNG under explicit pixel-format/dimension assumptions; do not commit or publish those previews.

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
- **Stage 05:** profiled both leading 16-bit fields in 32,862 elements; semantics were not proven.
- **Stage 06:** compared raw byte offsets and ×8 interpretation for four fields; ×8 is promising for the first element field.
- **Stage 07:** all 32,832 non-null first-field references across strict containers become 32-byte-aligned and in-bounds after multiplying by 8. In P0–P3, 55 candidate table prefixes contain 498 links to 14-byte records ending in \`0x7FFF\`.
- **Stage 08:** added a standard-library PNG previewer for 4/8/16bpp hypotheses. A 384-byte candidate block looks more coherent under 4bpp 24×32 than under a 16bpp guess, but dimensions, palette and format are not confirmed.
- **76 synthetic-only unit tests passed locally**; CI does not need the original disc.

Reports: [Stage 08 (RU)](docs/STAGE08_REPORT_RU.md) · [Stage 07](docs/STAGE07_REPORT_RU.md) · [Stage 06](docs/STAGE06_REPORT_RU.md) · [Stage 05](docs/STAGE05_REPORT_RU.md) · [Roadmap](docs/ROADMAP_RU.md)

**Not done:** confirmed pixel-format decoder, restored sprites, levels, combat, native C++/SDL2 game, Switch NRO or full-game playthrough. Distribution of a remake incorporating protected game materials would require permission from the rights holders.
