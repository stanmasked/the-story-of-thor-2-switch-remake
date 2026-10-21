# The Story of Thor 2 — Nintendo Switch Remake

Research and future native Nintendo Switch remake of *The Story of Thor 2* / *The Legend of Oasis* for Sega Saturn.

**Status: Stage 05 — candidate field and section relationships profiled.** The project is **not yet a playable game**.

The original Saturn ISO is processed privately and locally. Do not publish game BIN/ISO/CUE, proprietary sprites, music, video or other original game assets.

## Repeat the metadata-only investigation

Python 3.11+ and only the standard library:

```sh
python -m unittest discover -s tests -v
python tools/inspect_saturn_iso.py '/private/The Story of Thor 2.iso' -o stage01.json
python tools/stage02_probe.py '/private/The Story of Thor 2.iso' -o stage02.json
python tools/stage03_index_tables.py '/private/The Story of Thor 2.iso' -o stage03.json
python tools/stage04_record_layout.py '/private/The Story of Thor 2.iso' -o stage04.json
python tools/stage05_field_profile.py '/private/The Story of Thor 2.iso' -o stage05.json
```

The scripts report structural metadata and aggregate counts only; they do not export the original payload bytes.

## Verified progress

- **Stage 01:** verified Saturn `MK-81302` ISO9660 structure with 33 files.
- **Stage 02:** identified 12 candidate three-section containers.
- **Stage 03:** validated 21 counted big-endian 16-bit index tables and nine six-byte record chains.
- **Stage 04:** validated 3,730 records across ten containers using the `6 + 8×N` grammar; two containers need separate analysis.
- **Stage 05:** profiled 32,862 eight-byte elements in the ten strict containers. A 16-bit field is in range of the third section for all elements and aligned to 8 bytes for 99.0354%; this is a **candidate reference**, not a proven pointer. The candidate field did not directly match the words of the six-byte records.
- **43 synthetic-only unit tests passed locally**; CI never needs the original disc.

Reports: [Stage 05 (RU)](docs/STAGE05_REPORT_RU.md) · [Stage 04](docs/STAGE04_REPORT_RU.md) · [Stage 03](docs/STAGE03_REPORT_RU.md) · [Roadmap](docs/ROADMAP_RU.md)

**Not done:** graphics decoder, recovered animation semantics, levels, combat, native C++/SDL2 game, Switch NRO or full-game playthrough. Distribution of a remake incorporating protected game materials would require permission from the rights holders.
