# The Story of Thor 2 — Nintendo Switch Remake

Research and future native Nintendo Switch remake of *The Story of Thor 2* / *The Legend of Oasis* for Sega Saturn.

**Status: Stage 06 — candidate offset scales compared.** This is research tooling, **not a playable game**.

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
python tools/stage06_target_window_probe.py '/private/The Story of Thor 2.iso' -o stage06.json
```

The scripts report structural metadata and aggregate counts only; they do not export original payload bytes.

## Verified progress

- **Stage 01:** verified Saturn `MK-81302` ISO9660 structure with 33 files.
- **Stage 02:** identified 12 candidate three-section containers.
- **Stage 03:** validated 21 counted big-endian 16-bit index tables and nine six-byte record chains.
- **Stage 04:** validated 3,730 records across ten containers using the `6 + 8×N` grammar; two containers need separate analysis.
- **Stage 05:** profiled both leading 16-bit fields in 32,862 elements; their meanings are unproven.
- **Stage 06:** compared byte-offset and ×8 offset interpretations for four fields. The ×8 interpretation of element field A has 32,859/32,862 valid 128-byte target windows and yields more unique patterns; raw-byte interpretations fit all windows for element field B and both record-header fields. This is a testable hypothesis, not a decoded format.
- **55 synthetic-only unit tests passed locally**; CI does not need the original disc.

Reports: [Stage 06 (RU)](docs/STAGE06_REPORT_RU.md) · [Stage 05](docs/STAGE05_REPORT_RU.md) · [Stage 04](docs/STAGE04_REPORT_RU.md) · [Roadmap](docs/ROADMAP_RU.md)

**Not done:** pixel format decoder, recovered sprites, levels, combat, native C++/SDL2 game, Switch NRO or full-game playthrough. Distribution of a remake incorporating protected game materials would require permission from the rights holders.
