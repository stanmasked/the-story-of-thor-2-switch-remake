# The Story of Thor 2 — Nintendo Switch Remake

Research and future native Nintendo Switch remake of *The Story of Thor 2* / *The Legend of Oasis* for Sega Saturn.

**Status: Stage 04 — indexed record grammar verified.** The project is **not yet a playable game**.

The original Saturn ISO is processed **privately and locally**. Do not publish game BIN/ISO/CUE, proprietary sprites, music, video or other original game assets.

## Repeat the metadata-only investigation

Python 3.11+ and only the standard library:

```sh
python -m unittest discover -s tests -v
python tools/inspect_saturn_iso.py '/private/The Story of Thor 2.iso' -o stage01.json
python tools/stage02_probe.py '/private/The Story of Thor 2.iso' -o stage02.json
python tools/stage03_index_tables.py '/private/The Story of Thor 2.iso' -o stage03.json
python tools/stage04_record_layout.py '/private/The Story of Thor 2.iso' -o stage04.json
```

The scripts do **not** export game data. They report metadata, aggregate counts and validation outcomes.

## Verified progress

- **Stage 01:** verified 2048-byte-sector Saturn `MK-81302` ISO9660 structure, 33 files.
- **Stage 02:** found 12 possible three-section container structures.
- **Stage 03:** validated 21 counted big-endian 16-bit index tables; nine second-section six-byte record chains.
- **Stage 04:** validated **3,730 first-section records across ten containers**, each obeying **length = 6 + 8×N**, first BE16 word **N−1**. Two other containers do not follow the format.
- **31 synthetic-only tests passed locally**; GitHub Actions tests do not need the original disc.

[Stage 04 report (RU)](docs/STAGE04_REPORT_RU.md) · [Stage 03 report](docs/STAGE03_REPORT_RU.md) · [Roadmap](docs/ROADMAP_RU.md)

**Not done:** graphical asset decoder, recovered animation semantics, levels, combat, native C++/SDL2 game, Switch NRO or full-game playthrough. Publishing a remake that incorporates protected game materials would require permission from the rights holders.
