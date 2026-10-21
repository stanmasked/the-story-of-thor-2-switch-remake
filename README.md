# The Story of Thor 2 — Nintendo Switch Remake

Research and future native Nintendo Switch remake of *The Story of Thor 2* / *The Legend of Oasis* (Sega Saturn).

**Current status: Stage 03 — counted resource index tables.** This is research tooling, **not** a playable Nintendo Switch build.

The Sega Saturn ISO is analyzed **locally only**. Never upload copyrighted ISO/BIN/CUE, game audio, sprites, scripts, or other game assets into this public repository.

## Local tooling (Python 3.11+, standard library)

```sh
python -m unittest discover -s tests -v
python tools/inspect_saturn_iso.py '/private/path/The Story of Thor 2.iso' -o stage01.json
python tools/stage02_probe.py '/private/path/The Story of Thor 2.iso' -o stage02.json
python tools/stage03_index_tables.py '/private/path/The Story of Thor 2.iso' -o stage03.json
```

Scripts emit *metadata and aggregate statistics only*, never original payload bytes.

### Confirmed research milestones

- **Stage 01:** verified European Sega Saturn `MK-81302` ISO9660 image with 33 root files.
- **Stage 02:** identified 12 candidate three-section containers.
- **Stage 03:** validated **21 counted big-endian 16-bit index structures**, including **nine** candidate contiguous six-byte record arrays. Neither the record semantics nor the decompression/graphics format is known.
- **19 synthetic unit tests** checked locally. GitHub Actions validates syntax and unit tests without any game ISO.

See the [Stage 03 technical report (Russian)](docs/STAGE03_REPORT_RU.md), [Stage 02 findings](docs/STAGE02_REPORT_RU.md), and [project roadmap](docs/ROADMAP_RU.md).

### Explicitly not yet implemented

No asset decoder, reconstituted maps, combat, native C++/SDL2 engine, libnx/NRO build, or complete gameplay. These remain future stages subject to format analysis and verification.

Only original research code and noncopyrighted metadata are committed. Distribution of a finished remake containing protected game assets requires permission from their rights holders.
