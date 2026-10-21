# The Story of Thor 2 — Nintendo Switch Remake

Research and future native Nintendo Switch remake of *The Story of Thor 2* / *The Legend of Oasis* (Sega Saturn).

**Current status: Stage 02 — disc and resource-structure investigation.** This is not yet a playable Switch build.

The Sega Saturn ISO is analyzed **locally only**. Never upload copyrighted ISO/BIN/CUE, music, sprites, or other original game files to this public repository.

## Local tools

The repository includes a metadata-only Saturn ISO9660 inventory and Stage 02 structural probe (Python 3.11+ / standard library). Their output contains structural metadata and aggregate statistics only, not copyrighted payload data.

```sh
python -m unittest discover -s tests -v
python tools/inspect_saturn_iso.py '/private/path/The Story of Thor 2.iso' -o stage01.json
python tools/stage02_probe.py '/private/path/The Story of Thor 2.iso' -o stage02.json
```

See [Stage 02 results](docs/STAGE02_REPORT_RU.md) and [the roadmap](docs/ROADMAP_RU.md).

We have confirmed a 2048-byte-sector Saturn ISO9660 disc and identified **12 candidate files** with three-section offset headers. The semantics of these blocks, compression and asset formats are **not yet proven**. Homebrew-native Switch code has not yet been built.

This repository contains no proprietary game content. Distribution of a finished remake using original protected material would require permission from its rights holders.
