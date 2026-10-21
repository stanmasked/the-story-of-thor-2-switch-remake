#!/usr/bin/env python3
"""Read structural metadata from a 2048-byte-sector Sega Saturn ISO9660 image.

Nothing in the ISO is extracted or copied to an output file.
"""
import argparse
import hashlib
import json
from pathlib import Path

SECTOR = 2048

def le(buf, pos, size=4):
    return int.from_bytes(buf[pos:pos+size], "little")

def be(buf, pos, size=4):
    return int.from_bytes(buf[pos:pos+size], "big")

def decode(buf):
    return buf.decode("ascii", "replace").strip(" \0")

def inventory(image):
    image = Path(image)
    length = image.stat().st_size
    if length % SECTOR:
        raise ValueError("Image size is not a multiple of 2048")
    with image.open("rb") as fh:
        h = fh.read(SECTOR)
        if not h.startswith(b"SEGA SEGASATURN "):
            raise ValueError("Missing Sega Saturn header")
        info = {"product": decode(h[32:42]), "title": decode(h[96:208]),
                "date": decode(h[48:56]), "area": decode(h[64:80])}
        fh.seek(16 * SECTOR)
        pvd = fh.read(SECTOR)
        if pvd[:7] != b"\x01CD001\x01":
            raise ValueError("No primary ISO9660 volume descriptor")
        if le(pvd, 128, 2) != SECTOR or le(pvd, 80) != be(pvd, 84):
            raise ValueError("Unsupported block size or volume mismatch")
        if pvd[156] < 34 or le(pvd, 158) != be(pvd, 162):
            raise ValueError("Bad ISO9660 root record")
        extent = le(pvd, 158)
        size = le(pvd, 166)
        if extent * SECTOR + size > length:
            raise ValueError("Root directory outside image")
        fh.seek(extent * SECTOR)
        listing = fh.read(size)
        items = []
        i = 0
        while i < size:
            n = listing[i]
            if not n:
                i = (i // SECTOR + 1) * SECTOR
                continue
            if n < 34 or i + n > size:
                raise ValueError("Invalid ISO9660 directory entry")
            record = listing[i:i+n]
            i += n
            name = record[33:33+record[32]]
            if name in (b"\x00", b"\x01"):
                continue
            path = "/" + decode(name).split(";")[0]
            if record[25] & 2:
                raise ValueError("Nested directories not implemented")
            if le(record, 2) != be(record, 6) or le(record, 10) != be(record, 14):
                raise ValueError("Endian disagreement in directory entry: " + path)
            file_lba = le(record, 2)
            file_size = le(record, 10)
            if file_lba * SECTOR + file_size > length:
                raise ValueError("File outside image: " + path)
            items.append({"path": path, "extent_sector": file_lba, "size_bytes": file_size})
        fh.seek(0)
        digest = hashlib.sha256()
        for chunk in iter(lambda: fh.read(2 * 1024 * 1024), b""):
            digest.update(chunk)
    return {"source_file": image.name, "sha256": digest.hexdigest(),
            "size_bytes": length, "sector_size": SECTOR, "file_count": len(items),
            "saturn_header": info, "game_files": items,
            "warnings": ["ISO data track does not establish CD-DA tracks."]}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("image", type=Path)
    ap.add_argument("-o", "--output", type=Path)
    args = ap.parse_args()
    out = json.dumps(inventory(args.image), indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(out, encoding="utf-8")
        print("Metadata-only inventory saved:", args.output)
    else:
        print(out)
