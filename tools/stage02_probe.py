#!/usr/bin/env python3
"""Metadata-only Stage 02 resource-structure probe. NO payload extraction."""
import argparse
from collections import Counter
import json
import math
from pathlib import Path
from inspect_saturn_iso import SECTOR, inventory

WINDOW = 8192
LIMIT = 5 * 1024 * 1024

def offsets_layout(payload):
    """Identify three bounded sections, either at file offset 0 or after a preamble."""
    for base in (0, 4):
        if len(payload) < base + 16:
            continue
        vals = [int.from_bytes(payload[base+i:base+i+4], "big") for i in (0, 4, 8)]
        if vals[0] == 12 and vals[0] < vals[1] < vals[2] < len(payload)-base:
            bounds = [base+v for v in vals] + [len(payload)]
            return {"table_offset": base, "relative_offsets": vals,
                    "section_size_bytes": [bounds[i+1]-bounds[i] for i in range(3)],
                    "classification": "candidate_three_section_layout"}
    return None

def stats(data):
    if not data:
        return {"sampled_bytes": 0, "entropy_bits_per_byte": None, "zero_fraction": None}
    c = Counter(data)
    n = len(data)
    ent = -sum((v/n)*math.log2(v/n) for v in c.values())
    return {"sampled_bytes": n, "entropy_bits_per_byte": round(ent, 4),
            "zero_fraction": round(c.get(0, 0)/n, 4)}

def monotonic_be16_prefix(data, limit=128):
    """A heuristic count, not proof that a prefix contains pointers."""
    prev = -1
    count = 0
    for i in range(min(len(data)//2, limit)):
        word = int.from_bytes(data[i*2:i*2+2], "big")
        if word <= prev or word >= len(data):
            break
        prev = word
        count += 1
    return count

def structural_analysis(image):
    image = Path(image)
    info = inventory(image)
    results = []
    with image.open("rb") as fh:
        for entry in info["game_files"]:
            size = entry["size_bytes"]
            path = entry["path"]
            fh.seek(entry["extent_sector"] * SECTOR)
            # Skip large movie payloads; decode nothing.
            payload = fh.read(size) if size <= LIMIT else b""
            if size <= LIMIT and len(payload) != size:
                raise ValueError("Incomplete file extent: " + path)
            layout = offsets_layout(payload)
            item = {"path": path, "extent_sector": entry["extent_sector"],
                    "size_bytes": size, "structure": layout,
                    "start_sample": stats(payload[:WINDOW]) if payload else None}
            if layout:
                base = layout["table_offset"]
                bounds = [base+v for v in layout["relative_offsets"]] + [size]
                item["sections"] = []
                for i in range(3):
                    a,b = bounds[i:i+2]
                    sample = payload[a:min(b,a+WINDOW)]
                    item["sections"].append({
                        "index": i, "size_bytes": b-a,
                        "start_sample": stats(sample),
                        "monotonic_be16_prefix_words": monotonic_be16_prefix(sample)})
            results.append(item)
    candidates = [r["path"] for r in results if r["structure"]]
    return {"schema_version": 1, "disc_sha256": info["sha256"],
            "saturn_product": info["saturn_header"]["product"],
            "file_count": info["file_count"], "candidate_count": len(candidates),
            "candidates": candidates, "results": results,
            "warnings": ["Offset patterns do not prove resource types or compression.",
                         "Entropy sampled only near file/section starts.",
                         "Single-track ISO cannot confirm external CD-DA audio.",
                         "No original game payloads, imagery, music, video, or code are exported."]}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("image", type=Path)
    ap.add_argument("-o", "--output", type=Path)
    args = ap.parse_args()
    report = structural_analysis(args.image)
    output = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(output, encoding="utf-8")
        print(f"Saved {report['candidate_count']} structural candidates to {args.output}")
    else:
        print(output)
