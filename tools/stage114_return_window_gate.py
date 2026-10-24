#!/usr/bin/env python3
"""Fail-closed audit for private Stage114 SH-2 call/return windows.

Only safe counts and booleans are emitted. Raw PCs, opcodes, registers and RAM
bytes must remain in the owner-only evidence archive.
"""
from __future__ import annotations
import argparse, csv, json, re
from pathlib import Path

HEADER = [
 "kind","relative_step","global_step","pre_pc","pre_pc_id","pre_pc_if","pre_pipe_id","pre_pipe_if",
 "pre_r3","pre_r13","pre_r15","pre_pr","pre_sr","pre_byte",
 "post_pc","post_pc_id","post_pc_if","post_pipe_id","post_pipe_if",
 "post_r3","post_r13","post_r15","post_pr","post_sr","post_byte",
 "byte_changed","target_bsr","target_rts_candidate"
]
HEX8 = re.compile(r"^[0-9a-fA-F]{8}$")
HEX2 = re.compile(r"^[0-9a-fA-F]{2}$")
class AuditError(ValueError): pass

def is_normal_bsr(pid: int) -> bool:
    return ((pid >> 24) & 0xff) == 0x6a and ((pid & 0xffff) & 0xf000) == 0xb000

def is_normal_rts(pid: int) -> bool:
    return ((pid >> 24) & 0xff) == 0x6e and (pid & 0xffff) == 0x000b

def audit(path: Path, expected_trigger: int | None = None, expected_target: int | None = None) -> dict:
    if path.is_symlink() or not path.is_file():
        raise AuditError("invalid_input")
    steps = {}
    marker = None
    last_rel = 0
    last_global = 0
    global_offset = None
    with path.open("r", encoding="ascii", newline="") as fp:
        reader = csv.reader(fp)
        if next(reader, None) != ["stage114_return_window_v1"]:
            raise AuditError("bad_magic")
        if next(reader, None) != HEADER:
            raise AuditError("bad_header")
        for n, row in enumerate(reader, 1):
            if n > 513:  # up to 512 step rows plus one terminal marker
                raise AuditError("row_limit")
            if len(row) != len(HEADER):
                raise AuditError("column_count")
            d = dict(zip(HEADER, row))
            if marker is not None:
                raise AuditError("rows_after_marker")
            if d["kind"] in ("complete", "step_limit", "event_cap"):
                if not d["relative_step"].isascii() or not d["relative_step"].isdecimal():
                    raise AuditError("bad_marker_step")
                if not d["global_step"].isascii() or not d["global_step"].isdecimal():
                    raise AuditError("bad_marker_global_step")
                if any(d[k] for k in HEADER[3:]):
                    raise AuditError("marker_has_payload")
                marker = {"kind": d["kind"], "relative_step": int(d["relative_step"]),
                          "global_step": int(d["global_step"])}
                continue
            if d["kind"] != "step":
                raise AuditError("bad_kind")
            if not d["relative_step"].isascii() or not d["relative_step"].isdecimal():
                raise AuditError("bad_relative_step")
            if not d["global_step"].isascii() or not d["global_step"].isdecimal():
                raise AuditError("bad_global_step")
            rel, glob = int(d["relative_step"]), int(d["global_step"])
            if rel <= last_rel or glob <= last_global or rel > 2000000 or glob > 0xffffffffffffffff:
                raise AuditError("nonmonotonic_or_unbounded_step")
            offset = glob - rel
            if global_offset is None:
                global_offset = offset
            elif offset != global_offset:
                raise AuditError("relative_global_step_mismatch")
            last_rel, last_global = rel, glob
            for k in ("pre_pc","pre_pc_id","pre_pc_if","pre_pipe_id","pre_pipe_if",
                      "pre_r3","pre_r13","pre_r15","pre_pr","pre_sr",
                      "post_pc","post_pc_id","post_pc_if","post_pipe_id","post_pipe_if",
                      "post_r3","post_r13","post_r15","post_pr","post_sr"):
                if not HEX8.fullmatch(d[k]):
                    raise AuditError("bad_hex_field")
            if not HEX2.fullmatch(d["pre_byte"]) or not HEX2.fullmatch(d["post_byte"]):
                raise AuditError("bad_byte")
            if d["byte_changed"] not in ("0","1") or d["target_bsr"] not in ("0","1") or d["target_rts_candidate"] not in ("0","1"):
                raise AuditError("bad_flag")
            if (d["pre_byte"] != d["post_byte"]) != (d["byte_changed"] == "1"):
                raise AuditError("byte_flag_mismatch")
            steps[rel] = d
    if marker is None:
        raise AuditError("missing_terminal_marker")
    if (not steps or marker["relative_step"] < last_rel or marker["global_step"] < last_global or
            marker["relative_step"] > 2000000 or marker["global_step"] > 0xffffffffffffffff or
            global_offset is None or marker["global_step"] - marker["relative_step"] != global_offset):
        raise AuditError("terminal_step_offset_mismatch")
    bsr_rows = [d for d in steps.values() if d["target_bsr"] == "1"]
    rts_rows = [d for d in steps.values() if d["target_rts_candidate"] == "1"]
    byte_rows = [d for d in steps.values() if d["byte_changed"] == "1"]
    bsr_ok = False
    delay_slot_ok = False
    rts_match_ok = False
    rts_delay_slot_ok = False
    return_site_ok = False
    r13_preserved = False
    return_pc_match = False
    if len(bsr_rows) == 1:
        bsr = bsr_rows[0]
        bsr_step = int(bsr["relative_step"])
        pre_pid, post_pid = int(bsr["pre_pipe_id"],16), int(bsr["post_pipe_id"],16)
        pre_pc = int(bsr["pre_pc"],16)
        bsr_ok = is_normal_bsr(pre_pid) and int(bsr["post_pr"],16) != int(bsr["pre_pr"],16)
        if expected_trigger is not None:
            bsr_ok = bsr_ok and pre_pc == ((expected_trigger + 4) & 0xffffffff)
        ret_pc = int(bsr["post_pr"],16)
        delay = steps.get(bsr_step + 1)
        if delay:
            dpid = int(delay["pre_pipe_id"],16)
            dop = dpid & 0xffff
            delay_slot_ok = (
                post_pid == dpid and ((dpid >> 24) & 0x80) != 0 and
                (dop & 0xf00f) == 0x2000 and delay["byte_changed"] == "1"
            )
            if expected_target is not None:
                delay_slot_ok = delay_slot_ok and int(delay["pre_r3"],16) == expected_target
        else:
            delay_slot_ok = False
    else:
        ret_pc = None
    if len(rts_rows) == 1 and ret_pc is not None:
        rts = rts_rows[0]
        rts_step = int(rts["relative_step"])
        pre_pid = int(rts["pre_pipe_id"],16)
        post_pid = int(rts["post_pipe_id"],16)
        rts_match_ok = (
            is_normal_rts(pre_pid) and int(rts["pre_pr"],16) == ret_pc and
            int(rts["post_pc_if"],16) == ret_pc
        )
        # UCDelayBranch(PR) should place the old Pipe_IF into Pipe_ID as a
        # delay-slot dispatch and fetch the instruction at PR into Pipe_IF.
        rts_delay_slot_ok = (
            ((post_pid >> 24) & 0x80) != 0 and
            (post_pid & 0xffff) == (int(rts["pre_pipe_if"],16) & 0xffff)
        )
        delay = steps.get(rts_step + 1)
        ret_site = steps.get(rts_step + 2)
        if delay and ret_site:
            delay_pid = int(delay["pre_pipe_id"],16)
            delay_post_pid = int(delay["post_pipe_id"],16)
            ret_pre_pid = int(ret_site["pre_pipe_id"],16)
            return_site_ok = (
                delay_pid == post_pid and ((delay_pid >> 24) & 0x80) != 0 and
                (delay_post_pid & 0xffff) == (int(rts["post_pipe_if"],16) & 0xffff) and
                ((delay_post_pid >> 24) & 0x80) == 0 and
                ret_pre_pid == delay_post_pid and
                ((ret_pre_pid >> 24) & 0x80) == 0 and
                (ret_pre_pid & 0xffff) == (int(rts["post_pipe_if"],16) & 0xffff)
            )
            return_pc_match = int(rts["post_pc_if"],16) == ret_pc
            if bsr_rows:
                bsr_r13 = int(bsr_rows[0]["pre_r13"],16)
                rts_r13 = int(rts["pre_r13"],16)
                return_r13 = int(ret_site["pre_r13"],16)
                path_rows = [d for rel, d in steps.items() if bsr_step <= rel <= rts_step + 2]
                r13_preserved = (
                    marker["kind"] == "complete" and bsr_ok and delay_slot_ok and
                    len(byte_rows) == 1 and len(rts_rows) == 1 and rts_match_ok and
                    rts_delay_slot_ok and return_site_ok and return_pc_match and
                    bool(path_rows) and all(
                        int(d["pre_r13"], 16) == bsr_r13 and
                        int(d["post_r13"], 16) == bsr_r13
                        for d in path_rows
                    )
                )
    complete = (
        marker["kind"] == "complete" and bsr_ok and delay_slot_ok and
        len(byte_rows) == 1 and len(rts_rows) == 1 and rts_match_ok and
        rts_delay_slot_ok and return_site_ok and return_pc_match
    )
    return {
        "schema_version": 1,
        "stage": "stage114_targeted_bsr_rts_return_window",
        "capture_structure_valid": True,
        "terminal_marker": marker["kind"],
        "recorded_step_rows": len(steps),
        "target_bsr_records": len(bsr_rows),
        "target_byte_transition_records": len(byte_rows),
        "target_rts_candidate_records": len(rts_rows),
        "target_bsr_normal_dispatch_and_return_token": bsr_ok,
        "mov_b_delay_slot_and_target_byte_transition": delay_slot_ok,
        "rts_normal_dispatch_pr_match_and_return_fetch": rts_match_ok,
        "rts_delay_slot_pipeline_match": rts_delay_slot_ok,
        "return_site_instruction_selected_and_step_completed": return_site_ok,
        "return_pc_pipeline_match": return_pc_match,
        "r13_preserved_on_observed_call_path": r13_preserved,
        "complete_observed_call_return_proven": complete,
        "all_path_r13_preservation_proven": False,
        "raw_private_addresses_opcodes_registers_or_bytes_emitted": False
    }

def main() -> int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--trace", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--trigger", required=True, type=lambda x:int(x,16))
    ap.add_argument("--target", required=True, type=lambda x:int(x,16))
    a=ap.parse_args()
    try:
        result=audit(a.trace,a.trigger,a.target)
    except (AuditError,OSError,UnicodeError,ValueError):
        raise SystemExit("stage114_return_window_gate_failed") from None
    a.out.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print("stage114_return_window_gate_pass" if result["complete_observed_call_return_proven"] else "stage114_return_window_incomplete")
    return 0 if result["complete_observed_call_return_proven"] else 2
if __name__ == "__main__":
    raise SystemExit(main())
