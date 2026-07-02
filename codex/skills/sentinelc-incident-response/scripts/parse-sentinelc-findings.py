#!/usr/bin/env python3
import argparse
import json
from collections import Counter
from pathlib import Path


def load_json(path: Path):
    raw = path.read_bytes()
    for enc in ("utf-8-sig", "utf-16", "utf-8"):
        try:
            return json.loads(raw.decode(enc))
        except Exception:
            pass
    raise SystemExit(f"Could not parse JSON report: {path}")


def action_for(rule: str) -> str:
    if rule in {"OFFLINE.DEFENDER_EXCLUSION", "TAMPER.DEFENDER_EXCLUSION"}:
        return "Export evidence, then remove broad or user-writable Defender exclusions unless explicitly temporary."
    if rule == "FILE.YARA_MATCH":
        return "Hash full file, inspect match/embedded payload, preserve copy, then quarantine only when confirmed suspicious."
    if rule in {"PROC.ENCODED_CMD", "PROC.SUSPICIOUS_PARENT", "PROC.PPID_SPOOF"}:
        return "Capture full command line and parent process; attribute before stopping."
    if rule.startswith("RK.") or rule == "OFFLINE.BOOT_DRIVER":
        return "Collect driver/service evidence; disable only with strong evidence and rollback plan."
    if rule.startswith("PERSIST.") or rule in {"OFFLINE.RUNKEY", "OFFLINE.USER_RUNKEY"}:
        return "Export registry/task evidence; disable unwanted persistence rather than deleting app files."
    if rule.startswith("NET."):
        return "Confirm listener or remote endpoint is expected; stop or disable only unwanted services."
    if rule.startswith("KEY.") or rule.startswith("SPY."):
        return "Treat as privacy-sensitive; verify vendor/signature and disable if not needed."
    if rule in {"PROC.RWX_MEM", "CORR.IMPLANT", "CORR.MULTI_SIGNAL"}:
        return "Correlate with signature/path/process role; isolate only if not known JIT/developer/browser tooling."
    return "Review path, signature, hash, and correlation before action."


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("report", type=Path)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()

    data = load_json(args.report)
    findings = data.get("findings", [])
    summary = data.get("summary", {})
    sev_counts = Counter(f.get("severity", "UNKNOWN") for f in findings)
    rule_counts = Counter(f.get("rule", "UNKNOWN") for f in findings)

    lines = []
    lines.append("# SentinelC Findings Action Plan")
    lines.append("")
    lines.append(f"Source: `{args.report}`")
    if summary:
        lines.append(
            "Summary: total={total} critical={crit} high={high} medium={med} low={low} info={info}".format(
                total=summary.get("total", len(findings)),
                crit=summary.get("crit", sev_counts.get("CRITICAL", 0)),
                high=summary.get("high", sev_counts.get("HIGH", 0)),
                med=summary.get("med", sev_counts.get("MEDIUM", 0)),
                low=summary.get("low", sev_counts.get("LOW", 0)),
                info=summary.get("info", sev_counts.get("INFO", 0)),
            )
        )
    lines.append("")
    lines.append("## High and Critical Findings")
    lines.append("")
    priority = [f for f in findings if f.get("severity") in {"CRITICAL", "HIGH"}]
    if not priority:
        lines.append("No high or critical findings.")
    for idx, f in enumerate(priority, 1):
        rule = f.get("rule", "UNKNOWN")
        evidence = str(f.get("evidence", "")).replace("\n", " ")
        lines.append(f"{idx}. `{rule}` | `{f.get('target', '')}` | {f.get('title', '')}")
        lines.append(f"   Evidence: {evidence[:700]}")
        lines.append(f"   Action: {action_for(rule)}")
    lines.append("")
    lines.append("## Rule Counts")
    lines.append("")
    for rule, count in rule_counts.most_common():
        lines.append(f"- `{rule}`: {count} finding(s). {action_for(rule)}")
    lines.append("")
    lines.append("## Limitations")
    lines.append("")
    limits = str(data.get("limitations", "")).splitlines()
    if limits:
        for line in limits:
            lines.append(f"- {line}")
    else:
        lines.append("- None reported.")

    text = "\n".join(lines) + "\n"
    if args.out:
        args.out.write_text(text, encoding="utf-8")
    else:
        print(text)


if __name__ == "__main__":
    main()
