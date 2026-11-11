#!/usr/bin/env python3
"""Normalize scanner outputs (SARIF, ruff JSON, mypy text, JUnit XML) into one list.

Usage: build_findings.py --reports reports --out triage-input
Writes findings.json (machine readable) and findings.md (human summary).
"""
from __future__ import annotations

import argparse
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

LEVEL_TO_SEV = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
MAX_MSG = 500


def sev_from_score(score) -> str | None:
    try:
        v = float(score)
    except (TypeError, ValueError):
        return None
    if v >= 9:
        return "critical"
    if v >= 7:
        return "high"
    if v >= 4:
        return "medium"
    return "low"


def clean_path(p: str) -> str:
    p = p.removeprefix("file://")
    cwd = str(Path.cwd()) + "/"
    return p.removeprefix(cwd).lstrip("/")


def parse_sarif(path: Path) -> list[dict]:
    out = []
    data = json.loads(path.read_text())
    for run in data.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        tool = driver.get("name", path.stem)
        rules = {r.get("id"): r for r in driver.get("rules", [])}
        for res in run.get("results", []):
            rid = res.get("ruleId", "unknown")
            rule = rules.get(rid, {})
            sev = sev_from_score(rule.get("properties", {}).get("security-severity")) or \
                LEVEL_TO_SEV.get(res.get("level", "warning"), "medium")
            locs = res.get("locations") or [{}]
            phys = locs[0].get("physicalLocation", {})
            msg = res.get("message", {}).get("text", "") or \
                rule.get("shortDescription", {}).get("text", "")
            out.append({
                "tool": tool,
                "rule": rid,
                "severity": sev,
                "file": clean_path(phys.get("artifactLocation", {}).get("uri", "")),
                "line": phys.get("region", {}).get("startLine"),
                "message": " ".join(msg.split())[:MAX_MSG],
            })
    return out


def parse_ruff(path: Path) -> list[dict]:
    out = []
    for item in json.loads(path.read_text() or "[]"):
        out.append({
            "tool": "ruff",
            "rule": item.get("code") or "syntax",
            "severity": "low",
            "file": clean_path(item.get("filename", "")),
            "line": (item.get("location") or {}).get("row"),
            "message": item.get("message", "")[:MAX_MSG],
        })
    return out


MYPY_RE = re.compile(r"^(?P<file>[^:]+):(?P<line>\d+): (?P<lvl>error|warning): "
                     r"(?P<msg>.*?)(?:\s+\[(?P<code>[\w-]+)\])?$")


def parse_mypy(path: Path) -> list[dict]:
    out = []
    for line in path.read_text().splitlines():
        m = MYPY_RE.match(line)
        if m:
            out.append({
                "tool": "mypy",
                "rule": m["code"] or "mypy",
                "severity": "low",
                "file": clean_path(m["file"]),
                "line": int(m["line"]),
                "message": m["msg"][:MAX_MSG],
            })
    return out


def parse_junit(path: Path) -> list[dict]:
    out = []
    for case in ET.parse(path).getroot().iter("testcase"):
        for kind in ("failure", "error"):
            node = case.find(kind)
            if node is not None:
                out.append({
                    "tool": "pytest",
                    "rule": f"{case.get('classname')}::{case.get('name')}",
                    "severity": "high",
                    "file": clean_path(case.get("file") or case.get("classname", "")),
                    "line": None,
                    "message": (node.get("message") or "")[:MAX_MSG],
                })
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", default="reports")
    ap.add_argument("--out", default="triage-input")
    args = ap.parse_args()

    findings: list[dict] = []
    for f in sorted(Path(args.reports).rglob("*")):
        try:
            if f.suffix == ".sarif":
                findings += parse_sarif(f)
            elif f.name == "ruff.json":
                findings += parse_ruff(f)
            elif f.name == "mypy.txt":
                findings += parse_mypy(f)
            elif f.name == "junit.xml":
                findings += parse_junit(f)
        except Exception as exc:  # keep going; one bad report must not kill triage
            print(f"WARN: could not parse {f}: {exc}")

    findings.sort(key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["tool"], x["file"]))
    for i, f in enumerate(findings, 1):
        f["id"] = f"F-{i:03d}"

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "findings.json").write_text(json.dumps(findings, indent=2))

    by_tool = Counter(f["tool"] for f in findings)
    by_sev = Counter(f["severity"] for f in findings)
    md = ["# Raw findings", "", f"Total: **{len(findings)}**", "",
          "| Tool | Count |", "|---|---|"]
    md += [f"| {t} | {c} |" for t, c in sorted(by_tool.items())]
    md += ["", "| Severity | Count |", "|---|---|"]
    md += [f"| {s} | {by_sev[s]} |" for s in SEV_ORDER if by_sev[s]]
    (out / "findings.md").write_text("\n".join(md) + "\n")
    print(f"Wrote {len(findings)} findings to {out}/findings.json")


if __name__ == "__main__":
    main()