#!/usr/bin/env python3
"""Normalize scanner outputs into one findings list.

Supported inputs:
- SARIF files (*.sarif)
- Ruff JSON (ruff.json)
- mypy text (mypy.txt)
- JUnit XML (junit.xml)

Usage:
    python scripts/build_findings.py --reports reports --out triage-input

Writes:
    findings.json
    findings.md

Every parsed finding is retained. Duplicate findings are intentionally not
removed: triage can group them by root cause without losing scanner evidence.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from urllib.parse import unquote


LEVEL_TO_SEV = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}

SEV_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

MAX_MSG = 500

# Examples:
#   app/main.py:12: error: Missing return statement [return]
#   app/main.py:12: warning: Some warning
MYPY_RE = re.compile(
    r"^(?P<file>.+?):(?P<line>\d+): "
    r"(?P<lvl>error|warning|note): "
    r"(?P<msg>.*?)"
    r"(?:\s+\[(?P<code>[\w-]+)\])?$"
)


def normalize_severity(value: object) -> str | None:
    """Normalize common scanner severity labels."""
    if value is None:
        return None

    text = str(value).strip().lower()

    aliases = {
        "critical": "critical",
        "crit": "critical",
        "high": "high",
        "error": "high",
        "medium": "medium",
        "moderate": "medium",
        "warning": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
        "note": "low",
        "none": "info",
    }

    return aliases.get(text)


def sev_from_score(score: object) -> str | None:
    """Convert a numeric CVSS/security score into a severity."""
    try:
        value = float(score)
    except (TypeError, ValueError):
        return None

    if value >= 9:
        return "critical"
    if value >= 7:
        return "high"
    if value >= 4:
        return "medium"
    if value >= 0:
        return "low"

    return None


def clean_path(value: str | None) -> str:
    """Normalize scanner paths into readable repository-relative paths."""
    if not value:
        return ""

    path = unquote(str(value)).replace("\\", "/")
    path = path.removeprefix("file://")

    cwd = str(Path.cwd().resolve()).replace("\\", "/").rstrip("/") + "/"
    resolved_cwd_prefix = cwd

    if path.startswith(resolved_cwd_prefix):
        path = path[len(resolved_cwd_prefix):]

    # SARIF paths may start with ./.
    while path.startswith("./"):
        path = path[2:]

    return path


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def sarif_severity(result: dict, rule: dict) -> str:
    """Resolve severity from common SARIF producer conventions."""
    result_props = result.get("properties") or {}
    rule_props = rule.get("properties") or {}

    candidates = [
        result_props.get("severity"),
        result_props.get("security-severity"),
        rule_props.get("severity"),
        rule_props.get("security-severity"),
    ]

    for candidate in candidates:
        severity = normalize_severity(candidate)
        if severity:
            return severity

        severity = sev_from_score(candidate)
        if severity:
            return severity

    level = str(result.get("level", "warning")).lower()
    return LEVEL_TO_SEV.get(level, "medium")


def parse_sarif(path: Path) -> list[dict]:
    findings = []
    data = read_json(path)

    for run in data.get("runs", []):
        driver = (run.get("tool") or {}).get("driver") or {}
        tool = driver.get("name") or path.stem

        rules = {
            rule.get("id"): rule
            for rule in driver.get("rules", [])
            if rule.get("id")
        }

        for result in run.get("results", []):
            rule_id = result.get("ruleId") or "unknown"
            rule = rules.get(rule_id, {})

            locations = result.get("locations") or []
            physical = {}
            if locations:
                physical = (
                    locations[0].get("physicalLocation") or {}
                )

            artifact = physical.get("artifactLocation") or {}
            region = physical.get("region") or {}

            message_obj = result.get("message") or {}
            message = message_obj.get("text") or ""

            if not message:
                description = rule.get("shortDescription") or {}
                message = description.get("text") or ""

            findings.append({
                "tool": tool,
                "rule": rule_id,
                "severity": sarif_severity(result, rule),
                "file": clean_path(artifact.get("uri")),
                "line": region.get("startLine"),
                "message": " ".join(str(message).split())[:MAX_MSG],
            })

    return findings


def parse_ruff(path: Path) -> list[dict]:
    findings = []

    data = read_json(path)
    if not isinstance(data, list):
        raise ValueError("Ruff JSON root must be an array")

    for item in data:
        location = item.get("location") or {}

        findings.append({
            "tool": "ruff",
            "rule": item.get("code") or "syntax",
            "severity": "low",
            "file": clean_path(item.get("filename")),
            "line": location.get("row"),
            "message": " ".join(
                str(item.get("message", "")).split()
            )[:MAX_MSG],
        })

    return findings


def parse_mypy(path: Path) -> list[dict]:
    findings = []

    for raw_line in path.read_text(
        encoding="utf-8",
        errors="replace",
    ).splitlines():
        match = MYPY_RE.match(raw_line)

        if not match:
            continue

        findings.append({
            "tool": "mypy",
            "rule": match.group("code") or "mypy",
            "severity": (
                "high"
                if match.group("lvl") == "error"
                else "medium"
                if match.group("lvl") == "warning"
                else "low"
            ),
            "file": clean_path(match.group("file")),
            "line": int(match.group("line")),
            "message": " ".join(
                match.group("msg").split()
            )[:MAX_MSG],
        })

    return findings


def parse_junit(path: Path) -> list[dict]:
    findings = []
    root = ET.parse(path).getroot()

    for case in root.iter("testcase"):
        for kind in ("failure", "error"):
            node = case.find(kind)

            if node is None:
                continue

            message = node.get("message") or node.text or ""

            findings.append({
                "tool": "pytest",
                "rule": (
                    f"{case.get('classname', 'unknown')}::"
                    f"{case.get('name', 'unknown')}"
                ),
                "severity": "high",
                "file": clean_path(
                    case.get("file") or case.get("classname", "")
                ),
                "line": None,
                "message": " ".join(message.split())[:MAX_MSG],
            })

    return findings


def parse_report(path: Path) -> list[dict]:
    """Dispatch a supported report file to its parser."""
    if path.suffix.lower() == ".sarif":
        return parse_sarif(path)

    if path.name == "ruff.json":
        return parse_ruff(path)

    if path.name == "mypy.txt":
        return parse_mypy(path)

    if path.name == "junit.xml":
        return parse_junit(path)

    return []


def write_outputs(findings: list[dict], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    findings.sort(
        key=lambda item: (
            SEV_ORDER.get(item["severity"], 9),
            item["tool"].lower(),
            item["file"].lower(),
            item["line"] or 0,
            item["rule"],
            item["message"],
        )
    )

    for index, finding in enumerate(findings, start=1):
        finding["id"] = f"F-{index:03d}"

    json_path = output_dir / "findings.json"
    json_path.write_text(
        json.dumps(findings, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    by_tool = Counter(item["tool"] for item in findings)
    by_severity = Counter(item["severity"] for item in findings)

    lines = [
        "# Raw findings",
        "",
        f"Total: **{len(findings)}**",
        "",
        "| Tool | Count |",
        "|---|---:|",
    ]

    lines.extend(
        f"| {tool} | {count} |"
        for tool, count in sorted(by_tool.items())
    )

    lines.extend([
        "",
        "| Severity | Count |",
        "|---|---:|",
    ])

    lines.extend(
        f"| {severity} | {by_severity[severity]} |"
        for severity in SEV_ORDER
        if by_severity[severity]
    )

    (output_dir / "findings.md").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Normalize scanner reports for Codex triage."
    )
    parser.add_argument("--reports", default="reports")
    parser.add_argument("--out", default="triage-input")
    args = parser.parse_args()

    reports_dir = Path(args.reports)
    output_dir = Path(args.out)

    if not reports_dir.exists():
        print(
            f"ERROR: reports directory does not exist: {reports_dir}",
            file=sys.stderr,
        )
        return 1

    findings = []
    parse_errors = []

    report_files = sorted(
        path for path in reports_dir.rglob("*")
        if path.is_file()
    )

    for report in report_files:
        try:
            parsed = parse_report(report)
            findings.extend(parsed)
        except Exception as exc:
            # Keep processing other reports, but make failures visible.
            message = f"{report}: {type(exc).__name__}: {exc}"
            parse_errors.append(message)
            print(f"WARN: could not parse {message}", file=sys.stderr)

    write_outputs(findings, output_dir)

    print(f"Parsed reports: {len(report_files)}")
    print(f"Normalized findings: {len(findings)}")
    print(f"Report parse errors: {len(parse_errors)}")
    print(f"Output: {output_dir}/findings.json")
    print(f"Output: {output_dir}/findings.md")

    # A malformed report should not erase usable findings, but should make
    # the normalization step visible as degraded in the CI logs.
    return 1 if parse_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())


