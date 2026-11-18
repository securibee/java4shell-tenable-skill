"""Build findings.json from saved Tenable plugin outputs and CVE findings.

Usage:
  python3 findings.py --outputs <run>/outputs.jsonl [--cve <run>/cve_findings.json]
                      [--packages <run>/package_findings.json] -o <run>/findings.json

outputs.jsonl holds one JSON object per line with the keys asset_id, asset, ip, fqdn, plugin_id,
output and last_seen. An empty output means the asset has that plugin but its output could not be
retrieved. cve_findings.json is a JSON list of {asset_id, plugin_id, state}. package_findings.json is a
JSON list of {asset_id, asset, ip, fqdn, name, state, asset_class}; it adds rows for assets that have
no detection row but a Java package finding. Records that name no asset (no asset_id, asset or ip)
are skipped with a WARN line.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from java4shell.inventory import (
    asset_key,
    build_findings,
    has_identity,
    newest_java_detection,
    package_rows,
    unmatched_package_findings,
)

# Detection scans older than this predate the CVE plugin and cannot show the vulnerable state.
CVE_PLUGIN_PUBLISHED = datetime(2026, 11, 17, tzinfo=timezone.utc)


def read_outputs(path: Path) -> list[dict]:
    records = []
    with path.open(encoding="utf-8-sig") as f:
        for number, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except ValueError as e:
                sys.exit(f"{path}: line {number} is not valid JSON ({e})")
            if not isinstance(record, dict):
                sys.exit(f"{path}: line {number} is not a JSON object")
            records.append(record)
    return records


def read_cve(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, list):
        sys.exit(f"{path}: expected a JSON list of findings")
    return [f for f in data if isinstance(f, dict)]


def read_packages(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, list):
        sys.exit(f"{path}: expected a JSON list of package findings")
    return [f for f in data if isinstance(f, dict)]


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Build findings.json from plugin outputs.")
    parser.add_argument("--outputs", required=True, type=Path, help="outputs.jsonl")
    parser.add_argument("--cve", type=Path, help="cve_findings.json")
    parser.add_argument("--packages", type=Path, help="package_findings.json")
    parser.add_argument("-o", "--output", required=True, type=Path, help="findings.json to write")
    args = parser.parse_args(argv)

    outputs = read_outputs(args.outputs)
    cve = read_cve(args.cve) if args.cve else []
    packages = read_packages(args.packages) if args.packages else []
    # A record that names no asset cannot be told apart from any other such record, so it is never merged.
    nameless = sum(1 for r in outputs + packages if not has_identity(r))
    outputs = [r for r in outputs if has_identity(r)]
    packages = [r for r in packages if has_identity(r)]
    rows = build_findings(outputs, cve)
    covered = {asset_key(r) for r in rows}
    extra = package_rows(packages, covered, cve)
    unmatched = unmatched_package_findings(packages, covered)
    package_only = len({asset_key(r) for r in extra})
    rows = rows + extra

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    row_assets = {asset_key(r) for r in rows}
    stale = sum(1 for key, seen in newest_java_detection(outputs).items()
                if seen < CVE_PLUGIN_PUBLISHED and key in covered)
    only_placeholders = set()
    for key in row_assets:
        mine = [r for r in rows if asset_key(r) == key]
        if all(r["no_output"] for r in mine):
            only_placeholders.add(key)
    print(f"assets={len(row_assets)} pairs={len(rows)} truncated={sum(1 for r in rows if r['truncated'])} "
          f"stale_scans={stale} no_output={len(only_placeholders)} package_only={package_only} "
          f"package_unmatched={unmatched}")
    if nameless:
        print(f"WARN: {nameless} input records have no asset_id, asset or ip; skipped")


if __name__ == "__main__":
    main()
