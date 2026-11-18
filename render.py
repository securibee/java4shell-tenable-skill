#!/usr/bin/env python3
"""Render a Java4Shell (CVE-2026-114938) exposure report (CSV, HTML, PDF) from findings.json.

Usage: python3 render.py <run>/findings.json <outdir>

findings.json is a list of rows, one per Java install on one asset, with keys:
asset_id, asset, ip, fqdn, os, arch, cpu_model, virtualization, java_vendor,
vendor_confidence, java_version_raw, java_path, java_binary, managed_by_os,
detection_plugin, cve_plugins (list: CVE plugins in scope for this install),
asset_cve_plugins (list: every CVE plugin hit on the asset), last_seen, plugin_output,
truncated, no_output, version_conflict (plugins that read different versions), and
optionally cmdline_flags (list of -XX options seen on the process list; evidence only).
Rows with no_output, a cut-off blank row or a version_conflict are Unknown - verify.

Next to findings.json, an optional fixed.json (fixed-version overrides) is read
when present.
"""
from __future__ import annotations

import base64
import csv
import html
import json
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from string import Template

from java4shell.conditions import assess_arch, assess_cpu, assess_flags, confidence, decide, priority
from java4shell.model import (
    AFFECTED_CPU_UNCONFIRMED,
    IMPACTED,
    MITIGATED,
    NOT_IMPACTED,
    ORDER,
    UNKNOWN_VERIFY,
    HostEvidence,
)
from java4shell.inventory import asset_key
from java4shell.versions import (
    FIXED_AS_OF,
    assess_runtime,
    held_evidence,
    java_line,
    load_overrides,
    normalize_vendor,
)

FAQ = ("https://www.tenable.com/blog/java4shell-cve-2026-114938-frequently-asked-questions-"
       "about-openjdk-rce-vulnerability")
JAVA_REPORT = "https://www.tenable.com/vulnerability-management-reports/java-visibility-and-exposures"

# Swatches follow Tenable's severity palette (critical, high, medium); the rest are
# cyberagents-exchange-website tokens (MCP blue, bg-tertiary).
COLORS = {IMPACTED: "#91243E", AFFECTED_CPU_UNCONFIRMED: "#DD4B50", UNKNOWN_VERIFY: "#F18C43",
          MITIGATED: "#4EA5FF", NOT_IMPACTED: "#44494B"}
# Tiles for verdicts today's Tenable data cannot produce show only when something lands there.
HIDE_WHEN_ZERO = {IMPACTED, MITIGATED}

FIELDS = ["asset_id", "asset", "ip", "fqdn", "os", "arch", "cpu_model", "virtualization",
          "java_vendor", "vendor_confidence", "java_version_raw", "java_path", "java_binary",
          "managed_by_os", "detection_plugin", "cve_plugins", "asset_cve_plugins", "cmdline_flags",
          "last_seen", "truncated", "no_output", "version_conflict"]
DERIVED = ["r", "r_evidence", "a", "a_evidence", "c", "c_evidence", "j", "j_evidence",
           "verdict", "reason", "confidence", "priority", "fixed_version"]

# HTML table: (row key, header). Columns no row fills are dropped; the CSV keeps them.
COLUMNS = [("asset", "Asset"), ("ip", "IP"), ("java_version_raw", "Java"), ("java_vendor", "Vendor"),
           ("java_path", "Path"), ("verdict", "Verdict"), ("reason", "Reason"), ("r", "R"), ("a", "A"),
           ("c", "C"), ("j", "J"), ("confidence", "Confidence"), ("priority", "Priority"),
           ("fixed_version", "Fix")]
NOWRAP = {"ip", "java_version_raw", "confidence", "fixed_version"}
CONDITIONS = {"r", "a", "c", "j"}
# Priority is a triage hint for rows that still need action.
PRIORITY_VERDICTS = {IMPACTED, AFFECTED_CPU_UNCONFIRMED, UNKNOWN_VERIFY}
ASSETS = Path(__file__).resolve().parent / "assets"


def text(value: object) -> str:
    """A findings value as display text: lists joined, booleans as yes/no, None blank."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (list, tuple)):
        return ", ".join(text(v) for v in value if text(v))
    return str(value)


def host_evidence(row: dict) -> HostEvidence | None:
    """Host facts Tenable reported for a row. Today that is only the process list's -XX options."""
    flags = row.get("cmdline_flags")
    if not isinstance(flags, list):
        return None
    flags = tuple(str(f) for f in flags if isinstance(f, str) and f.strip())
    if not flags:
        return None
    return HostEvidence(
        cpu_flags=None, cpu_source="", runtime_version=None, os_arch=None,
        default_flags=None, live_flags=None, live_skip_reason="",
        cmdline_flags=flags, collected_at="", stale=False,
    )


def enrich(rows: list[dict], overrides: dict) -> list[dict]:
    """Assess every row. Returns new dicts sorted worst verdict first."""
    out = []
    for row in rows:
        host = host_evidence(row)
        r, fixed = assess_runtime(row, overrides, None)
        a = assess_arch(row, host)
        c = assess_cpu(row, host)
        j = assess_flags(row, host)
        verdict, reason = decide(r, a, c, j)
        if verdict == UNKNOWN_VERIFY and r.value == "unknown" and (
                held_evidence(row) or text(row.get("version_conflict")).strip()):
            # A row that stands in for unread installs names why, rather than listing unknowns.
            reason = r.evidence
        item = dict(row)
        item.update({
            "r": r.value, "r_evidence": r.evidence,
            "a": a.value, "a_evidence": a.evidence,
            "c": c.value, "c_evidence": c.evidence,
            "j": j.value, "j_evidence": j.evidence,
            "verdict": verdict, "reason": reason,
            "confidence": confidence(r, a, c, j, host),
            "priority": priority(row) if verdict in PRIORITY_VERDICTS else "",
            "fixed_version": fixed,
        })
        out.append(item)
    _lift_contradicted(out)
    out.sort(key=lambda r: (ORDER.index(r["verdict"]), r["priority"] == "", text(r.get("asset"))))
    return out


# Oracle's CSPU plugin checks the version only and also covers other Oracle flaws on Java 8 and 11,
# so it contradicts a clear only on an Oracle install on line 17 or later.
ORACLE_CSPU = "382091"


def _plugins(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(p).strip() for p in value if str(p).strip()]


def _contradicting_plugin(rows: list[dict]) -> str:
    """The first CVE plugin hit on an asset that a Not impacted verdict cannot stand against, or ""."""
    hits: list[str] = []
    for r in rows:
        found = _plugins(r.get("asset_cve_plugins")) if "asset_cve_plugins" in r else _plugins(r.get("cve_plugins"))
        hits.extend(p for p in found if p not in hits)
    oracle_17_plus = any(
        normalize_vendor(text(r.get("java_vendor")), text(r.get("java_path")), text(r.get("java_version_raw"))) == "oracle"
        and (java_line(r) or 0) >= 17
        for r in rows)
    for plugin in hits:
        if plugin != ORACLE_CSPU or oracle_17_plus:
            return plugin
    return ""


def _lift_contradicted(rows: list[dict]) -> None:
    """Raise every row of a cleared asset to Unknown - verify when a Tenable CVE plugin flags it."""
    by_asset: dict = {}
    for r in rows:
        by_asset.setdefault(asset_key(r), []).append(r)
    for mine in by_asset.values():
        if any(r["verdict"] != NOT_IMPACTED for r in mine):
            continue
        plugin = _contradicting_plugin(mine)
        if not plugin:
            continue
        for r in mine:
            r["verdict"] = UNKNOWN_VERIFY
            r["reason"] = f"Tenable plugin {plugin} flags this asset"
            r["priority"] = priority(r)


def asset_rollup(rows: list[dict]) -> Counter:
    """Worst verdict per asset."""
    worst: dict = {}
    for r in rows:
        key = asset_key(r)
        if key not in worst or ORDER.index(r["verdict"]) < ORDER.index(worst[key]):
            worst[key] = r["verdict"]
    return Counter(worst.values())


# A spreadsheet reads a cell that starts with one of these as a formula.
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def csv_cell(value: object) -> str:
    """A findings value as CSV text, quoted with a leading ' when it would read as a formula."""
    cell = text(value)
    return "'" + cell if cell.startswith(_FORMULA_START) else cell


def write_csv(rows: list[dict], path: Path) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS + DERIVED, extrasaction="ignore")
        w.writeheader()
        w.writerows({k: csv_cell(r.get(k)) for k in FIELDS + DERIVED} for r in rows)


def _display(row: dict, key: str) -> str:
    if key == "asset":
        return text(row.get("asset")) or text(row.get("fqdn")) or text(row.get("asset_id"))
    if key == "java_path":
        return text(row.get("java_path")) or text(row.get("java_binary"))
    return text(row.get(key))


def _cell(row: dict, key: str) -> str:
    v = html.escape(_display(row, key))
    if key == "verdict":
        return (f'<td><span class="status" style="--c:{COLORS[row["verdict"]]}">'
                f'<span class="swatch"></span>{v}</span></td>')
    if key in CONDITIONS:
        evidence = html.escape(text(row.get(f"{key}_evidence")), quote=True)
        return f'<td class="cond {v}" title="{evidence}">{v}</td>'
    if key == "reason":
        return f'<td class="reason">{v}</td>'
    if key == "java_path":
        return f'<td class="path">{v}</td>'
    return f'<td class="nowrap">{v}</td>' if key in NOWRAP else f"<td>{v}</td>"


def _installs(n: int) -> str:
    return f"{n} Java install" + ("" if n == 1 else "s")


def write_html(rows: list[dict], path: Path, generated: str) -> None:
    counts = asset_rollup(rows)
    pairs = Counter(r["verdict"] for r in rows)
    tiles = "".join(
        f'<div class="tile clip-corner" style="--c:{COLORS[s]}"><b>{counts.get(s, 0)}</b>'
        f'<span class="caption">{html.escape(s)}</span>'
        f'<span class="pairs">{_installs(pairs.get(s, 0))}</span></div>'
        for s in ORDER if counts.get(s, 0) > 0 or s not in HIDE_WHEN_ZERO)
    cols = [(k, label) for k, label in COLUMNS if any(_display(r, k) for r in rows)] or [
        (k, label) for k, label in COLUMNS if k in ("asset", "ip", "java_version_raw", "verdict")]
    thead = "".join(f"<th>{label}</th>" for _, label in cols)
    tbody = "".join("<tr>" + "".join(_cell(r, k) for k, _ in cols) + "</tr>" for r in rows) or (
        f'<tr><td class="empty" colspan="{len(cols)}">No Java installs returned by Tenable.</td></tr>')
    lockup = (ASSETS / "tenable-lockup.svg").read_text(encoding="utf-8")
    doc = Template((ASSETS / "report.html").read_text(encoding="utf-8")).substitute(
        font=b64(ASSETS / "WorkSans-latin.woff2"),
        lockup_white=base64.b64encode(lockup.encode()).decode(),
        lockup_dark=base64.b64encode(lockup.replace("fill: #fff", "fill: #1E2426").encode()).decode(),
        iris=b64(ASSETS / "tenable-iris.png"),
        generated=html.escape(generated), row_count=len(rows), asset_count=sum(counts.values()),
        fixed_as_of=FIXED_AS_OF, tiles=tiles, thead=thead, tbody=tbody, faq=FAQ, java_report=JAVA_REPORT)
    path.write_text(doc, encoding="utf-8")


def b64(path: Path) -> str:
    return base64.b64encode(path.read_bytes()).decode()


def find_chrome() -> str | None:
    mac = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
    if mac.exists():
        return str(mac)
    for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "msedge"):
        if shutil.which(name):
            return shutil.which(name)
    return None


def write_pdf(html_path: Path, pdf_path: Path) -> bool:
    chrome = find_chrome()
    if not chrome:
        print("WARN: no Chrome/Chromium found; PDF skipped. Print report.html to PDF manually.")
        return False
    profile = tempfile.mkdtemp(prefix=".chrome-", dir=pdf_path.parent)
    try:
        subprocess.run([chrome, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
                        f"--user-data-dir={profile}", f"--print-to-pdf={pdf_path}",
                        html_path.resolve().as_uri()],
                       check=True, capture_output=True, timeout=120)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
        # The CSV and HTML are already written, so keep going to the file list.
        print(f"WARN: Chrome failed ({e}); PDF skipped. Print report.html to PDF manually.")
        return False
    finally:
        shutil.rmtree(profile, ignore_errors=True)
    return pdf_path.exists()


def load_run(findings: Path) -> tuple[list[dict], list[str]]:
    """Read findings.json and fixed.json next to it. Returns (enriched rows, warnings)."""
    rows = json.loads(findings.read_text(encoding="utf-8"))
    if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
        sys.exit(f"{findings}: expected a JSON list of objects")
    run = findings.resolve().parent
    overrides, warnings = load_overrides(run / "fixed.json")
    return enrich(rows, overrides), list(dict.fromkeys(warnings))


def main(argv: list[str] | None = None) -> None:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        sys.exit(__doc__)
    now = datetime.now(timezone.utc)
    rows, warnings = load_run(Path(args[0]))
    out = Path(args[1])
    out.mkdir(parents=True, exist_ok=True)
    write_csv(rows, out / "report.csv")
    write_html(rows, out / "report.html", now.strftime("%Y-%m-%d %H:%M UTC"))

    counts = asset_rollup(rows)
    pairs = Counter(r["verdict"] for r in rows)
    print(f"pairs={len(rows)} assets={sum(counts.values())}")
    for s in ORDER:
        print(f"  {s}: {counts.get(s, 0)} assets ({pairs.get(s, 0)} pairs)")
    print(f"fixed builds as of {FIXED_AS_OF}")
    for w in warnings:
        print(f"WARN: {w}")
    # write_pdf prints its own WARN line, so it runs after the others and before the file list.
    pdf_ok = write_pdf(out / "report.html", out / "report.pdf")
    for name in ("report.csv", "report.html") + (("report.pdf",) if pdf_ok else ()):
        print(out / name)


if __name__ == "__main__":
    main()
