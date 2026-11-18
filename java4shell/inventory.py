"""Parse Tenable plugin outputs into Java install rows and per-asset context.

Java detection outputs are free text. Each install is a block that starts at a ``Path`` line and
holds ``Label : value`` lines. Values can wrap onto deeper-indented lines, optional labels can be
missing, and a long output may be cut off with a trailing ``(truncated)`` marker. The value on the
last line before the cut may itself be incomplete, so it is dropped. A cut can also hide later
installs, so a cut-off output adds one blank row for its asset and plugin unless its
``Nessus detected N installs of Java`` header shows that every install was read.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Iterable, Optional

from .paths import normalize_binary
from .versions import _vendor_from_name, normalize_vendor, versions_agree

# Order matters: it is the order plugin IDs are listed in a merged row's detection_plugin.
JAVA_PLUGIN_ORDER = (
    "147817", "148499", "148373", "148707", "64815", "33545", "169699", "148374",
    "148376", "148375", "148372", "171539", "148706", "148708", "148705", "148709",
)
JAVA_PLUGINS = set(JAVA_PLUGIN_ORDER)
# The Java Detection and Identification plugins look for every vendor. A complete output from one of
# them accounts for every install on the asset; a vendor plugin only accounts for its own vendor.
UNIFIED_PLUGINS = {"147817", "148499"}
# Vendor implied by a vendor-specific detection plugin, used when its output has no Application line.
# Names follow each plugin's public page (https://www.tenable.com/plugins/nessus/<id>). The generic
# Java Detection and Identification plugins (147817, 148499) imply no vendor.
VENDOR_BY_PLUGIN = {
    "64815": "Oracle Java", "33545": "Oracle Java",
    "148373": "OpenJDK Java", "148707": "OpenJDK Java",
    "169699": "Temurin Java", "171539": "Temurin Java",
    "148374": "Azul Zulu Java", "148706": "Azul Zulu Java",
    "148376": "Amazon Corretto Java", "148708": "Amazon Corretto Java",
    "148375": "AdoptOpenJDK Java", "148705": "AdoptOpenJDK Java",
    "148372": "IBM Java", "148709": "IBM Java",
}
CONTEXT_PLUGINS = {"45432": "cpu", "48942": "arch", "11936": "os", "20094": "vmware", "35081": "xen",
                   "110483": "processes", "asset_info": "asset_info"}

# Which installs a CVE plugin can speak for. A plugin ID not listed here applies to every install.
_ALAS = ("382312", "382347", "382319", "382332", "382309")
CVE_PLUGIN_SCOPE = {"382091": "oracle", "382045": "corretto", "382489": "os"}
CVE_PLUGIN_SCOPE.update({pid: "corretto" for pid in _ALAS})


def _cve_applies(plugin: str, row: dict) -> bool:
    scope = CVE_PLUGIN_SCOPE.get(plugin)
    if scope is None:
        return True
    managed = row.get("managed_by_os") is True
    if scope == "os":
        return managed
    vendor = normalize_vendor(row.get("java_vendor") or "", row.get("java_path") or "",
                              row.get("java_version_raw") or "")
    if scope == "oracle":
        return vendor in ("oracle", "oracle-epp")
    return vendor == "corretto" or managed


def cve_by_asset(cve_findings: Iterable[dict]) -> dict[str, list[str]]:
    """CVE plugin IDs per asset ID, in first-seen order. FIXED findings and findings with no asset ID
    are left out; every other state counts."""
    cve: dict[str, list[str]] = {}
    for finding in cve_findings or []:
        if not isinstance(finding, dict):
            continue
        if str(finding.get("state") or "").strip().upper() == "FIXED":
            continue
        asset_id = str(finding.get("asset_id") or "").strip()
        pid = str(finding.get("plugin_id") or "").strip()
        if not asset_id or not pid:
            continue
        plugins = cve.setdefault(asset_id, [])
        if pid not in plugins:
            plugins.append(pid)
    return cve


_LABELS = {
    "path": "path",
    "version": "version",
    "application": "application",
    "binary location": "binary",
    "details": "details",
    "detection method": "method",
    "managed by os": "managed",
}
_FIELD = re.compile(r"^\s*([A-Za-z][A-Za-z ]*?)\s*:\s*(.*?)\s*$")
_CONFIDENCE = re.compile(r"\(\s*(high|low)\s+confidence\s*\)", re.IGNORECASE)
_TRUNCATED = re.compile(r"^\s*\.\.\.\s*\(truncated\)\s*$")
_VERSION_LINE = re.compile(r"^\s*Version\s*:\s*(.+?)\s*$", re.IGNORECASE)
_ARCH_LINE = re.compile(r"^\s*Architecture\s*[:=]\s*(.+?)\s*$", re.IGNORECASE)
_OS_LINE = re.compile(r"^\s*Remote operating system\s*:\s*(.+?)\s*$", re.IGNORECASE)
# An asset record's OS line, e.g. "Operating System: Linux Kernel 5.14.0-362.el9.x86_64 on Rocky Linux 9".
_OS_INFO_LINE = re.compile(r"^\s*Operating System\s*:\s*(.+?)\s*$", re.IGNORECASE)
# Architecture tokens in an OS string count only between separators (el9.x86_64, 6.1.0-18-arm64),
# never inside a word.
_OS_ARCH_TOKENS = (("x64", ("x86_64", "amd64")), ("arm64", ("aarch64", "arm64")),
                   ("x86", ("i686", "i586", "i486", "i386")))
_OS_ARCH_EDGE = r"[\s.\-_/(),;]"
_INSTALL_COUNT = re.compile(r"Nessus detected (\d+) installs? of Java", re.IGNORECASE)

_INSTALL_STRING_KEYS = ("java_path", "java_version_raw", "java_vendor", "java_binary", "vendor_confidence")


def _parse_time(value: object) -> Optional[datetime]:
    """An ISO 8601 time as an aware datetime (UTC when no offset is given), or None."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _field(line: str) -> Optional[tuple[str, str]]:
    """Return (known key, value) when the line starts a known ``Label : value`` field."""
    m = _FIELD.match(line)
    if not m:
        return None
    key = _LABELS.get(m.group(1).strip().lower())
    return (key, m.group(2)) if key else None


def _blank_install() -> dict:
    return {"java_path": "", "java_version_raw": "", "java_vendor": "", "java_binary": "",
            "vendor_confidence": "", "managed_by_os": None, "truncated": False}


def _finish(block: dict) -> dict:
    install = _blank_install()
    install["java_path"] = block["path"]
    install["java_version_raw"] = block["version"]
    install["java_vendor"] = block["application"]
    install["java_binary"] = block["binary"][0] if block["binary"] else ""
    m = _CONFIDENCE.search(" ".join(block["details"]))
    install["vendor_confidence"] = m.group(1).lower() if m else ""
    managed = block["managed"].strip().lower()
    install["managed_by_os"] = True if managed == "true" else False if managed == "false" else None
    return install


def is_truncated(output: str) -> bool:
    """True when the output carries the trailing truncation marker."""
    if not isinstance(output, str):
        return False
    return output.rstrip().endswith("(truncated)") or any(_TRUNCATED.match(l) for l in output.splitlines())


def install_count(output: str) -> Optional[int]:
    """The install count announced by a multi-install output's header, or None when there is none."""
    m = _INSTALL_COUNT.search(output) if isinstance(output, str) else None
    return int(m.group(1)) if m else None


def _blank_row(install: dict) -> bool:
    return not (install["java_path"] or install["java_binary"] or install["java_version_raw"])


def parse_java_detection(output: str) -> list[dict]:
    """Return one dict per install found in a Java detection plugin output."""
    if not isinstance(output, str) or not output.strip():
        return []
    truncated = is_truncated(output)

    blocks: list[dict] = []
    current: Optional[dict] = None
    last_key = ""
    # What the latest non-blank line wrote: (block, key, whether it appended to a list).
    last_write: Optional[tuple[dict, str, bool]] = None
    cut_at: Optional[tuple[dict, str, bool]] = None
    for line in output.splitlines():
        if _TRUNCATED.match(line):
            if cut_at is None:
                cut_at = last_write or ({}, "", False)
            continue
        if not line.strip():
            continue
        field = _field(line)
        if field and field[0] == "path":
            current = {"path": field[1], "version": "", "application": "", "binary": [],
                       "details": [], "managed": "", "method": ""}
            blocks.append(current)
            last_key = "path"
            last_write = (current, "path", False)
            continue
        if current is None:
            last_write = None
            continue
        last_write = (current, "", False)
        if field:
            key, value = field
            last_key = key
            if key in ("binary", "details"):
                if value or key == "details":
                    current[key].append(value)
                    last_write = (current, key, True)
            elif key in current:
                current[key] = value
                last_write = (current, key, False)
        else:
            # A wrapped continuation line; only multi-line fields keep it.
            if last_key in ("binary", "details"):
                current[last_key].append(line.strip())
                last_write = (current, last_key, True)
    if truncated and cut_at is None:
        # The marker sits at the end of a value line rather than on its own line.
        cut_at = last_write
    if cut_at is not None:
        block, key, appended = cut_at
        if key and appended:
            block[key].pop()
        elif key:
            block[key] = ""

    installs = [_finish(b) for b in blocks]
    if truncated and installs:
        installs[-1]["truncated"] = True
    return installs


def parse_cpu_models(output: str) -> list[str]:
    """CPU model strings, one per ``Version`` line, in output order."""
    models = []
    for line in (output or "").splitlines():
        m = _VERSION_LINE.match(line)
        if m:
            models.append(m.group(1))
    return models


def parse_windows_arch(output: str) -> str:
    for line in (output or "").splitlines():
        m = _ARCH_LINE.match(line)
        if m:
            return m.group(1)
    return ""


def parse_asset_info(output: str) -> tuple[str, str]:
    """(OS string, architecture) from an asset record. The architecture is x64, arm64 or x86 when the
    OS string names exactly one, else ""."""
    os_name = ""
    for line in (output or "").splitlines():
        m = _OS_INFO_LINE.match(line)
        if m:
            os_name = m.group(1)
            break
    if os_name.upper() in ("N/A", "NA", "UNKNOWN"):
        os_name = ""
    found = set()
    for arch, tokens in _OS_ARCH_TOKENS:
        for token in tokens:
            if re.search(rf"(?:^|{_OS_ARCH_EDGE}){token}(?:$|{_OS_ARCH_EDGE})", os_name, re.IGNORECASE):
                found.add(arch)
    return os_name, (found.pop() if len(found) == 1 else "")


def parse_os(output: str) -> str:
    for line in (output or "").splitlines():
        m = _OS_LINE.match(line)
        if m:
            return m.group(1)
    return ""


# JVM launcher options that take their value as the next argument.
_JAVA_VALUE_OPTIONS = {
    "-cp", "-classpath", "--class-path", "-p", "--module-path", "--upgrade-module-path",
    "--add-modules", "--limit-modules", "--add-reads", "--add-exports", "--add-opens",
    "--patch-module", "--enable-native-access",
}
# Options after which the remaining arguments belong to the application.
_JAVA_MAIN_OPTIONS = {"-jar", "-m", "--module"}


def _jvm_xx_options(args: list[str]) -> list[str]:
    """The -XX options among a java launcher's own arguments (before the main class or jar)."""
    found: list[str] = []
    skip = False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg in _JAVA_MAIN_OPTIONS or not arg.startswith("-"):
            break
        if arg in _JAVA_VALUE_OPTIONS:
            skip = True
        elif arg.startswith("-XX:") and arg not in found:
            found.append(arg)
    return found


def parse_process_list(output: str) -> dict[str, tuple[str, ...]]:
    """Map each java binary in a ``ps auxww`` style listing to the -XX options it was started with.

    Keys are ``normalize_binary`` install roots. Only commands that name a java binary by its
    path count: a bare ``java`` found on PATH cannot be tied to an install. Options from several
    processes of the same binary are combined, in first-seen order.
    """
    flags: dict[str, list[str]] = {}
    for line in (output or "").splitlines():
        fields = line.split(None, 10)
        if len(fields) < 11 or not fields[1].isdigit():
            continue
        args = fields[10].split()
        exe = args[0]
        if "/" not in exe or exe.rsplit("/", 1)[1] != "java":
            continue
        key = normalize_binary(exe)
        if not key:
            continue
        seen = flags.setdefault(key, [])
        seen.extend(f for f in _jvm_xx_options(args[1:]) if f not in seen)
    return {key: tuple(value) for key, value in flags.items()}


# ---------------------------------------------------------------- findings builder

def has_identity(record: dict) -> bool:
    """True when a record names its asset by asset ID, name or IP."""
    return any(str(record.get(k) or "").strip() for k in ("asset_id", "asset", "ip"))


def asset_key(record: dict) -> str:
    """Identity of the asset a record belongs to: its asset ID, else name plus IP."""
    asset_id = str(record.get("asset_id") or "").strip()
    if asset_id:
        return asset_id
    name = str(record.get("asset") or record.get("fqdn") or "").strip().lower()
    return f"{name}|{str(record.get('ip') or '').strip()}"


def _plugin_id(record: dict) -> str:
    return str(record.get("plugin_id") or "").strip()


def newest_java_detection(outputs: Iterable[dict]) -> dict[str, datetime]:
    """Newest parseable ``last_seen`` among Java detection records, per asset key."""
    newest: dict[str, datetime] = {}
    for record in outputs:
        if _plugin_id(record) not in JAVA_PLUGINS:
            continue
        seen = _parse_time(record.get("last_seen"))
        key = asset_key(record)
        if seen is not None and (key not in newest or seen > newest[key]):
            newest[key] = seen
    return newest


def _newer(a: str, b: str) -> str:
    ta, tb = _parse_time(a), _parse_time(b)
    if ta is None:
        return b or a
    if tb is None:
        return a
    return b if tb > ta else a


def _install_key(install: dict) -> str:
    return normalize_binary(install["java_binary"] or install["java_path"])


def _merge_candidates(candidates: list[dict]) -> dict:
    """Collapse the same install reported by several plugins into one row's fields."""
    ranked = sorted(candidates, key=lambda c: (c["install"]["vendor_confidence"] != "high",
                                               c["install"]["truncated"],
                                               JAVA_PLUGIN_ORDER.index(c["plugin"])
                                               if c["plugin"] in JAVA_PLUGINS else len(JAVA_PLUGIN_ORDER)))
    merged = dict(ranked[0]["install"])
    for other in ranked[1:]:
        for key in _INSTALL_STRING_KEYS:
            if not merged[key]:
                merged[key] = other["install"][key]
        if merged["managed_by_os"] is None:
            merged["managed_by_os"] = other["install"]["managed_by_os"]
    if not merged["java_vendor"]:
        # No Application line anywhere: a vendor-specific detection plugin still names the vendor.
        # A different vendor named in the path (GraalVM, Semeru, Azul Prime and so on) wins: the
        # application name is read before the path, so a plugin vendor there would hide it.
        path_vendor = _vendor_from_name(f'{merged["java_path"]} {merged["java_binary"]}'.lower())
        for c in ranked:
            name = VENDOR_BY_PLUGIN.get(c["plugin"])
            if name:
                if path_vendor is None or path_vendor == _vendor_from_name(name.lower()):
                    merged["java_vendor"] = name
                break
    # Plugins that read different releases for the same install are not settled by plugin rank.
    vendor = normalize_vendor(merged["java_vendor"], merged["java_path"])
    reported: list[str] = []
    for c in ranked:
        raw = c["install"]["java_version_raw"].strip()
        if raw and raw not in reported:
            reported.append(raw)
    clash = [raw for raw in reported if not all(versions_agree(raw, other, vendor) for other in reported)]
    merged["version_conflict"] = " vs ".join(clash)
    if clash:
        merged["java_version_raw"] = ""
    flags = [c["install"]["truncated"] for c in candidates]
    merged["truncated"] = all(flags)
    plugins = {c["plugin"] for c in candidates}
    merged["detection_plugin"] = ",".join(p for p in JAVA_PLUGIN_ORDER if p in plugins)
    merged["plugin_output"] = ranked[0]["output"]
    last_seen = ""
    for c in candidates:
        last_seen = _newer(last_seen, c["last_seen"]) if last_seen else c["last_seen"]
    merged["last_seen"] = last_seen
    return merged


def _blank_context() -> dict:
    return {"cpu": [], "arch": "", "info_arch": "", "os": "", "virt": "", "processes": {}}


def build_findings(outputs: Iterable[dict], cve_findings: list[dict]) -> list[dict]:
    """One row per (asset, install). See the module docstring for the output layout."""
    meta: dict[str, dict] = {}
    context: dict[str, dict] = {}
    entries: dict[tuple, list[dict]] = {}
    # (asset, plugin) pairs where the plugin's output gave at least one install.
    parsed_by: set[tuple[str, str]] = set()
    # Assets with a complete (not cut off) unified detection output.
    complete: set[str] = set()

    for record in outputs:
        plugin = _plugin_id(record)
        if plugin not in JAVA_PLUGINS and plugin not in CONTEXT_PLUGINS:
            continue
        if not has_identity(record):
            # With no asset ID, name or IP, the record could merge into any other such record.
            continue
        akey = asset_key(record)
        info = meta.setdefault(akey, {"asset_id": "", "asset": "", "ip": "", "fqdn": ""})
        for field in info:
            if not info[field]:
                info[field] = str(record.get(field) or "").strip()
        output = record.get("output")
        output = output if isinstance(output, str) else ""
        last_seen = str(record.get("last_seen") or "")

        if plugin in CONTEXT_PLUGINS:
            ctx = context.setdefault(akey, _blank_context())
            kind = CONTEXT_PLUGINS[plugin]
            if kind == "cpu":
                ctx["cpu"] += [m for m in parse_cpu_models(output) if m not in ctx["cpu"]]
            elif kind == "arch":
                ctx["arch"] = ctx["arch"] or parse_windows_arch(output)
            elif kind == "os":
                ctx["os"] = ctx["os"] or parse_os(output)
            elif kind == "asset_info":
                os_name, arch = parse_asset_info(output)
                ctx["os"] = ctx["os"] or os_name
                # Kept apart so the Windows architecture plugin wins whatever the record order.
                ctx["info_arch"] = ctx["info_arch"] or arch
            elif kind == "vmware":
                ctx["virt"] = "VMware"
            elif kind == "xen":
                ctx["virt"] = ctx["virt"] or "Xen"
            elif kind == "processes":
                for binary, options in parse_process_list(output).items():
                    held = ctx["processes"].setdefault(binary, [])
                    held.extend(o for o in options if o not in held)
            continue

        found = 0
        installs = parse_java_detection(output)
        if installs:
            parsed_by.add((akey, plugin))
            if plugin in UNIFIED_PLUGINS and not is_truncated(output):
                complete.add(akey)
        for install in installs:
            key = _install_key(install)
            # An install with no usable path (cut off early) is kept as its own row, never merged.
            entry = ("install", akey, key) if key else ("unkeyed", akey, plugin, len(entries))
            entries.setdefault(entry, []).append(
                {"install": install, "plugin": plugin, "output": output, "last_seen": last_seen})
            found += 1
        if found and is_truncated(output) and not any(_blank_row(i) for i in installs):
            # The cut may have hidden later installs. Unless the header shows every announced install
            # was read, one row for this asset and plugin stands in for them. A blank row from a cut
            # inside an install already does that.
            announced = install_count(output)
            if announced is None or announced > found:
                blank = _blank_install()
                blank["truncated"] = True
                entries.setdefault(("cutoff", akey, plugin), []).append(
                    {"install": blank, "plugin": plugin, "output": output, "last_seen": last_seen})
        if not found:
            # Known to have the plugin, but nothing usable was parsed: no output at all, a cut-off
            # output, or text with no recognisable install. The asset must not drop out of the data.
            blank = _blank_install()
            blank["truncated"] = is_truncated(output)
            entries.setdefault(("placeholder", akey, plugin), []).append(
                {"install": blank, "plugin": plugin, "output": output, "last_seen": last_seen})

    # Every CVE hit on the asset is kept as asset_cve_plugins; cve_plugins holds the ones that can
    # speak for this install. Both are evidence; render.py lifts a cleared asset that one contradicts.
    cve = cve_by_asset(cve_findings)

    rows = []
    for entry, candidates in entries.items():
        kind, akey = entry[0], entry[1]
        # A placeholder stands for installs this plugin may have found but whose output is missing.
        # It goes only when the same plugin did report installs here, or a complete unified output did.
        if kind == "placeholder" and ((akey, entry[2]) in parsed_by or akey in complete):
            continue
        merged = _merge_candidates(candidates)
        if kind in ("placeholder", "cutoff"):
            merged["detection_plugin"] = candidates[0]["plugin"]
            merged["truncated"] = any(c["install"]["truncated"] for c in candidates)
        info = meta[akey]
        ctx = context.get(akey) or _blank_context()
        row = {
            "asset_id": info["asset_id"], "asset": info["asset"], "ip": info["ip"], "fqdn": info["fqdn"],
            "os": ctx["os"], "arch": ctx["arch"] or ctx["info_arch"], "cpu_model": ";".join(ctx["cpu"]),
            "virtualization": ctx["virt"],
            "java_vendor": merged["java_vendor"], "vendor_confidence": merged["vendor_confidence"],
            "java_version_raw": merged["java_version_raw"], "version_conflict": merged["version_conflict"],
            "java_path": merged["java_path"],
            "java_binary": merged["java_binary"], "managed_by_os": merged["managed_by_os"],
            "detection_plugin": merged["detection_plugin"],
            "cve_plugins": [], "asset_cve_plugins": list(cve.get(info["asset_id"], [])),
            "last_seen": merged["last_seen"], "plugin_output": merged["plugin_output"],
            "truncated": merged["truncated"],
            "no_output": kind == "placeholder" and not merged["truncated"],
        }
        row["cve_plugins"] = [p for p in row["asset_cve_plugins"] if _cve_applies(p, row)]
        # Command-line options are evidence only; they never settle J (see conditions.assess_flags).
        for key in (normalize_binary(merged["java_binary"]), normalize_binary(merged["java_path"])):
            if key and key in ctx["processes"]:
                row["cmdline_flags"] = list(ctx["processes"][key])
                break
        rows.append(row)
    return rows


# --- package findings coverage pass ------------------------------------------

# Java package tokens inside a finding name. Specific forms come first; bare vendor names and bare
# openjdk, jdk and jre are a fallback. Whole-token boundaries keep javascript, javamail, javassist
# and the like out.
JAVA_PACKAGE_RE = re.compile(
    r"(?<![a-z0-9])(?:"
    r"java-(?:1\.8\.0|\d+)-openjdk"
    r"|java-(?:1\.8\.0|\d+)-amazon-corretto"
    r"|openjdk-\d+-(?:jre(?:-headless)?|jdk)"
    r"|openjdk\d+"
    r"|temurin-\d+-(?:jdk|jre)"
    r"|amazon-corretto-\d+"
    r"|adoptopenjdk-\d+(?:-(?:hotspot|openj9))?(?:-(?:jdk|jre))?"
    r"|oracle-java\d+(?:-installer)?"
    r"|zulu\d+"
    r"|graalvm"
    r"|temurin|corretto|zulu|adoptopenjdk|semeru"
    r"|openjdk|jdk|jre"
    r")(?![a-z0-9])",
    re.IGNORECASE,
)
# Bare vendor names carry no line; the finding name may give one right after the name.
_BARE_VENDORS = ("temurin", "corretto", "zulu", "adoptopenjdk", "semeru")


def _package_vendor(token: str) -> str:
    if token.startswith("oracle-java"):
        return "Oracle Java"
    if "openj9" in token or token == "semeru":
        return "semeru"
    if token.startswith(("temurin", "adoptopenjdk")):
        return "temurin"
    if "corretto" in token:
        return "corretto"
    if token.startswith("zulu"):
        return "zulu"
    if token == "graalvm":
        return "graalvm"
    return "OpenJDK Java"


def _package_path(token: str, after: str) -> str:
    # The text after the token in the finding name may give a bare vendor name its line.
    if token in _BARE_VENDORS:
        m = re.match(r"[\s_-]*(\d{1,2})(?!\d)", after)
        if m:
            return f"package:{token}-{m.group(1)}"
    return f"package:{token}"


def _package_record(record: object, covered_asset_ids: set[str]) -> Optional[str]:
    """The asset key of a package finding that counts, or None (not a dict, FIXED, no identity, covered)."""
    if not isinstance(record, dict) or not has_identity(record):
        return None
    if str(record.get("state") or "").strip().upper() == "FIXED":
        return None
    akey = asset_key(record)
    return None if akey in covered_asset_ids else akey


def unmatched_package_findings(findings: list[dict], covered_asset_ids: set[str]) -> int:
    """Package findings on uncovered assets whose names match no Java package token."""
    return sum(1 for record in findings or []
               if _package_record(record, covered_asset_ids) is not None
               and not JAVA_PACKAGE_RE.search(str(record.get("name") or "")))


def package_rows(findings: list[dict], covered_asset_ids: set[str],
                 cve_findings: Optional[list[dict]] = None) -> list[dict]:
    """Rows for assets seen only through Java package findings (no detection plugin row).

    A finding record is {asset_id, asset, ip, fqdn, name, state, asset_class}. Every state except
    FIXED counts. One row per (asset, package token, line). The package name carries no version, so the
    row is judged by its Java line alone, and a line that needs a version comes out unknown.
    """
    rows: list[dict] = []
    seen: set[tuple[str, str]] = set()
    cve = cve_by_asset(cve_findings or [])
    for record in findings or []:
        akey = _package_record(record, covered_asset_ids)
        if akey is None:
            continue
        name = str(record.get("name") or "")
        asset_id = str(record.get("asset_id") or "").strip()
        for match in JAVA_PACKAGE_RE.finditer(name):
            token = match.group(0).lower()
            path = _package_path(token, name[match.end():])
            if (akey, path) in seen:
                continue
            seen.add((akey, path))
            row = {
                "asset_id": asset_id,
                "asset": str(record.get("asset") or "").strip(),
                "ip": str(record.get("ip") or "").strip(),
                "fqdn": str(record.get("fqdn") or "").strip(),
                "os": "", "arch": "", "cpu_model": "", "virtualization": "",
                "java_vendor": _package_vendor(token), "vendor_confidence": "",
                "java_version_raw": "", "version_conflict": "", "java_path": path, "java_binary": "",
                "managed_by_os": None, "detection_plugin": "package finding",
                "cve_plugins": [], "asset_cve_plugins": list(cve.get(asset_id, [])),
                "last_seen": "", "plugin_output": name,
                "truncated": False, "no_output": False,
            }
            row["cve_plugins"] = [p for p in row["asset_cve_plugins"] if _cve_applies(p, row)]
            rows.append(row)
    return rows
