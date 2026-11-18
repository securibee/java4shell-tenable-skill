"""Java version parsing and the runtime condition (R).

R answers one question for a Java install: is this runtime at a version that
carries the vulnerable code without the fix? The answer is "yes", "no" or
"unknown". Ambiguous input always lands on "unknown", never on "no".
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from pathlib import Path

from java4shell.model import NO, UNKNOWN, YES, Condition

FIXED_AS_OF = "2026-11-18"

# First fixed release per supported line, as (line, minor, security, patch).
FIXED = {17: (17, 0, 21, 1), 21: (21, 0, 13, 1), 25: (25, 0, 5, 1), 27: (27, 0, 1, 1)}

# Oracle Java 8 Enterprise Performance Pack: first fixed update number.
EPP_FIXED_UPDATE = 513

# Azul Zulu product numbers: first fixed (minor, security) per line.
ZULU_FIXED = {17: (70, 201), 21: (54, 201), 25: (38, 201), 27: (30, 201)}

# Azul Prime streams (year, month) and their first fixed release.
PRIME_FIXED = {(26, 8): (26, 8, 110, 0), (26, 2): (26, 2, 510, 0)}

# Prime streams from this one onward are not covered by the tracked fixes.
PRIME_UNTRACKED_FROM = (26, 11)

# Lines that carry the vulnerable code and will not receive a fix.
NO_FIX_LINES = {18, 19, 20, 22, 23, 24, 26}

# Line 17 releases before this security update predate the vulnerable code.
LINE_17_FIRST_AFFECTED = 6

MIN_LINE = 8
# Java 6 and 7 predate the vulnerable code. They are read from their own version forms
# (1.7.0_72, 7u72), never from an install path alone. A dotted 7.0.72 is read only when
# something corroborates it (see parse_java_version's legacy_ok).
LEGACY_LINES = (6, 7)
MAX_LINE = 40
MAX_TRACKED_LINE = 27

VENDORS = (
    "oracle", "oracle-epp", "openjdk", "temurin", "zulu", "prime", "corretto",
    "microsoft", "liberica", "sapmachine", "redhat", "graalvm", "semeru", "unknown",
)

# Vendors whose R is never computed from a fixed version, so a fixed-version
# override would have no effect on them.
_NO_FIXED_COMPARE = {"prime", "graalvm", "semeru"}

_OVERRIDE_DISPUTED = "fixed build disputed (fixed.json)"
_BOUNDARY_AMBIGUOUS = "patch level ambiguous at fix boundary"


@dataclass(frozen=True)
class JavaVersion:
    line: int
    minor: int
    security: int
    patch: int | None
    build: int | None
    certain: bool  # True when the patch/build split is known
    raw: str


# --- parsing -----------------------------------------------------------------

_PARENS = re.compile(r"\([^)]*\)")
# Java 6 to 8 update form: 8u402, 8u402b06, 8u511b33-perf, 7u72.
_J8_UPDATE = re.compile(r"^([678])u(\d+)(?:-?b(\d+))?", re.IGNORECASE)
# Java 6 to 8 legacy form: 1.8.0, 1.8.0_402, 1.8.0_402-b06, 1.7.0_72, 1.6.0_45.
_J8_LEGACY = re.compile(r"^1\.([678])\.0(?:_(\d+))?(?:-b(\d+))?(?![\d.])", re.IGNORECASE)
# Dotted form with an optional "+build": 17.0.21, 17.0.21+9, 17.0.21.1+2.
_DOTTED = re.compile(r"^v?(\d+(?:\.\d+)*)(?:\+(\d+))?")


def _clean(raw: str) -> str:
    # Strip parenthesised annotations such as " (CA)" and surrounding space.
    # Trailing suffixes such as "-LTS" are ignored by the patterns below.
    return _PARENS.sub(" ", raw or "").strip()


def _dotted(text: str) -> tuple[list[int], int | None] | None:
    m = _DOTTED.match(text)
    if not m:
        return None
    parts = [int(p) for p in m.group(1).split(".")]
    plus = int(m.group(2)) if m.group(2) is not None else None
    return parts, plus


def parse_java_version(raw: str, vendor: str = "", legacy_ok: bool = False) -> JavaVersion | None:
    """Parse a reported Java version string. Return None when it is not a Java version.

    A dotted 6.x.y or 7.x.y string is too easily some other product's version, so it is read
    as Java only when legacy_ok says the vendor or install path backs it up.
    """
    text = _clean(raw)
    if not text:
        return None

    # Java 6 to 8: the security field is the update number. The patch concept
    # does not apply, so the split is treated as known.
    m = _J8_UPDATE.match(text)
    if m:
        build = int(m.group(3)) if m.group(3) else None
        return JavaVersion(int(m.group(1)), 0, int(m.group(2)), 0, build, True, raw)
    m = _J8_LEGACY.match(text)
    if m:
        update = int(m.group(2)) if m.group(2) else 0
        build = int(m.group(3)) if m.group(3) else None
        return JavaVersion(int(m.group(1)), 0, update, 0, build, True, raw)

    found = _dotted(text)
    if found is None:
        return None
    parts, plus = found
    # One or two numbers cannot identify a release.
    if len(parts) < 3:
        return None
    line, minor, security = parts[0], parts[1], parts[2]
    if line in LEGACY_LINES:
        # Dotted Java 6 or 7, e.g. 7.0.72: the third number is the update. Update
        # numbers stay below 1000, which keeps strings such as the Windows build
        # 6.0.6002.18005 from reading as Java 6.
        if not legacy_ok or minor != 0 or len(parts) > 4 or security >= 1000:
            return None
        return JavaVersion(line, minor, security, 0, plus, True, raw)
    if line < MIN_LINE or line > MAX_LINE:
        return None

    # The second number of a Java version is always 0. A non-zero second number
    # means the string is something else, such as an operating system release
    # (8.6.0), unless the vendor numbers its own products this way (Azul Zulu,
    # e.g. 25.36.15).
    if minor != 0:
        if vendor == "zulu" and security < 500:
            return JavaVersion(line, minor, security, None, None, True, raw)
        return None

    if line == 8:
        # Dotted Java 8, e.g. 8.0.402: the third number is the update. Java 8
        # update numbers run past 500, so only a four-digit one is rejected, like
        # the legacy lines above.
        if security >= 1000:
            return None
        return JavaVersion(8, minor, security, 0, plus, True, raw)

    # From Java 9 on, security updates stay far below 500. A larger third number
    # is an operating system build, e.g. 10.0.19045 or 10.0.17763.1234.
    if security >= 500:
        return None

    if len(parts) > 5:
        # A vendor build string such as 11.0.16.1.3.2207.12: only the first three
        # numbers are read, and the patch level is not known.
        return JavaVersion(line, minor, security, None, None, False, raw)

    if len(parts) == 3:
        # No patch field means patch 0. A "+" suffix is the build number.
        return JavaVersion(line, minor, security, 0, plus, True, raw)

    fourth = parts[3]
    if len(parts) == 4:
        if plus is not None:
            # a.b.c.d+e: d is the patch, e the build.
            return JavaVersion(line, minor, security, fourth, plus, True, raw)
        # a.b.c.d without "+": d may be a patch or a build number that was
        # appended in place of "+". The split is not known.
        return JavaVersion(line, minor, security, None, None, False, raw)

    # a.b.c.d.e: patch numbers are only 0 or 1, so d in {0, 1} is the patch
    # and e the build; a larger d is the build itself and the patch is 0.
    fifth = parts[4]
    if fourth in (0, 1):
        return JavaVersion(line, minor, security, fourth, fifth, True, raw)
    return JavaVersion(line, minor, security, 0, fourth, True, raw)


_PATH_LINE = re.compile(
    r"(?:jdk|jre|java|zulu|temurin|corretto|liberica|sapmachine|semeru)[-_]?(\d+)(?:\.(\d+))?",
    re.IGNORECASE,
)


def _path_lines(path: str) -> set[int]:
    # Every Java line (6 to MAX_LINE) the path names, e.g. java-21-openjdk, jdk-17.0.12, jre1.8.0_402.
    lines = set()
    for m in _PATH_LINE.finditer(path or ""):
        first = int(m.group(1))
        # Legacy names such as jre1.8.0 carry the line in the second number.
        if first == 1 and m.group(2) is not None:
            first = int(m.group(2))
        if first in LEGACY_LINES or MIN_LINE <= first <= MAX_LINE:
            lines.add(first)
    return lines


def line_from_path(path: str) -> int | None:
    """The Java line (8 or later) an install path names. None when it names none, or names
    more than one, as a parent directory can (/opt/java8-tools/jdk-21/)."""
    lines = _path_lines(path)
    if len(lines) != 1:
        return None
    (line,) = lines
    return line if line >= MIN_LINE else None


def _path_contradicts(path: str, line: int) -> bool:
    # A version contradicts its path when the path names any other Java line, even when the
    # path also names the version's own line (jdk-21/jre1.8.0_402 could be either install).
    return bool(_path_lines(path) - {line})


def legacy_line_from_path(path: str) -> int | None:
    """Java 6 or 7 named by an install path (jdk1.7.0_72, java-7-openjdk, jre6), else None."""
    lines = _path_lines(path)
    if len(lines) != 1:
        return None
    (line,) = lines
    return line if line in LEGACY_LINES else None


def _has(pattern: str, text: str) -> bool:
    return re.search(pattern, text) is not None


def _vendor_from_name(text: str) -> str | None:
    # More specific names are checked before the generic ones they contain
    # (for example "Oracle GraalVM" or "Microsoft Build of OpenJDK").
    if "graalvm" in text:
        return "graalvm"
    if ("azul" in text and "prime" in text) or _has(r"(?<![a-z])zing", text):
        return "prime"
    if "zulu" in text:
        return "zulu"
    if "semeru" in text or "openj9" in text or _has(r"(?<![a-z])ibm", text):
        return "semeru"
    if "temurin" in text or "adoptium" in text or "adoptopenjdk" in text:
        return "temurin"
    if "corretto" in text or "amazon" in text:
        return "corretto"
    if "microsoft" in text:
        return "microsoft"
    if "liberica" in text or "bellsoft" in text:
        return "liberica"
    if "sapmachine" in text:
        return "sapmachine"
    if "red hat" in text or "redhat" in text:
        return "redhat"
    if "oracle" in text:
        return "oracle"
    if "openjdk" in text:
        return "openjdk"
    return None


def normalize_vendor(application: str, path: str, version: str = "") -> str:
    """Map a reported application name, install path and version to a vendor key."""
    application = (application or "").lower()
    path = (path or "").lower()
    everything = f"{application} {path} {(version or '').lower()}"

    # A standalone "perf" marker in the name, path or version identifies the
    # Enterprise Performance Pack build. It is checked first: missing it would
    # turn a vulnerable build into a clear one, and directory names elsewhere
    # in the path must not hide it.
    if _has(r"(?<![a-z])perf(?![a-z])", everything):
        return "oracle-epp"

    # Azul Prime, GraalVM and Semeru (OpenJ9) are checked next, in the name and the path, so a
    # generic or low-confidence application name cannot hide them. They only ever make R more
    # cautious: none of them is cleared by the standard fixed-version table.
    both = f"{application} {path}"
    if any("azul" in t and "prime" in t for t in (application, path)) or _has(r"(?<![a-z])zing", both):
        return "prime"
    if "graalvm" in both:
        return "graalvm"
    if "semeru" in both or "openj9" in both:
        return "semeru"

    # Otherwise the application name is more reliable than the path, whose
    # parent directories can carry unrelated vendor names.
    for text in (application, path):
        vendor = _vendor_from_name(text)
        if vendor is not None:
            return vendor

    # Operating system package locations hold distribution OpenJDK builds.
    if "/usr/lib/jvm/" in path or "/usr/lib64/jvm/" in path:
        return "openjdk"
    return "unknown"


# --- comparison --------------------------------------------------------------

def _readings(v: JavaVersion) -> list[tuple]:
    # Every (line, minor, security, patch, build) a parsed version may stand for. None matches anything.
    head = (v.line, v.minor, v.security)
    if v.certain:
        return [head + (v.patch, v.build)]
    d = _fourth_field(v.raw)
    if d is None:
        return [head + (None, None)]
    return [head + (d, None), head + (0, d)]


def _match(a: tuple, b: tuple) -> bool:
    return all(x is None or y is None or x == y for x, y in zip(a, b))


def versions_agree(first: str, second: str, vendor: str = "") -> bool:
    """False when two reported version strings for one install name different releases.

    A string that is not a Java version, and a Zulu product number set against a Java version
    number, cannot be compared, so they never count as a disagreement.
    """
    a = parse_java_version(first, vendor, legacy_ok=True)
    b = parse_java_version(second, vendor, legacy_ok=True)
    if a is None or b is None:
        return True
    if a.line >= 9 and b.line >= 9 and (a.minor != 0) != (b.minor != 0):
        return True
    return any(_match(x, y) for x in _readings(a) for y in _readings(b))


def _fourth_field(raw: str) -> int | None:
    found = _dotted(_clean(raw))
    if found is None or len(found[0]) != 4:
        return None
    return found[0][3]


def below_fixed(v: JavaVersion, fixed: tuple[int, int, int, int]) -> bool | None:
    """True if v is below the fixed release, False if at or above, None if it cannot be told."""
    have = (v.line, v.minor, v.security)
    want = tuple(fixed[:3])
    if have < want:
        return True
    if have > want:
        return False
    fixed_patch = fixed[3]
    if fixed_patch == 0:
        return False
    if v.certain:
        if v.patch is None:
            return None
        return v.patch < fixed_patch
    # Same release, unknown split: the fourth number is either a patch or a
    # build. Patch numbers are small (0 or 1), so a larger value can only be a
    # build, which means patch 0. Collect every patch the value could stand
    # for and answer only when they all agree.
    d = _fourth_field(v.raw)
    if d is None:
        return None
    possible = {0}
    if d <= max(1, fixed_patch):
        possible.add(d)
    if all(p < fixed_patch for p in possible):
        return True
    if all(p >= fixed_patch for p in possible):
        return False
    return None


def _fmt(t: tuple[int, ...]) -> str:
    return ".".join(str(n) for n in t)


# --- overrides ---------------------------------------------------------------

def _parse_override_value(value: object) -> tuple[int, int, int, int] | None:
    if not isinstance(value, str):
        return None
    m = re.fullmatch(r"\s*(\d+)\.(\d+)\.(\d+)\.(\d+)\s*", value)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4)))


def load_overrides(path: Path) -> tuple[dict[tuple[str, int], tuple[int, int, int, int] | None], list[str]]:
    """Read fixed-version overrides: {vendor: {line: "a.b.c.d" | "unknown"}}.

    "unknown" forces R to unknown for that vendor and line. Invalid entries are
    skipped with a warning. A missing file means no overrides.
    """
    path = Path(path)
    overrides: dict[tuple[str, int], tuple[int, int, int, int] | None] = {}
    warnings: list[str] = []
    if not path.exists():
        return overrides, warnings
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError, TypeError) as exc:
        return {}, [f"{path.name}: could not be read ({type(exc).__name__}); using built-in fixed versions"]
    if not isinstance(data, dict):
        return {}, [f"{path.name}: top level must be an object; using built-in fixed versions"]

    for vendor, lines in data.items():
        if vendor not in VENDORS or vendor == "unknown":
            warnings.append(f"{path.name}: unknown vendor {vendor!r} ignored")
            continue
        if not isinstance(lines, dict):
            warnings.append(f"{path.name}: {vendor!r} must map line numbers to versions; ignored")
            continue
        for line_key, value in lines.items():
            key_text = str(line_key).strip()
            try:
                line = int(key_text) if key_text.isdecimal() else None
            except (ValueError, TypeError):
                line = None
            if line is None or not MIN_LINE <= line <= MAX_LINE:
                warnings.append(f"{path.name}: {vendor} line {line_key!r} is not a Java line; ignored")
                continue
            if isinstance(value, str) and value.strip().lower() == "unknown":
                overrides[(vendor, line)] = None
                continue
            parsed = _parse_override_value(value)
            if parsed is None or parsed[0] != line:
                warnings.append(f"{path.name}: {vendor} {line} value {value!r} is not a.b.c.d for line {line}; ignored")
                continue
            if parsed[1] != 0 and vendor != "zulu":
                warnings.append(f"{path.name}: {vendor} {line} value {value!r} is not a Java version; ignored")
                continue
            if vendor in _NO_FIXED_COMPARE:
                warnings.append(f"{path.name}: {vendor} is not assessed against a fixed version; only \"unknown\" applies; ignored")
                continue
            overrides[(vendor, line)] = parsed
    return overrides, warnings


# --- rule R ------------------------------------------------------------------

def _prime_product(raw: str) -> tuple[int, int, int, int] | None:
    # Prime product numbers are year.month.release.build, e.g. 26.08.110.0.
    found = _dotted(_clean(raw))
    if found is None:
        return None
    parts = found[0]
    if len(parts) < 2 or len(parts) > 5:
        return None
    year, month = parts[0], parts[1]
    if not 15 <= year <= 99 or not 1 <= month <= 12:
        return None
    padded = (parts + [0, 0])[:4]
    return (padded[0], padded[1], padded[2], padded[3])


def _prime_display(t: tuple[int, int, int, int]) -> str:
    return f"{t[0]}.{t[1]:02d}.{t[2]}.{t[3]}"


def _assess_prime(candidates: list[tuple[str, str]]) -> tuple[Condition, str]:
    # Prime is judged by its own product stream on every Java line.
    product = None
    used = ""
    prefix = ""
    for raw, source in candidates:
        product = _prime_product(raw)
        if product is not None:
            used, prefix = raw, source
            break
    every_fix = " or ".join(_prime_display(PRIME_FIXED[k]) for k in sorted(PRIME_FIXED))
    if product is None:
        return Condition(UNKNOWN, f"{prefix}Prime product version not determined"), ""
    stream = (product[0], product[1])
    if stream in PRIME_FIXED:
        fixed = PRIME_FIXED[stream]
        display = _prime_display(fixed)
        if product < fixed:
            return Condition(YES, f"{prefix}Prime {used} is below fixed {display}"), display
        return Condition(NO, f"{prefix}Prime {used} is at or above fixed {display}"), display
    if stream < PRIME_UNTRACKED_FROM:
        return Condition(YES, f"{prefix}Prime stream {stream[0]}.{stream[1]:02d} predates the fixed streams"), every_fix
    return Condition(UNKNOWN, f"{prefix}Prime stream {stream[0]}.{stream[1]:02d} is not in the tracked fixes"), ""


def _legacy_ok(vendor: str, application: str, path: str) -> bool:
    # A dotted Java 6 or 7 version counts only when an Oracle, Sun or IBM vendor, or a
    # Java 6 or 7 install path, backs it up.
    return (vendor in ("oracle", "oracle-epp", "semeru")
            or _has(r"(?<![a-z])sun(?![a-z])", application.lower())
            or legacy_line_from_path(path) is not None)


def held_evidence(row: dict) -> str:
    """Why a row holds no readable install, or "" for a row that describes one.

    Placeholder rows stand for installs a plugin found but whose details Tenable did not return:
    an output that was not retrieved, or one cut off before (some of) its installs.
    """
    plugin = str(row.get("detection_plugin") or "").strip() or "detection"
    if row.get("no_output") is True:
        if str(row.get("plugin_output") or "").strip():
            return f"plugin {plugin} output has no readable install"
        return f"plugin {plugin} output not retrieved"
    blank = not any(str(row.get(k) or "").strip() for k in ("java_path", "java_binary", "java_version_raw"))
    if row.get("truncated") is True and blank:
        return "installs cut off in plugin output"
    return ""


def _assess(row: dict, overrides: dict, host_runtime_version: str | None) -> tuple[Condition, str]:
    held = held_evidence(row)
    if held:
        return Condition(UNKNOWN, held), ""
    conflict = str(row.get("version_conflict") or "").strip()
    if conflict:
        return Condition(UNKNOWN, f"plugins disagree: {conflict}"), ""
    raw = str(row.get("java_version_raw") or "").strip()
    application = str(row.get("java_vendor") or "")
    path = str(row.get("java_path") or "")
    host = str(host_runtime_version or "").strip()
    vendor = normalize_vendor(application, path, f"{raw} {host}")

    if vendor == "prime":
        candidates = [(c, src) for c, src in ((host, "host-reported: "), (raw, "")) if c]
        return _assess_prime(candidates)

    legacy_ok = _legacy_ok(vendor, application, path)

    # A version read on the host itself replaces the inventory value.
    v = parse_java_version(host, vendor, legacy_ok) if host else None
    prefix = "host-reported: " if v is not None else ""
    if v is None:
        v = parse_java_version(raw, vendor, legacy_ok)

    # Corretto numbers its builds a.b.c.build.revision, so a five-part Corretto string at the fixed
    # release cannot be read as patch then build.
    if v is not None and vendor == "corretto":
        found = _dotted(_clean(v.raw))
        if found is not None and len(found[0]) == 5:
            v = replace(v, patch=None, build=None, certain=False)

    # The install path names a line too. When both are known they must agree.
    # When the version is unusable, the path line stands alone.
    path_line = line_from_path(path)
    if v is not None and _path_contradicts(path, v.line):
        return Condition(UNKNOWN, f"{prefix}version and path disagree"), ""
    line = v.line if v is not None else path_line
    if line is None:
        return Condition(UNKNOWN, f"{prefix}Java line not determined"), ""

    key = (vendor, line)
    if key in overrides and overrides[key] is None:
        return Condition(UNKNOWN, f"{prefix}{_OVERRIDE_DISPUTED}"), ""
    override = overrides.get(key)

    if line == 8 and vendor == "oracle-epp":
        fixed_update = override[2] if override else EPP_FIXED_UPDATE
        display = f"8u{fixed_update}-perf"
        if v is None:
            return Condition(UNKNOWN, f"{prefix}Performance Pack update not determined"), display
        if v.security < fixed_update:
            return Condition(YES, f"{prefix}{v.raw} is below fixed {display}"), display
        return Condition(NO, f"{prefix}{v.raw} is at or above fixed {display}"), display

    if line < 17:
        return Condition(NO, f"{prefix}Java {line}: standard build assumed; vulnerable code not present"), ""

    # GraalVM and Semeru (OpenJ9) have no tracked fix; only the line rule above can clear them.
    if vendor in ("graalvm", "semeru"):
        name = "GraalVM" if vendor == "graalvm" else "Semeru"
        return Condition(UNKNOWN, f"{prefix}{name}: fix status not determined for this distribution"), ""

    if line > MAX_TRACKED_LINE:
        return Condition(UNKNOWN, f"{prefix}Java {line}: newer than the tracked fixes"), ""

    if line in NO_FIX_LINES:
        return Condition(YES, f"{prefix}end of life, no fix"), "none (EOL)"

    java_fixed = override if override and override[1] == 0 else FIXED[line]
    java_display = _fmt(java_fixed)

    if v is None:
        return Condition(UNKNOWN, f"{prefix}Java {line}: version not reported; fix level cannot be checked"), java_display

    if vendor == "zulu" and v.minor != 0:
        # A Zulu product number: compare its own (minor, security) pair.
        zulu_fixed = (override[1], override[2]) if override and override[1] != 0 else ZULU_FIXED[line]
        display = f"{line}.{zulu_fixed[0]}.{zulu_fixed[1]}"
        if line == 17 and v.minor < 40:
            return Condition(UNKNOWN, f"{prefix}Zulu {v.raw}: product number not mapped to a Java update"), display
        if (v.minor, v.security) < zulu_fixed:
            return Condition(YES, f"{prefix}Zulu {v.raw} is below fixed {display}"), display
        return Condition(NO, f"{prefix}Zulu {v.raw} is at or above fixed {display}"), display

    if line == 17 and v.security < LINE_17_FIRST_AFFECTED:
        return Condition(NO, f"{prefix}Java 17 before 17.0.{LINE_17_FIRST_AFFECTED}: vulnerable code not present"), java_display

    result = below_fixed(v, java_fixed)
    if result is True:
        return Condition(YES, f"{prefix}{v.raw} is below fixed {java_display}"), java_display
    if result is False:
        return Condition(NO, f"{prefix}{v.raw} is at or above fixed {java_display}"), java_display
    return Condition(UNKNOWN, f"{prefix}{_BOUNDARY_AMBIGUOUS}"), java_display


def java_line(row: dict) -> int | None:
    """The Java line a row's version and path agree on, or None when it cannot be told."""
    if held_evidence(row) or str(row.get("version_conflict") or "").strip():
        return None
    raw = str(row.get("java_version_raw") or "").strip()
    application = str(row.get("java_vendor") or "")
    path = str(row.get("java_path") or "")
    vendor = normalize_vendor(application, path, raw)
    v = parse_java_version(raw, vendor, _legacy_ok(vendor, application, path))
    if v is not None and _path_contradicts(path, v.line):
        return None
    return v.line if v is not None else line_from_path(path)


def assess_runtime(row: dict, overrides: dict | None = None,
                   host_runtime_version: str | None = None) -> tuple[Condition, str]:
    """Return (R, fixed version display) for one Java install row."""
    condition, fixed = _assess(row, overrides or {}, host_runtime_version)
    plugins = [str(p).strip() for p in (row.get("cve_plugins") or []) if str(p).strip()]
    if plugins:
        # Plugin matches are recorded as evidence only; they never change R.
        condition = Condition(condition.value, f"{condition.evidence} · also flagged by Tenable plugin {', '.join(plugins)}")
    return condition, fixed
