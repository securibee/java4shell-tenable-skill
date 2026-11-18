"""Exposure conditions A, C and J, the verdict, confidence and priority.

R (runtime) comes from versions.py. The other conditions are:

  A  the JVM runs on a 64-bit x86 architecture
  C  the CPU offers the AVX-512 features the vulnerable code path needs
  J  the JVM has the vulnerable intrinsic switched on

Every condition is "yes", "no" or "unknown". Missing or ambiguous input always
lands on "unknown", never on "no", and a CPU model alone can rule a host out
but can never confirm it.
"""
from __future__ import annotations

import re
from typing import Optional

from java4shell.model import (
    AFFECTED_CPU_UNCONFIRMED,
    IMPACTED,
    MITIGATED,
    NO,
    NOT_IMPACTED,
    UNKNOWN,
    UNKNOWN_VERIFY,
    YES,
    Condition,
    HostEvidence,
)

REQUIRED_FLAGS = ("avx512f", "avx512bw", "avx512vbmi", "bmi2", "avx512vl")


def _norm_flag(token: str) -> str:
    return str(token).lower().replace("_", "")


def _text(row: dict, key: str) -> str:
    value = row.get(key)
    return "" if value is None else str(value)


# ---------------------------------------------------------------- A: architecture

_HOST_ARCH_YES = {"amd64", "x86_64"}
_HOST_ARCH_NO = {"aarch64", "arm64"}
_HOST_ARCH_32 = {"x86", "i386", "i486", "i586", "i686"}

_PATH_YES = ("amd64", "x86_64", "x64")
_PATH_NO = ("aarch64", "arm64", "i386", "i686")
# Architecture tokens count only as a whole path segment or a part between separators
# (java-21-openjdk-amd64, el9.x86_64, jdk-17_windows-x64_bin), never inside a word (x64dbg).
_SEGMENT_EDGE = r"[/\\._\-\s]"


def _path_has(token: str, path: str) -> bool:
    return re.search(rf"(?:^|{_SEGMENT_EDGE}){re.escape(token)}(?:$|{_SEGMENT_EDGE})", path) is not None


def assess_arch(row: dict, host: Optional[HostEvidence] = None) -> Condition:
    """A: is the runtime a 64-bit x86 build?"""
    if host is not None and host.os_arch:
        arch = host.os_arch.strip().lower()
        if arch in _HOST_ARCH_YES:
            return Condition(YES, f"host reports {arch}")
        if arch in _HOST_ARCH_NO:
            return Condition(NO, f"host reports {arch}")
        if arch in _HOST_ARCH_32:
            return Condition(NO, f"host reports {arch} (32-bit)")

    row_arch = _text(row, "arch").strip().lower()
    if row_arch == "x64":
        return Condition(YES, "Tenable reports x64")
    if row_arch == "x86":
        return Condition(NO, "Tenable reports x86 (32-bit)")
    if row_arch in ("arm64", "aarch64"):
        return Condition(NO, f"Tenable reports {row_arch}")

    path = _text(row, "java_path").lower()
    yes_hits = [t for t in _PATH_YES if _path_has(t, path)]
    no_hits = [t for t in _PATH_NO if _path_has(t, path)]
    if yes_hits and not no_hits:
        return Condition(YES, f"install path contains {yes_hits[0]}")
    if no_hits and not yes_hits:
        return Condition(NO, f"install path contains {no_hits[0]}")

    os_name = _text(row, "os").lower()
    if "mac" in os_name and ("arm64" in os_name or "aarch64" in os_name or "apple silicon" in os_name):
        return Condition(NO, "macOS on Apple silicon (arm64)")

    return Condition(UNKNOWN, "architecture not in Tenable data")


# ---------------------------------------------------------------- C: CPU features

_GOLD_SKYLAKE_CASCADE = re.compile(
    r"\b(Platinum|Gold|Silver|Bronze)\s+([1-9])([12])\d\d(?!\d)", re.I)
_XEON_E3_5_7 = re.compile(r"Xeon(?:\(R\))?\s+(?:CPU\s+)?E[357]-", re.I)
_XEON_OLD = re.compile(r"Xeon(?:\(R\))?\s+(?:CPU\s+)?[EXLW]\d{4}(?!\d)", re.I)
# Excludes the 8th-gen mobile parts that do have AVX-512 VBMI (the 8121U and 8114Y).
_CORE_OLD = re.compile(r"\bi[3579]-(?!81(?:21U|14Y))[2-9]\d{3}(?!\d)", re.I)
_EPYC_OLD = re.compile(r"\bEPYC\s+[3-7]\d\d[1-3](?!\d)", re.I)
# The model number follows the tier digit (Ryzen 7 5800X, Ryzen 5 PRO 4650G) or Threadripper
# (Threadripper PRO 3995WX). Other numbers in the string, such as a clock speed, do not count.
_RYZEN_OLD = re.compile(
    r"\bRyzen\s+(?:Threadripper\s+(?:PRO\s+)?|(?:PRO\s+)?\d\s+(?:PRO\s+)?)[1-5]\d{3}(?!\d)", re.I)
_LEGACY_FAMILY = re.compile(r"\b(Opteron|Atom|Pentium|Celeron)\b", re.I)
_VIRTUAL_OLD = re.compile(
    r"Skylake|Cascade\s?lake|Broadwell|Haswell|IvyBridge|SandyBridge|Westmere|Nehalem"
    r"|EPYC-Rome|EPYC-Milan",
    re.I,
)


def cpu_rules_out(model: str) -> Optional[str]:
    """Return why a CPU model cannot run the vulnerable path, or None.

    This only rules out. A model that is not recognised, or that looks capable,
    returns None: a model name can never confirm the required features.
    """
    if not model:
        return None
    m = _GOLD_SKYLAKE_CASCADE.search(model)
    if m:
        if m.group(3) == "1":
            return "Intel Xeon Scalable 1st gen (Skylake): no AVX-512 VBMI"
        return "Intel Xeon Scalable 2nd gen (Cascade Lake): no AVX-512 VBMI"
    if _XEON_E3_5_7.search(model):
        return "Intel Xeon E3/E5/E7: no AVX-512"
    if _XEON_OLD.search(model):
        return "Intel Xeon pre-Scalable: no AVX-512"
    if _CORE_OLD.search(model):
        return "Intel Core 2nd to 9th gen: no AVX-512 VBMI"
    if _EPYC_OLD.search(model):
        return "AMD EPYC Zen 1-3: no AVX-512"
    if _RYZEN_OLD.search(model):
        return "AMD Ryzen Zen 1-3: no AVX-512"
    m = _LEGACY_FAMILY.search(model)
    if m:
        return f"{m.group(1).title()} family: no AVX-512"
    m = _VIRTUAL_OLD.search(model)
    if m:
        return f"virtual CPU model {m.group(0)}: no AVX-512 VBMI"
    return None


def assess_cpu(row: dict, host: Optional[HostEvidence] = None) -> Condition:
    """C: does the CPU offer every required feature?"""
    if host is not None and host.cpu_flags:
        have = {_norm_flag(f) for f in host.cpu_flags}
        missing = [f for f in REQUIRED_FLAGS if f not in have]
        source = host.cpu_source or "host"
        if missing:
            return Condition(NO, f"missing CPU flags: {', '.join(missing)} ({source})")
        return Condition(YES, f"all required CPU flags present ({source})")

    models = [p.strip() for p in _text(row, "cpu_model").split(";") if p.strip()]
    if models:
        reasons = [cpu_rules_out(model) for model in models]
        if all(reasons):
            unique = list(dict.fromkeys(reasons))
            return Condition(NO, "; ".join(unique))
    return Condition(UNKNOWN, "CPU flags not in Tenable data")


# ---------------------------------------------------------------- J: JVM flags

_CMDLINE_OFF = re.compile(r"-XX:(-UseBASE64Intrinsics|UseAVX=[0-2])")


def _as_bool(value: object) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        low = value.strip().lower()
        if low in ("true", "1", "yes", "on"):
            return True
        if low in ("false", "0", "no", "off"):
            return False
    return None


def _as_int(value: object) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def _fmt(flags: dict) -> str:
    return ", ".join(f"{k}={v}" for k, v in flags.items())


def assess_flags(row: dict, host: Optional[HostEvidence] = None) -> Condition:
    """J: is the vulnerable intrinsic active in the running JVM?"""
    if host is None:
        return Condition(UNKNOWN, "JVM flags not collected")

    if host.live_flags:
        base64 = _as_bool(host.live_flags.get("UseBASE64Intrinsics"))
        avx = _as_int(host.live_flags.get("UseAVX"))
        if base64 is False:
            return Condition(NO, "live: UseBASE64Intrinsics=false")
        if avx is not None and avx <= 2:
            return Condition(NO, f"live: UseAVX={avx}")
        if base64 is True and avx is not None:
            return Condition(YES, f"live: UseBASE64Intrinsics=true, UseAVX={avx}")
        return Condition(UNKNOWN, f"live flags incomplete: {_fmt(host.live_flags)}")

    for flag in host.cmdline_flags or ():
        if _CMDLINE_OFF.fullmatch(flag):
            return Condition(UNKNOWN, "mitigation flag seen on command line; confirm with jcmd")

    if host.default_flags:
        return Condition(UNKNOWN, f"defaults only: {_fmt(host.default_flags)}")

    return Condition(UNKNOWN, "JVM flags not collected")


# ---------------------------------------------------------------- verdict

def decide(r: Condition, a: Condition, c: Condition, j: Condition) -> tuple[str, str]:
    """Combine the four conditions into (verdict, reason).

    Worst first: Impacted (R, A, C yes), Affected build - CPU unconfirmed (R yes,
    A yes or unknown, C unknown), Unknown - verify (anything else not cleared),
    Mitigated (J no), Not impacted (R, A or C no). An unknown never clears.
    """
    for letter, cond in (("R", r), ("A", a), ("C", c)):
        if cond.value == NO:
            return NOT_IMPACTED, f"{letter}: {cond.evidence}"
    if j.value == NO:
        return MITIGATED, f"J: {j.evidence}"
    if r.value == YES and a.value == YES and c.value == YES:
        return IMPACTED, "R, A and C all yes"
    if r.value == YES and a.value in (YES, UNKNOWN) and c.value == UNKNOWN:
        return AFFECTED_CPU_UNCONFIRMED, "CPU flags not in Tenable data"
    unknown = [letter for letter, cond in (("R", r), ("A", a), ("C", c), ("J", j))
               if cond.value == UNKNOWN]
    return UNKNOWN_VERIFY, "unknown: " + ", ".join(unknown)


def confidence(r: Condition, a: Condition, c: Condition, j: Condition,
               host: Optional[HostEvidence]) -> str:
    """How firmly the evidence supports the verdict: high, medium or low."""
    c_from_host = (host is not None and bool(host.cpu_flags) and c.value in (YES, NO))
    j_from_host = (host is not None and bool(host.live_flags) and j.value in (YES, NO))
    if c_from_host and j_from_host:
        return "high"
    r_settled = r.value != UNKNOWN
    if r_settled and (c_from_host or c.value == NO):
        return "medium"
    return "low"


# ---------------------------------------------------------------- priority

_PRE_AUTH = (
    ("keycloak", "Keycloak"), ("jira", "Jira"), ("confluence", "Confluence"),
    ("artifactory", "Artifactory"), ("jenkins", "Jenkins"), ("pingfederate", "PingFederate"),
)
_POST_AUTH = (
    ("kafka", "Kafka"), ("solr", "Solr"), ("elasticsearch", "Elasticsearch"),
    ("gerrit", "Gerrit"), ("spinnaker", "Spinnaker"),
)
_OS_JAVA_DIRS = ("/usr/lib/jvm", "/usr/java")


def _under(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix + "/")


def priority(row: dict) -> str:
    """Triage hints for a row. Never affects the verdict."""
    path = _text(row, "java_path").strip().lower()
    haystack = " ".join((path, _text(row, "java_binary").lower(), _text(row, "java_vendor").lower()))
    parts = []
    pre = [name for key, name in _PRE_AUTH if key in haystack]
    if pre:
        parts.append("pre-auth product: " + ", ".join(pre))
    post = [name for key, name in _POST_AUTH if key in haystack]
    if post:
        parts.append("post-auth product: " + ", ".join(post))
    if path and not row.get("managed_by_os") and not any(_under(path, d) for d in _OS_JAVA_DIRS):
        parts.append("bundled runtime")
    return "; ".join(parts)
