from __future__ import annotations

from dataclasses import dataclass

YES = "yes"
NO = "no"
UNKNOWN = "unknown"
CONDITION_VALUES = (YES, NO, UNKNOWN)

IMPACTED = "Impacted"
AFFECTED_CPU_UNCONFIRMED = "Affected build \u2013 CPU unconfirmed"
UNKNOWN_VERIFY = "Unknown \u2013 verify"
MITIGATED = "Mitigated (temporary)"
NOT_IMPACTED = "Not impacted"

# Worst first.
ORDER = [IMPACTED, AFFECTED_CPU_UNCONFIRMED, UNKNOWN_VERIFY, MITIGATED, NOT_IMPACTED]


@dataclass(frozen=True)
class Condition:
    """One assessed condition: a value of yes, no or unknown, and the evidence behind it."""

    value: str
    evidence: str

    def __post_init__(self) -> None:
        if self.value not in CONDITION_VALUES:
            raise ValueError(f"condition value must be one of {CONDITION_VALUES}, got {self.value!r}")


@dataclass(frozen=True)
class HostEvidence:
    """Host facts for one install, as read from Tenable plugin output.

    Any field may be empty or None when no plugin reported it. Today only
    cmdline_flags is filled (from the process list plugin).
    """

    cpu_flags: frozenset[str] | None
    cpu_source: str
    runtime_version: str | None
    os_arch: str | None
    default_flags: dict | None
    live_flags: dict | None
    live_skip_reason: str
    cmdline_flags: tuple[str, ...]
    collected_at: str
    stale: bool
