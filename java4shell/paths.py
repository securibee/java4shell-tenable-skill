"""Java install path helpers shared by the plugin output parsers."""
from __future__ import annotations

import re

_DRIVE = re.compile(r"^[A-Za-z]:")
_BINARY_SUFFIXES = ("/bin/java", "/bin/java.exe", "/bin/javaw.exe")


def normalize_binary(path: str) -> str:
    """Reduce a java binary or install path to a comparable install root."""
    if not isinstance(path, str):
        return ""
    text = path.strip()
    if _DRIVE.match(text) or "\\" in text:
        text = text.lower()
    text = text.replace("\\", "/").rstrip("/")
    lower = text.lower()
    for suffix in _BINARY_SUFFIXES:
        if lower.endswith(suffix):
            text = text[: -len(suffix)]
            break
    text = text.rstrip("/")
    if text.lower().endswith("/jre"):
        text = text[: -len("/jre")]
    return text.rstrip("/")
