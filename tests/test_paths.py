from __future__ import annotations

import unittest

from java4shell.paths import normalize_binary

LINUX_BIN = "/usr/lib/jvm/java-21-openjdk-amd64/bin/java"


class NormalizeBinaryTests(unittest.TestCase):
    def test_strips_bin_java_and_jre(self) -> None:
        self.assertEqual(
            normalize_binary("/opt/x/jdk1.8.0_377/jre/bin/java"),
            normalize_binary("/opt/x/jdk1.8.0_377/"),
        )

    def test_variants(self) -> None:
        self.assertEqual(normalize_binary(LINUX_BIN), "/usr/lib/jvm/java-21-openjdk-amd64")
        self.assertEqual(normalize_binary("/Opt/X/bin/java"), "/Opt/X")
        self.assertEqual(normalize_binary("C:\\Java\\JDK-17\\bin\\javaw.exe"), "c:/java/jdk-17")
        self.assertEqual(normalize_binary(""), "")
        self.assertEqual(normalize_binary(None), "")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
