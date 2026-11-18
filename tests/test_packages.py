from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import findings
from java4shell.inventory import JAVA_PACKAGE_RE, package_rows, unmatched_package_findings
from java4shell.versions import assess_runtime

FIXTURES = Path(__file__).parent / "fixtures"

ROW_KEYS = {
    "asset_id", "asset", "ip", "fqdn", "os", "arch", "cpu_model", "virtualization", "java_vendor",
    "vendor_confidence", "java_version_raw", "version_conflict", "java_path", "java_binary", "managed_by_os",
    "detection_plugin", "cve_plugins", "asset_cve_plugins", "last_seen", "plugin_output", "truncated",
    "no_output",
}


def finding(name: str, asset_id: str = "a-9", state: str = "OPEN") -> dict:
    return {"asset_id": asset_id, "asset": "ctr09", "ip": "192.0.2.99", "fqdn": "ctr09.example.test",
            "name": name, "state": state, "asset_class": "CONTAINER"}


def tokens(name: str) -> list[str]:
    return [m.group(0).lower() for m in JAVA_PACKAGE_RE.finditer(name)]


class TokenTests(unittest.TestCase):
    def test_tokens(self) -> None:
        self.assertEqual(tokens("RHEL 9 : java-17-openjdk (RHSA-2099:0001)"), ["java-17-openjdk"])
        self.assertEqual(tokens("Ubuntu : openjdk-21-jre-headless vulnerability"),
                         ["openjdk-21-jre-headless"])
        self.assertEqual(tokens("Alpine : openjdk17 (CVE-2099-0001)"), ["openjdk17"])
        self.assertEqual(tokens("Some unrelated javascript package"), [])

    def test_other_forms(self) -> None:
        self.assertEqual(tokens("RHEL 8 : java-1.8.0-openjdk (RHSA-2099:0002)"), ["java-1.8.0-openjdk"])
        self.assertEqual(tokens("Debian : openjdk-17-jdk"), ["openjdk-17-jdk"])
        self.assertEqual(tokens("temurin-21-jre update"), ["temurin-21-jre"])
        self.assertEqual(tokens("amazon-corretto-17 update"), ["amazon-corretto-17"])
        self.assertEqual(tokens("java-11-amazon-corretto update"), ["java-11-amazon-corretto"])
        self.assertEqual(tokens("zulu17 update"), ["zulu17"])
        self.assertEqual(tokens("GraalVM update"), ["graalvm"])
        self.assertEqual(tokens("Some JRE issue"), ["jre"])
        self.assertEqual(tokens("Some JDK issue"), ["jdk"])
        self.assertEqual(tokens("OpenJDK update"), ["openjdk"])

    def test_non_runtime_names_do_not_match(self) -> None:
        for name in ("javascript", "java-atk-wrapper", "javamail", "javassist", "libjdkfoo", "jdkish"):
            self.assertEqual(tokens(f"Ubuntu : {name} vulnerability"), [], name)


class PackageRowsTests(unittest.TestCase):
    def test_row_shape(self) -> None:
        (row,) = package_rows([finding("RHEL 9 : java-17-openjdk (RHSA-2099:0001)")], set())
        self.assertEqual(set(row), ROW_KEYS)
        self.assertEqual(row["java_path"], "package:java-17-openjdk")
        self.assertEqual(row["detection_plugin"], "package finding")
        self.assertEqual(row["java_vendor"], "OpenJDK Java")
        self.assertEqual(row["java_version_raw"], "")
        self.assertIsNone(row["managed_by_os"])
        self.assertIs(row["no_output"], False)
        self.assertIs(row["truncated"], False)
        self.assertEqual(row["virtualization"], "")
        self.assertEqual(row["os"], "")
        self.assertEqual(row["cve_plugins"], [])
        self.assertEqual(row["plugin_output"], "RHEL 9 : java-17-openjdk (RHSA-2099:0001)")
        self.assertEqual(row["asset_id"], "a-9")
        self.assertEqual(row["ip"], "192.0.2.99")

    def test_vendor_from_token(self) -> None:
        cases = {
            "temurin-17-jdk update": "temurin",
            "amazon-corretto-17 update": "corretto",
            "java-17-amazon-corretto update": "corretto",
            "zulu17 update": "zulu",
            "GraalVM update": "graalvm",
            "openjdk17 update": "OpenJDK Java",
        }
        for name, vendor in cases.items():
            (row,) = package_rows([finding(name)], set())
            self.assertEqual(row["java_vendor"], vendor, name)

    def test_covered_assets_skipped(self) -> None:
        recs = [finding("RHEL 9 : java-17-openjdk", asset_id="a-1")]
        self.assertEqual(package_rows(recs, {"a-1"}), [])
        self.assertEqual(len(package_rows(recs, {"a-2"})), 1)

    def test_covered_by_name_and_ip_when_no_asset_id(self) -> None:
        rec = finding("RHEL 9 : java-17-openjdk", asset_id="")
        key = "ctr09|192.0.2.99"
        self.assertEqual(package_rows([rec], {key}), [])
        self.assertEqual(len(package_rows([rec], set())), 1)

    def test_state_filter(self) -> None:
        self.assertEqual(package_rows([finding("java-17-openjdk", state="FIXED")], set()), [])
        self.assertEqual(package_rows([finding("java-17-openjdk", state="fixed")], set()), [])
        self.assertEqual(len(package_rows([finding("java-17-openjdk", state="NEW")], set())), 1)
        self.assertEqual(len(package_rows([finding("java-17-openjdk", state="REOPENED")], set())), 1)
        self.assertEqual(len(package_rows([finding("java-17-openjdk", state="")], set())), 1)

    def test_line_rule_applies(self) -> None:
        (old,) = package_rows([finding("RHEL 9 : java-11-openjdk (RHSA-2099:0003)")], set())
        self.assertEqual(assess_runtime(old)[0].value, "no")
        (new,) = package_rows([finding("RHEL 9 : java-17-openjdk (RHSA-2099:0001)")], set())
        self.assertEqual(assess_runtime(new)[0].value, "unknown")

    def test_line_from_every_token_form(self) -> None:
        cases = {
            "java-11-openjdk": "no", "openjdk17": "unknown", "openjdk-21-jre-headless": "unknown",
            "java-1.8.0-openjdk": "no", "temurin-17-jdk": "unknown", "zulu17": "unknown",
            "amazon-corretto-21": "unknown", "java-17-amazon-corretto": "unknown",
        }
        for token, expected in cases.items():
            (row,) = package_rows([finding(f"Pkg : {token} issue")], set())
            self.assertEqual(assess_runtime(row)[0].value, expected, token)

    def test_unknown_line_is_unknown(self) -> None:
        for name in ("OpenJDK update", "GraalVM update", "Some JRE issue"):
            (row,) = package_rows([finding(name)], set())
            self.assertEqual(assess_runtime(row)[0].value, "unknown", name)

    def test_vendor_and_installer_package_names(self) -> None:
        cases = {
            "Ubuntu : adoptopenjdk-11-hotspot vulnerability": ("adoptopenjdk-11-hotspot", "no"),
            "Debian : oracle-java17-installer vulnerability": ("oracle-java17-installer", "unknown"),
            "Debian : oracle-java8-installer vulnerability": ("oracle-java8-installer", "no"),
        }
        for name, (token, expected) in cases.items():
            self.assertEqual(tokens(name), [token], name)
            (row,) = package_rows([finding(name)], set())
            self.assertEqual(assess_runtime(row)[0].value, expected, name)
        (row,) = package_rows([finding("Debian : oracle-java17-installer vulnerability")], set())
        self.assertEqual(row["java_vendor"], "Oracle Java")

    def test_bare_vendor_tokens_make_unknown_rows(self) -> None:
        for name in ("Eclipse Temurin vulnerability", "Amazon Corretto update", "Azul Zulu update",
                     "AdoptOpenJDK update", "IBM Semeru Runtime update"):
            rows = package_rows([finding(name)], set())
            self.assertEqual(len(rows), 1, name)
            self.assertEqual(assess_runtime(rows[0])[0].value, "unknown", name)

    def test_bare_vendor_token_takes_line_from_name(self) -> None:
        (row,) = package_rows([finding("Amazon Corretto 11 update")], set())
        self.assertEqual(row["java_path"], "package:corretto-11")
        self.assertEqual(assess_runtime(row)[0].value, "no")
        (row,) = package_rows([finding("Semeru-21.0.4 update")], set())
        self.assertEqual(assess_runtime(row)[0].value, "unknown")

    def test_unmatched_package_findings_counted(self) -> None:
        recs = [finding("Some unrelated javascript package"), finding("java-17-openjdk"),
                finding("libfoo update", asset_id="a-1"), finding("libbar update", state="FIXED"),
                finding("libbaz update", asset_id="a-2")]
        self.assertEqual(unmatched_package_findings(recs, {"a-2"}), 2)

    def test_one_row_per_package(self) -> None:
        rows = package_rows([finding("RHEL 9 : java-17-openjdk (RHSA-2099:0001)"),
                             finding("RHEL 9 : java-17-openjdk (RHSA-2099:0002)")], set())
        self.assertEqual(len(rows), 1)

    def test_one_row_per_asset_and_token(self) -> None:
        rows = package_rows([finding("java-17-openjdk and java-11-openjdk"),
                             finding("java-17-openjdk", asset_id="a-10")], set())
        self.assertEqual(sorted((r["asset_id"], r["java_path"]) for r in rows),
                         [("a-10", "package:java-17-openjdk"), ("a-9", "package:java-11-openjdk"),
                          ("a-9", "package:java-17-openjdk")])

    def test_no_token_no_row(self) -> None:
        self.assertEqual(package_rows([finding("Some unrelated javascript package")], set()), [])


class PackagesCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def run_cli(self, *extra: str) -> tuple[str, list[dict]]:
        out = self.tmp / "findings.json"
        argv = ["--outputs", str(FIXTURES / "outputs.jsonl"), "--cve", str(FIXTURES / "cve_findings.json"),
                "-o", str(out), *extra]
        buf = io.StringIO()
        with redirect_stdout(buf):
            findings.main(argv)
        return buf.getvalue(), json.loads(out.read_text(encoding="utf-8"))

    def test_cli_counts(self) -> None:
        printed, rows = self.run_cli("--packages", str(FIXTURES / "package_findings.json"))
        self.assertEqual(printed.strip(),
                         "assets=7 pairs=10 truncated=2 stale_scans=1 no_output=1 package_only=1 package_unmatched=0")
        package = [r for r in rows if r["detection_plugin"] == "package finding"]
        self.assertEqual([(r["asset_id"], r["java_path"]) for r in package],
                         [("a-301", "package:java-17-openjdk")])

    def test_without_packages_output_unchanged_apart_from_count(self) -> None:
        printed, rows = self.run_cli()
        self.assertEqual(printed.strip(),
                         "assets=6 pairs=9 truncated=2 stale_scans=1 no_output=1 package_only=0 package_unmatched=0")
        self.assertEqual(len(rows), 9)


if __name__ == "__main__":
    unittest.main()
