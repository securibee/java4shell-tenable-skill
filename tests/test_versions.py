from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from java4shell.versions import (
    assess_runtime,
    below_fixed,
    java_line,
    line_from_path,
    load_overrides,
    normalize_vendor,
    parse_java_version,
)

_TEMP_DIRS: list[tempfile.TemporaryDirectory] = []


def tmp_path_with(content: str) -> Path:
    """Write content to fixed.json in a fresh temporary directory and return its path."""
    tmp = tempfile.TemporaryDirectory()
    _TEMP_DIRS.append(tmp)
    path = Path(tmp.name) / "fixed.json"
    path.write_text(content, encoding="utf-8")
    return path


def tearDownModule():
    while _TEMP_DIRS:
        _TEMP_DIRS.pop().cleanup()


class ParseTests(unittest.TestCase):
    def test_plus_forms_are_certain(self):
        v = parse_java_version("17.0.21+9-LTS"); self.assertEqual((v.security, v.patch, v.build, v.certain), (21, 0, 9, True))
        v = parse_java_version("17.0.21.1+2"); self.assertEqual((v.patch, v.build), (1, 2))
    def test_four_part_is_uncertain(self):
        v = parse_java_version("17.0.21.9"); self.assertFalse(v.certain)
    def test_five_part(self):
        self.assertEqual(parse_java_version("17.0.21.1.2").patch, 1)
        v = parse_java_version("17.0.12.8.300"); self.assertEqual((v.patch, v.build), (0, 8))
    def test_rejects_non_java(self):
        self.assertIsNone(parse_java_version("24.04.3"))
        self.assertIsNone(parse_java_version("25.36"))
    def test_rejects_os_build_strings(self):
        for raw in ("10.0.19045", "10.0.17763.1234", "8.6.0", "11.0.500", "17.0.20348.1", "8.1.7"):
            self.assertIsNone(parse_java_version(raw), raw)
        # Zulu product numbers keep a non-zero second field.
        self.assertIsNotNone(parse_java_version("8.72.0.17", vendor="zulu"))
        # Java 8 update numbers run past 500, so the dotted Java 8 form keeps them.
        v = parse_java_version("8.0.511.33")
        self.assertEqual((v.line, v.security), (8, 511))
        r = assess_runtime({"java_version_raw": "10.0.19045", "java_vendor": "", "java_path": "/opt/app/jre/"})[0]
        self.assertNotEqual(r.value, "no")
    def test_zulu_product_number(self):
        v = parse_java_version("25.36.15 (CA)", vendor="zulu"); self.assertEqual((v.line, v.minor), (25, 36))
    def test_java8_forms(self):
        for raw in ("1.8.0_402", "8u402", "8.0.402"):
            self.assertEqual(parse_java_version(raw).line, 8)
    def test_java6_and_7_forms(self):
        for raw, line in (("1.6.0_45", 6), ("1.7.0_72", 7), ("7u72", 7), ("6u45", 6)):
            v = parse_java_version(raw)
            self.assertIsNotNone(v, raw)
            self.assertEqual(v.line, line, raw)
        self.assertEqual(parse_java_version("1.7.0_72").security, 72)
        # Dotted 6.x.y and 7.x.y read as Java only when corroborated.
        self.assertIsNone(parse_java_version("7.0.72"))
        v = parse_java_version("7.0.72", legacy_ok=True)
        self.assertEqual((v.line, v.security), (7, 72))
        self.assertIsNone(parse_java_version("7.4.1", legacy_ok=True))
        self.assertIsNone(parse_java_version("6.0.6002.18005", legacy_ok=True))
        self.assertIsNone(parse_java_version("7.0.72.1.2", legacy_ok=True))
    def test_more_than_five_parts(self):
        v = parse_java_version("11.0.16.1.3.2207.12")
        self.assertEqual((v.line, v.minor, v.security, v.patch, v.build, v.certain), (11, 0, 16, None, None, False))
        v = parse_java_version("25.0.3.4.412.88")
        self.assertEqual((v.line, v.security, v.patch, v.certain), (25, 3, None, False))
    def test_line_from_path(self):
        cases = {"/usr/lib/jvm/java-21-openjdk-amd64/": 21, "/opt/x/jdk-17.0.12/": 17,
                 "C:\\Program Files\\Zulu\\zulu25\\": 25, "/opt/x/jre1.8.0_402/": 8}
        for p, line in cases.items():
            self.assertEqual(line_from_path(p), line)


class PathLineTests(unittest.TestCase):
    def test_disagreeing_path_lines_give_none(self):
        self.assertIsNone(line_from_path("/opt/java8-tools/jdk-21.0.3/"))
        self.assertIsNone(line_from_path("/opt/jdk-17-migration/jre1.8.0_402/"))
        self.assertIsNone(line_from_path("/opt/java7-compat/jdk-17/"))
        # Repeated mentions of one line agree.
        self.assertEqual(line_from_path("/usr/lib/jvm/java-17-openjdk-17.0.9.0.9-2.el9.x86_64/"), 17)
        self.assertEqual(line_from_path("/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.402.b06-1.el9.x86_64/"), 8)
        r = assess_runtime({"java_version_raw": "", "java_vendor": "OpenJDK Java",
                            "java_path": "/opt/java8-tools/jdk-21.0.3/"})[0]
        self.assertNotEqual(r.value, "no")

    def test_version_contradicted_by_any_path_line_is_unknown(self):
        cases = [
            ("8.0.402", "OpenJDK Java", "/opt/jdk-21.0.3/legacy-java8/"),
            ("1.8.0_402", "Oracle Java", "/opt/jdk-21/jre1.8.0_402/"),
            ("1.7.0_72", "Oracle Java", "/opt/jdk-17-apps/jre1.7.0_72/"),
        ]
        for version, app, path in cases:
            row = {"java_version_raw": version, "java_vendor": app, "java_path": path}
            r = assess_runtime(row)[0]
            self.assertEqual(r.value, "unknown", (version, path, r.evidence))
            self.assertIn("version and path disagree", r.evidence)
            self.assertIsNone(java_line(row))

    def test_version_matching_every_path_line_still_assessed(self):
        row = {"java_version_raw": "1.8.0_402", "java_vendor": "OpenJDK Java",
               "java_path": "/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.402.b06-1.el9.x86_64/"}
        self.assertEqual(assess_runtime(row)[0].value, "no")
        self.assertEqual(java_line(row), 8)


class BoundaryTests(unittest.TestCase):
    F = (17, 0, 21, 1)
    def test_build_not_read_as_patch(self):   # 17.0.21+9 shown as 17.0.21.9 must not read as fixed
        self.assertTrue(below_fixed(parse_java_version("17.0.21.9"), self.F))
    def test_four_part_one_is_ambiguous(self):
        self.assertIsNone(below_fixed(parse_java_version("17.0.21.1"), self.F))
    def test_below_and_above(self):
        self.assertTrue(below_fixed(parse_java_version("17.0.20.8"), self.F))
        self.assertFalse(below_fixed(parse_java_version("17.0.22.3"), self.F))
        self.assertFalse(below_fixed(parse_java_version("17.0.21.1+2"), self.F))


class RuleRTests(unittest.TestCase):
    def r(self, version, app="OpenJDK Java", path="/usr/lib/jvm/java-21-openjdk-amd64/", **kw):
        return assess_runtime({"java_version_raw": version, "java_vendor": app, "java_path": path}, **kw)[0].value
    def test_lines(self):
        self.assertEqual(self.r("11.0.25", path="/usr/lib/jvm/java-11-openjdk/"), "no")
        self.assertEqual(self.r("1.8.0_402", path="/usr/lib/jvm/java-8/"), "no")
        self.assertEqual(self.r("17.0.5+8", path="/opt/jdk-17.0.5/"), "no")
        self.assertEqual(self.r("17.0.6+10", path="/opt/jdk-17.0.6/"), "yes")
        self.assertEqual(self.r("21.0.6.7"), "yes")
        self.assertEqual(self.r("21.0.13.1+2"), "no")
        self.assertEqual(self.r("24.0.2+12", path="/opt/jdk-24/"), "yes")
    def test_java7_not_affected(self):
        self.assertEqual(self.r("7.0.72", app="Oracle Java", path="C:\\Program Files\\Java\\jre1.7.0_72\\"), "no")
        self.assertEqual(self.r("1.6.0_45", app="Oracle Java", path="/opt/java/jre1.6.0_45/"), "no")
    def test_dotted_java7_needs_corroboration(self):
        self.assertNotEqual(self.r("7.0.5", app="", path="/opt/app/jre/"), "no")
        self.assertEqual(self.r("7.0.72", app="Sun Java", path="/opt/app/jre/"), "no")
        self.assertEqual(self.r("7.0.10.0", app="IBM Java", path="/opt/app/jre/"), "no")
        self.assertEqual(self.r("7.0.72", app="", path="/opt/java/jdk1.7.0_72/"), "no")
        self.assertEqual(self.r("7.0.72", app="", path="/usr/lib/jvm/java-7-openjdk/"), "no")
        self.assertEqual(self.r("7u72", app="", path="/opt/app/jre/"), "no")
    def test_line_rule_before_semeru_and_graalvm(self):
        self.assertEqual(self.r("1.8.0_391", app="IBM Java", path="/opt/ibm/java/"), "no")
        self.assertEqual(self.r("11.0.20", app="GraalVM", path="/opt/graalvm-11/"), "no")
        self.assertEqual(self.r("21.0.14", app="IBM Semeru Runtime", path="/opt/semeru-21/"), "unknown")
        self.assertEqual(self.r("21.0.14", app="GraalVM", path="/opt/graalvm-jdk-21/"), "unknown")
        # Prime keeps its own rule on every line.
        self.assertNotEqual(self.r("11.0.20", app="Azul Prime", path="/opt/zing/zing-jdk11/"), "no")
    def test_vendor_build_strings_with_many_parts(self):
        jbr = "/opt/vendor/ide/jbr/"
        self.assertEqual(self.r("11.0.16.1.3.2207.12", app="", path=jbr), "no")
        self.assertEqual(self.r("25.0.3.4.412.88", app="", path=jbr), "yes")
        self.assertEqual(self.r("21.0.13.1.5.9", app="", path=jbr), "unknown")
    def test_corretto_five_part_at_boundary_uncertain(self):
        path = "/usr/lib/jvm/java-17-amazon-corretto/"
        app = "Amazon Corretto Java"
        self.assertEqual(self.r("17.0.21.1.1", app=app, path=path), "unknown")
        self.assertEqual(self.r("17.0.21.1.2", app=app, path=path), "unknown")
        self.assertEqual(self.r("17.0.20.8.1", app=app, path=path), "yes")
        self.assertEqual(self.r("17.0.22.5.1", app=app, path=path), "no")
        # Other vendors keep the patch-then-build reading.
        self.assertEqual(self.r("17.0.21.1.2", app="OpenJDK Java", path="/opt/jdk-17/"), "no")
    def test_epp(self):
        self.assertEqual(self.r("8u511b33-perf", app="Oracle Java", path="/opt/jdk1.8.0_511-perf/"), "yes")
    def test_disagreement_is_unknown(self):
        self.assertEqual(self.r("21.0.6.7", path="/usr/lib/jvm/java-17-openjdk/"), "unknown")
    def test_os_release_version_falls_back_to_path(self):
        self.assertEqual(self.r("24.04.3", path="/usr/lib/jvm/java-8-openjdk-amd64/"), "no")
    def test_graalvm_and_semeru_unknown(self):
        self.assertEqual(self.r("21.0.13.1", app="GraalVM", path="/opt/graalvm-jdk-21/"), "unknown")
        self.assertEqual(self.r("21.0.13.1", app="IBM Semeru Runtime", path="/opt/semeru-21/"), "unknown")
    def test_zulu_product(self):
        self.assertEqual(self.r("25.36.15", app="Azul Zulu Java", path="/opt/zulu25/"), "yes")
        self.assertEqual(self.r("25.38.201", app="Azul Zulu Java", path="/opt/zulu25/"), "no")
    def test_host_runtime_overrides(self):
        self.assertEqual(self.r("21.0.13.1", host_runtime_version="21.0.13+11-LTS"), "yes")
    def test_override_forces_unknown(self):
        self.assertEqual(self.r("21.0.13.1+2", overrides={("openjdk", 21): None}), "unknown")
    def test_cve_plugin_is_evidence_only(self):
        cond, _ = assess_runtime({"java_version_raw": "11.0.25", "java_vendor": "OpenJDK Java",
                                  "java_path": "/usr/lib/jvm/java-11-openjdk/", "cve_plugins": ["382091"]})
        self.assertEqual(cond.value, "no")
        self.assertIn("382091", cond.evidence)

    # Additional coverage for the rules in the brief.
    def test_evidence_strings(self):
        row = {"java_version_raw": "11.0.25", "java_vendor": "OpenJDK Java", "java_path": "/usr/lib/jvm/java-11-openjdk/"}
        self.assertEqual(assess_runtime(row)[0].evidence, "Java 11: standard build assumed; vulnerable code not present")
        row = {"java_version_raw": "24.0.2+12", "java_vendor": "OpenJDK Java", "java_path": "/opt/jdk-24/"}
        cond, fixed = assess_runtime(row)
        self.assertEqual((cond.evidence, fixed), ("end of life, no fix", "none (EOL)"))
        row = {"java_version_raw": "21.0.6.7", "java_vendor": "OpenJDK Java", "java_path": "/usr/lib/jvm/java-17-openjdk/"}
        self.assertEqual(assess_runtime(row)[0].evidence, "version and path disagree")
        row = {"java_version_raw": "21.0.13.1+2", "java_vendor": "OpenJDK Java", "java_path": "/usr/lib/jvm/java-21-openjdk/"}
        self.assertEqual(assess_runtime(row, overrides={("openjdk", 21): None})[0].evidence, "fixed build disputed (fixed.json)")
        row = {"java_version_raw": "21.0.13.1", "java_vendor": "OpenJDK Java", "java_path": "/usr/lib/jvm/java-21-openjdk/"}
        cond, fixed = assess_runtime(row)
        self.assertEqual((cond.value, cond.evidence, fixed), ("unknown", "patch level ambiguous at fix boundary", "21.0.13.1"))
    def test_host_runtime_evidence(self):
        row = {"java_version_raw": "21.0.13.1", "java_vendor": "OpenJDK Java", "java_path": "/usr/lib/jvm/java-21-openjdk/"}
        cond, _ = assess_runtime(row, host_runtime_version="21.0.13.1+2")
        self.assertEqual(cond.value, "no")
        self.assertIn("host-reported", cond.evidence)
    def test_epp_fixed_and_display(self):
        row = {"java_version_raw": "8u513b11-perf", "java_vendor": "Oracle Java", "java_path": "/opt/jdk1.8.0_513-perf/"}
        cond, fixed = assess_runtime(row)
        self.assertEqual((cond.value, fixed), ("no", "8u513-perf"))
    def test_zulu_17_low_minor_unknown(self):
        self.assertEqual(self.r("17.32.13", app="Azul Zulu Java", path="/opt/zulu17/"), "unknown")
    def test_prime(self):
        self.assertEqual(self.r("26.08.100.0", app="Azul Prime", path="/opt/zing/zing-jdk11/"), "yes")
        self.assertEqual(self.r("26.08.110.0", app="Azul Prime", path="/opt/zing/zing-jdk11/"), "no")
        self.assertEqual(self.r("26.02.510.0", app="Azul Zing", path="/opt/zing/zing-jdk8/"), "no")
        self.assertEqual(self.r("25.12.3.0", app="Azul Prime", path="/opt/zing/zing-jdk8/"), "yes")
        self.assertEqual(self.r("26.11.1.0", app="Azul Prime", path="/opt/zing/zing-jdk17/"), "unknown")
        self.assertEqual(self.r("17.0.9", app="Azul Prime", path="/opt/zing/zing-jdk17/"), "unknown")
    def test_unknown_line(self):
        self.assertEqual(self.r("not a version", path="/opt/app/"), "unknown")
        self.assertEqual(self.r("29.0.1+3", path="/opt/jdk-29/"), "unknown")
    def test_path_only_never_clears_fix_line(self):
        self.assertEqual(self.r("", path="/usr/lib/jvm/java-21-openjdk/"), "unknown")
    def test_condition_values_restricted(self):
        from java4shell.model import Condition
        with self.assertRaises(ValueError):
            Condition("maybe", "x")


class VendorTests(unittest.TestCase):
    def test_vendors(self):
        cases = [
            ("Oracle Java", "/opt/jdk-17/", "oracle"),
            ("Oracle Java", "/opt/jdk1.8.0_511-perf/", "oracle-epp"),
            ("OpenJDK Java", "/opt/x/", "openjdk"),
            ("Java", "/usr/lib/jvm/java-17/", "openjdk"),
            ("Eclipse Temurin", "/opt/x/", "temurin"),
            ("Adoptium JDK", "/opt/x/", "temurin"),
            ("Azul Zulu Java", "/opt/x/", "zulu"),
            ("Azul Prime", "/opt/x/", "prime"),
            ("Zing JVM", "/opt/x/", "prime"),
            ("Amazon Corretto", "/opt/x/", "corretto"),
            ("Microsoft Build of OpenJDK", "/opt/x/", "microsoft"),
            ("BellSoft Liberica", "/opt/x/", "liberica"),
            ("SapMachine", "/opt/x/", "sapmachine"),
            ("Red Hat build of OpenJDK", "/opt/x/", "redhat"),
            ("Oracle GraalVM", "/opt/x/", "graalvm"),
            ("IBM Semeru Runtime", "/opt/x/", "semeru"),
            ("Eclipse OpenJ9", "/opt/x/", "semeru"),
            ("Some Runtime", "/opt/x/", "unknown"),
        ]
        for app, path, expected in cases:
            self.assertEqual(normalize_vendor(app, path), expected, app)
    def test_perf_in_version(self):
        self.assertEqual(normalize_vendor("Oracle Java", "/opt/java/", "8u511b33-perf"), "oracle-epp")
    def test_epp_not_lost_to_other_names(self):
        cases = [
            ("Java", "/opt/jdk1.8.0_511-perf/"),
            ("Oracle Java", "/opt/amazon-tools/jdk1.8.0_511-perf/"),
            ("Oracle Java", "C:\\Program Files\\Microsoft\\jdk1.8.0_511-perf\\"),
        ]
        for app, path in cases:
            row = {"java_version_raw": "8u511b33-perf", "java_vendor": app, "java_path": path}
            self.assertEqual(normalize_vendor(app, path), "oracle-epp", path)
            self.assertEqual(assess_runtime(row)[0].value, "yes", path)
    def test_application_name_beats_path(self):
        self.assertEqual(normalize_vendor("Oracle Java", "/opt/amazon-tools/jdk-17/"), "oracle")
        self.assertEqual(normalize_vendor("Java", "/opt/amazon-corretto-17/"), "corretto")
    def test_cautious_path_vendor_beats_generic_name(self):
        def r(version, app, path):
            return assess_runtime({"java_version_raw": version, "java_vendor": app, "java_path": path})[0].value
        self.assertNotEqual(r("11.0.20", "OpenJDK Java", "/opt/zing/zing-jdk11/"), "no")
        self.assertEqual(r("21.0.13.1+2", "Oracle Java", "/opt/graalvm-jdk-21/"), "unknown")
        self.assertEqual(r("21.0.13.1+2", "Oracle Java", "/opt/ibm/semeru-jdk-21/"), "unknown")
        self.assertEqual(r("21.0.13.1+2", "OpenJDK Java", "/opt/openj9-21/"), "unknown")
        self.assertEqual(normalize_vendor("OpenJDK Java", "/opt/zing/zing-jdk11/"), "prime")
        self.assertEqual(normalize_vendor("Oracle Java", "/opt/graalvm-jdk-21/"), "graalvm")
        self.assertEqual(normalize_vendor("Java", "/opt/x/", ""), "unknown")
    def test_perf_needs_token(self):
        self.assertEqual(normalize_vendor("Oracle Java", "/opt/performance/jdk-17/"), "oracle")


class OverrideTests(unittest.TestCase):
    def test_bad_overrides_warn_and_ignore(self):
        content = json.dumps({"oracle": {"17": "17.0.21.2", "99": "x"}, "nope": {"21": "21.0.13.1"}, "zulu": "bad"})
        ov, warnings = load_overrides(tmp_path_with(content))
        self.assertEqual(ov, {("oracle", 17): (17, 0, 21, 2)})
        self.assertEqual(len(warnings), 3)
    def test_unreadable_file_warns(self):
        ov, warnings = load_overrides(tmp_path_with("{not json"))
        self.assertEqual((ov, len(warnings)), ({}, 1))
    def test_malformed_files_warn_instead_of_crashing(self):
        ov, warnings = load_overrides(tmp_path_with(json.dumps({"oracle": {"\u00b2": "17.0.21.2"}})))
        self.assertEqual((ov, len(warnings)), ({}, 1))
        ov, warnings = load_overrides(tmp_path_with("[" * 200000 + "]" * 200000))
        self.assertEqual((ov, len(warnings)), ({}, 1))

    def test_unknown_value_forces_none(self):
        ov, warnings = load_overrides(tmp_path_with(json.dumps({"openjdk": {"21": "unknown"}})))
        self.assertEqual((ov, warnings), ({("openjdk", 21): None}, []))
    def test_override_value_used(self):
        ov, _ = load_overrides(tmp_path_with(json.dumps({"oracle": {"17": "17.0.21.2"}})))
        row = {"java_version_raw": "17.0.21.1+2", "java_vendor": "Oracle Java", "java_path": "/opt/jdk-17/"}
        cond, fixed = assess_runtime(row, overrides=ov)
        self.assertEqual((cond.value, fixed), ("yes", "17.0.21.2"))


if __name__ == "__main__":
    unittest.main()
