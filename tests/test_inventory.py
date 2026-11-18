from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import findings
import render
from java4shell.versions import assess_runtime
from java4shell.inventory import (
    CONTEXT_PLUGINS,
    JAVA_PLUGINS,
    VENDOR_BY_PLUGIN,
    build_findings,
    parse_asset_info,
    parse_cpu_models,
    parse_java_detection,
    parse_os,
    parse_process_list,
    parse_windows_arch,
)

FIXTURES = Path(__file__).parent / "fixtures"

LINUX_PATH = "/usr/lib/jvm/java-21-openjdk-amd64/"
LINUX_BIN = "/usr/lib/jvm/java-21-openjdk-amd64/bin/java"

TWO_INSTALLS = f"""
Nessus detected 2 installs of Java:

  Path             : {LINUX_PATH}
  Version          : 21.0.13
  Application      : OpenJDK Java
  Binary Location  : {LINUX_BIN}
  Details          : This Java install appears to be OpenJDK due to the install directory
                     name (high confidence).
  Detection Method : "locate" utility
  Managed by OS    : True

  Path             : /opt/vendor/app/jbr/
  Version          : 11.0.20.1
  Binary Location  : /opt/vendor/app/jbr/bin/java
  Details          : This Java install may be openjdk, as neither "Oracle" nor "Sun" are
                     found in the binary (low confidence).
  Detection Method : "find" utility
"""

TRUNCATED = """
Nessus detected 2 installs of Java:

  Path             : /usr/lib/jvm/java-21-openjdk-amd64/
  Version          : 21.0.13
  Application      : OpenJDK Java
  Binary Location  : /usr/lib/jvm/java-21-openjdk-amd64/bin/java
  Details          : This Java install appears to be OpenJDK (high confidence).
  Managed by OS    : False

  Path             : /opt/vendor/app/jbr/
  Version          : 17.0.1
    ... (truncated)
"""

SAME_INSTALL_HIGH = f"""
  Path             : {LINUX_PATH}
  Version          : 21.0.13
  Application      : OpenJDK Java
  Binary Location  : {LINUX_BIN}
  Details          : This Java install appears to be OpenJDK (high confidence).
"""

SAME_INSTALL_LOW = f"""
  Path             : {LINUX_PATH.rstrip("/")}
  Version          : 21.0.13
  Application      : Some Other Java
  Details          : This Java install may be openjdk (low confidence).
"""


def rec(plugin_id: str, output: str, asset_id: str = "a-1", last_seen: str = "2026-11-18T08:00:00Z",
        **kw) -> dict:
    row = {"asset_id": asset_id, "asset": "app01", "ip": "192.0.2.11", "fqdn": "app01.example.test",
           "plugin_id": plugin_id, "output": output, "last_seen": last_seen}
    row.update(kw)
    return row


class ParseJavaDetectionTests(unittest.TestCase):
    def test_two_installs_parsed(self) -> None:
        installs = parse_java_detection(TWO_INSTALLS)
        self.assertEqual(len(installs), 2)
        first, second = installs
        self.assertEqual(first["java_path"], LINUX_PATH)
        self.assertEqual(first["java_version_raw"], "21.0.13")
        self.assertEqual(first["java_vendor"], "OpenJDK Java")
        self.assertEqual(first["java_binary"], LINUX_BIN)
        self.assertEqual(first["vendor_confidence"], "high")
        self.assertIs(first["managed_by_os"], True)
        self.assertFalse(first["truncated"])
        self.assertEqual(second["java_path"], "/opt/vendor/app/jbr/")
        self.assertEqual(second["java_version_raw"], "11.0.20.1")
        self.assertEqual(second["java_vendor"], "")
        self.assertEqual(second["vendor_confidence"], "low")
        self.assertIsNone(second["managed_by_os"])

    def test_truncated_install_kept(self) -> None:
        installs = parse_java_detection(TRUNCATED)
        self.assertEqual(len(installs), 2)
        self.assertIs(installs[0]["managed_by_os"], False)
        self.assertFalse(installs[0]["truncated"])
        self.assertTrue(installs[1]["truncated"])
        self.assertEqual(installs[1]["java_path"], "/opt/vendor/app/jbr/")
        # The value right before the cut may be incomplete, so it is dropped.
        self.assertEqual(installs[1]["java_version_raw"], "")
        self.assertEqual(installs[1]["java_binary"], "")
        self.assertEqual(installs[1]["vendor_confidence"], "")

    def test_truncated_last_value_blanked(self) -> None:
        output = ("  Path             : /opt/a/\n  Version          : 17.0.12\n"
                  "  Application      : Orac\n    ... (truncated)\n")
        (install,) = parse_java_detection(output)
        self.assertEqual(install["java_vendor"], "")
        self.assertEqual(install["java_version_raw"], "17.0.12")
        self.assertEqual(install["java_path"], "/opt/a/")
        self.assertTrue(install["truncated"])
        # No header says how many installs there were, so a cut-off placeholder follows the install.
        row, cut = build_findings([rec("147817", output)], [])
        self.assertEqual(cut["java_path"], "")
        self.assertEqual(row["java_vendor"], "")
        self.assertIs(row["truncated"], True)

    def test_truncated_wrapped_binary_line_dropped(self) -> None:
        output = ("  Path             : C:\\Java\\jre8\\\n  Version          : 8.0.371.4\n"
                  "  Binary Location  : C:\\Java\\jre8\\bin\\java.exe\n"
                  "                     C:\\Ja\n    ... (truncated)\n")
        (install,) = parse_java_detection(output)
        self.assertEqual(install["java_binary"], "C:\\Java\\jre8\\bin\\java.exe")
        self.assertEqual(install["java_version_raw"], "8.0.371.4")
        output = "  Path             : /opt/a/\n  Binary Location  : /opt/a/b\n    ... (truncated)\n"
        (install,) = parse_java_detection(output)
        self.assertEqual(install["java_binary"], "")

    def test_truncated_path_blanked(self) -> None:
        output = SAME_INSTALL_HIGH + "\n  Path             : /opt/vendor/ap\n    ... (truncated)\n"
        installs = parse_java_detection(output)
        self.assertEqual([i["java_path"] for i in installs], [LINUX_PATH, ""])
        self.assertEqual([i["truncated"] for i in installs], [False, True])

    def test_partial_label_does_not_blank_previous_value(self) -> None:
        output = "  Path             : /opt/a/\n  Version          : 17.0.12\n  Applica\n    ... (truncated)\n"
        (install,) = parse_java_detection(output)
        self.assertEqual(install["java_version_raw"], "17.0.12")
        self.assertTrue(install["truncated"])

    def test_inline_truncation_marker_blanks_value(self) -> None:
        output = "  Path             : /opt/a/\n  Version          : 17.0... (truncated)"
        (install,) = parse_java_detection(output)
        self.assertEqual(install["java_version_raw"], "")
        self.assertTrue(install["truncated"])

    def test_empty_version_before_truncation(self) -> None:
        output = "  Path             : /opt/a/\n  Version          :\n    ... (truncated)\n"
        installs = parse_java_detection(output)
        self.assertEqual(len(installs), 1)
        self.assertEqual(installs[0]["java_version_raw"], "")
        self.assertTrue(installs[0]["truncated"])

    def test_windows_paths_and_wrapped_binary_lines(self) -> None:
        output = (
            "  Path             : C:\\Program Files\\Java\\jre1.8.0_371\\\n"
            "  Version          : 8.0.371.4\n"
            "  Application      : Oracle Java\n"
            "  Binary Location  : C:\\Program Files\\Java\\jre1.8.0_371\\bin\\java.exe\n"
            "                     C:\\Program Files\\Java\\jre1.8.0_371\\bin\\javaw.exe\n"
            "  Details          : This Java install appears to be Oracle Java, confirmed by\n"
            "                     associated files (high\n"
            "                     confidence).\n"
            "  Detection Method : Found in Registry\n\n\n\n"
        )
        (install,) = parse_java_detection(output)
        self.assertEqual(install["java_path"], "C:\\Program Files\\Java\\jre1.8.0_371\\")
        self.assertEqual(install["java_binary"], "C:\\Program Files\\Java\\jre1.8.0_371\\bin\\java.exe")
        self.assertEqual(install["vendor_confidence"], "high")
        self.assertIsNone(install["managed_by_os"])
        self.assertFalse(install["truncated"])

    def test_tolerates_extra_spaces_and_odd_version(self) -> None:
        output = "Path      :   /opt/zulu/  \nVersion  :  17.62.17 (CA)\nManaged by OS : true\n"
        (install,) = parse_java_detection(output)
        self.assertEqual(install["java_path"], "/opt/zulu/")
        self.assertEqual(install["java_version_raw"], "17.62.17 (CA)")
        self.assertIs(install["managed_by_os"], True)

    def test_empty_and_unrelated_output(self) -> None:
        self.assertEqual(parse_java_detection(""), [])
        self.assertEqual(parse_java_detection("The remote host has no Java.\n"), [])


class ContextParserTests(unittest.TestCase):
    def test_cpu_models_one_per_processor(self) -> None:
        output = ("Processor Information:\n\n  Version : Intel(R) Xeon(R) Gold 6430\n"
                  "  Version : AMD EPYC 9654 96-Core Processor\n")
        self.assertEqual(parse_cpu_models(output),
                         ["Intel(R) Xeon(R) Gold 6430", "AMD EPYC 9654 96-Core Processor"])

    def test_windows_arch(self) -> None:
        self.assertEqual(parse_windows_arch("OS Version : 10.0\nArchitecture : x64\n"), "x64")
        self.assertEqual(parse_windows_arch("nothing here"), "")

    def test_windows_arch_equals_separator(self) -> None:
        output = "Operating system version = 10.0\nArchitecture = x64\nBuild lab extended = x\n"
        self.assertEqual(parse_windows_arch(output), "x64")
        self.assertEqual(parse_windows_arch("Architecture=x86\n"), "x86")

    def test_os_first_value(self) -> None:
        output = ("Remote operating system : Microsoft Windows Server 2022 Standard\n"
                  "Confidence level : 99\nMethod : SMB\n\n"
                  "Remote operating system : something else\n")
        self.assertEqual(parse_os(output), "Microsoft Windows Server 2022 Standard")
        self.assertEqual(parse_os(""), "")

    def test_asset_info_os_and_arch(self) -> None:
        def info(os_line: str) -> str:
            return ("Asset Information: 00000000-0000-4000-8000-000000000001\n"
                    "Hostnames: app01\nIPv4 Addresses: 192.0.2.10\nFQDN: N/A\n"
                    f"Operating System: {os_line}\nMAC Addresses: N/A\n")
        centos = "CentOS Linux 7.9.2009, Linux Kernel 3.10.0-1160.99.1.el7.x86_64 on CentOS Linux release 7.9.2009 (Core)"
        self.assertEqual(parse_asset_info(info(centos)), (centos, "x64"))
        self.assertEqual(parse_asset_info(info("Linux Kernel 6.1.0-18-arm64 on Debian 12"))[1], "arm64")
        self.assertEqual(parse_asset_info(info("Linux Kernel 5.14.0-362.el9.aarch64 on Rocky Linux 9"))[1], "arm64")
        self.assertEqual(parse_asset_info(info("Linux Kernel 2.6.32-754.el6.i686 on CentOS release 6.10"))[1], "x86")
        self.assertEqual(parse_asset_info(info("Linux Kernel 5.4.0-150-generic on Ubuntu 20.04"))[1], "")
        self.assertEqual(parse_asset_info(info("Microsoft Windows Server 2022 Standard"))[1], "")
        self.assertEqual(parse_asset_info(info("N/A")), ("", ""))
        self.assertEqual(parse_asset_info(""), ("", ""))
        # A word that merely contains an arch token is not an arch.
        self.assertEqual(parse_asset_info(info("Linux Kernel 5.15 on x86_64ish appliance"))[1], "")

    def test_asset_info_fills_row_context(self) -> None:
        det = {"asset_id": "a-301", "asset": "app01", "ip": "192.0.2.31", "fqdn": "",
               "plugin_id": "147817", "output": TWO_INSTALLS, "last_seen": "2026-11-18T00:00:00Z"}
        ai = {"asset_id": "a-301", "asset": "app01", "ip": "192.0.2.31", "fqdn": "",
              "plugin_id": "asset_info", "last_seen": "",
              "output": "Hostnames: app01\nOperating System: Linux Kernel 5.14.0-362.el9.aarch64 on Rocky Linux 9\n"}
        rows = build_findings([det, ai], [])
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual(row["arch"], "arm64")
            self.assertIn("Rocky Linux 9", row["os"])
        # An asset-info record alone never creates a row.
        self.assertEqual(build_findings([ai], []), [])

    def test_windows_arch_plugin_beats_asset_info(self) -> None:
        det = {"asset_id": "a-302", "asset": "win01", "ip": "192.0.2.32", "fqdn": "",
               "plugin_id": "148499", "last_seen": "",
               "output": "  Path : C:\\Program Files\\Java\\jdk-21\\\n  Version : 21.0.6.7\n"}
        arch = {"asset_id": "a-302", "plugin_id": "48942", "last_seen": "", "asset": "win01", "ip": "",
                "fqdn": "", "output": "Architecture = x86\n"}
        ai = {"asset_id": "a-302", "plugin_id": "asset_info", "last_seen": "", "asset": "win01", "ip": "",
              "fqdn": "", "output": "Operating System: Linux Kernel 5.14.0.x86_64 on Something\n"}
        for order in ([det, ai, arch], [det, arch, ai]):
            rows = build_findings(order, [])
            self.assertEqual({r["arch"] for r in rows}, {"x86"})

    def test_plugin_tables(self) -> None:
        self.assertIn("147817", JAVA_PLUGINS)
        self.assertEqual(len(JAVA_PLUGINS), 16)
        self.assertEqual(CONTEXT_PLUGINS["20094"], "vmware")
        self.assertEqual(CONTEXT_PLUGINS["110483"], "processes")


PS_HEADER = "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
PS_OUTPUT = (
    "Running processes:\n\n" + PS_HEADER
    + "root           1  0.0  0.1 167744 11904 ?        Ss   Nov17   0:04 /sbin/init\n"
    + "svc-app     2101  3.2 12.0 9876543 987654 ?      Sl   Nov17  42:10 "
      f"{LINUX_BIN} -Xmx2g -XX:-UseBASE64Intrinsics -jar app.jar -XX:NotAJvmFlag\n"
    + "svc-app     2202  0.1  1.0 4567890 123456 ?      Sl   Nov17   1:02 java -XX:UseAVX=2 -jar other.jar\n"
    + "svc-ci      2303  0.4  2.0 5678901 234567 ?      Sl   Nov17   3:33 /opt/vendor/app/jbr/bin/java "
      "-cp /opt/vendor/app/lib/x.jar -XX:+UseG1GC com.example.Main\n"
)


class ProcessListTests(unittest.TestCase):
    def test_parse_process_list(self) -> None:
        flags = parse_process_list(PS_OUTPUT)
        self.assertEqual(flags, {
            "/usr/lib/jvm/java-21-openjdk-amd64": ("-XX:-UseBASE64Intrinsics",),
            "/opt/vendor/app/jbr": ("-XX:+UseG1GC",),
        })

    def test_bare_java_and_noise_skipped(self) -> None:
        self.assertEqual(parse_process_list(""), {})
        self.assertEqual(parse_process_list(PS_HEADER + "u 1 0 0 1 1 ? S Nov17 0:00 java -XX:UseAVX=2 -jar a.jar\n"), {})
        self.assertEqual(parse_process_list("no process table here\n"), {})

    def test_flags_merge_across_processes(self) -> None:
        out = (PS_HEADER
               + f"u 1 0 0 1 1 ? S Nov17 0:00 {LINUX_BIN} -XX:UseAVX=2 -jar a.jar\n"
               + f"u 2 0 0 1 1 ? S Nov17 0:00 {LINUX_BIN} -XX:-UseBASE64Intrinsics -XX:UseAVX=2 -jar b.jar\n")
        self.assertEqual(parse_process_list(out)["/usr/lib/jvm/java-21-openjdk-amd64"],
                         ("-XX:UseAVX=2", "-XX:-UseBASE64Intrinsics"))

    def test_process_list_flags(self) -> None:
        rows = build_findings([rec("147817", TWO_INSTALLS), rec("110483", PS_OUTPUT)], [])
        by_path = {r["java_path"]: r for r in rows}
        self.assertEqual(by_path[LINUX_PATH]["cmdline_flags"], ["-XX:-UseBASE64Intrinsics"])
        self.assertEqual(by_path["/opt/vendor/app/jbr/"]["cmdline_flags"], ["-XX:+UseG1GC"])

    def test_process_list_does_not_cross_assets(self) -> None:
        rows = build_findings([rec("147817", TWO_INSTALLS), rec("110483", PS_OUTPUT, asset_id="a-2")], [])
        self.assertTrue(all("cmdline_flags" not in r for r in rows))
        self.assertEqual(len(rows), 2)

    def test_unmatched_binary_not_attached(self) -> None:
        other = PS_HEADER + "u 1 0 0 1 1 ? S Nov17 0:00 /opt/other/bin/java -XX:UseAVX=2 -jar a.jar\n"
        rows = build_findings([rec("147817", TWO_INSTALLS), rec("110483", other)], [])
        self.assertTrue(all("cmdline_flags" not in r for r in rows))


NO_APPLICATION = """
  Path             : /opt/java/runtime/
  Version          : 21.0.6
  Binary Location  : /opt/java/runtime/bin/java
  Details          : Found by its install directory (high confidence).
"""


class VendorFromPluginTests(unittest.TestCase):
    def test_vendor_table(self) -> None:
        self.assertEqual(VENDOR_BY_PLUGIN, {
            "64815": "Oracle Java", "33545": "Oracle Java",
            "148373": "OpenJDK Java", "148707": "OpenJDK Java",
            "169699": "Temurin Java", "171539": "Temurin Java",
            "148374": "Azul Zulu Java", "148706": "Azul Zulu Java",
            "148376": "Amazon Corretto Java", "148708": "Amazon Corretto Java",
            "148375": "AdoptOpenJDK Java", "148705": "AdoptOpenJDK Java",
            "148372": "IBM Java", "148709": "IBM Java",
        })
        self.assertTrue(set(VENDOR_BY_PLUGIN) <= JAVA_PLUGINS)

    def test_vendor_from_plugin_when_application_missing(self) -> None:
        (row,) = build_findings([rec("148373", NO_APPLICATION)], [])
        self.assertEqual(row["java_vendor"], "OpenJDK Java")
        for plugin, vendor in VENDOR_BY_PLUGIN.items():
            (row,) = build_findings([rec(plugin, NO_APPLICATION)], [])
            self.assertEqual(row["java_vendor"], vendor, plugin)
        for plugin in ("147817", "148499"):
            (row,) = build_findings([rec(plugin, NO_APPLICATION)], [])
            self.assertEqual(row["java_vendor"], "", plugin)

    def test_application_line_wins_over_plugin(self) -> None:
        (row,) = build_findings([rec("148373", SAME_INSTALL_HIGH.replace("OpenJDK Java", "Red Hat OpenJDK"))], [])
        self.assertEqual(row["java_vendor"], "Red Hat OpenJDK")
        # Another plugin's Application line beats the vendor implied by a plugin ID.
        generic = NO_APPLICATION.replace("  Binary", "  Application      : Eclipse Temurin\n  Binary")
        rows = build_findings([rec("148373", NO_APPLICATION), rec("147817", generic)], [])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["java_vendor"], "Eclipse Temurin")

    def _r(self, plugin: str, path: str, version: str):
        output = f"  Path             : {path}\n  Version          : {version}\n"
        (row,) = build_findings([rec(plugin, output)], [])
        return row, assess_runtime(row)[0]

    def test_path_vendor_not_hidden_by_plugin_vendor(self) -> None:
        for plugin, path in (("148373", "/opt/graalvm-jdk-21/"), ("148373", "/opt/ibm/semeru-jdk-21/"),
                             ("64815", "/opt/oracle/graalvm-jdk-21/")):
            row, r = self._r(plugin, path, "21.0.14")
            self.assertEqual(row["java_vendor"], "", path)
            self.assertEqual(r.value, "unknown", path)

    def test_matching_path_vendor_keeps_plugin_vendor(self) -> None:
        row, _ = self._r("148373", "/usr/lib/jvm/java-21-openjdk-amd64/", "21.0.14")
        self.assertEqual(row["java_vendor"], "OpenJDK Java")
        row, _ = self._r("169699", "/opt/temurin-21/", "21.0.14")
        self.assertEqual(row["java_vendor"], "Temurin Java")

    def test_prime_path_keeps_prime_rule(self) -> None:
        for path, version in (("/opt/zing/zing-jdk11/", "11.0.20"), ("/opt/azul-prime-21/", "21.0.14")):
            row, r = self._r("148374", path, version)
            self.assertEqual(row["java_vendor"], "", path)
            self.assertNotEqual(r.value, "no", path)
            self.assertIn("Prime", r.evidence, path)

    def test_truncated_vendor_falls_back_to_plugin(self) -> None:
        output = "  Path             : /opt/a/\n  Version          : 8.0.371\n  Application      : O\n    ... (truncated)\n"
        row = build_findings([rec("33545", output)], [])[0]
        self.assertEqual(row["java_vendor"], "Oracle Java")

    def test_placeholder_gets_plugin_vendor(self) -> None:
        (row,) = build_findings([rec("148374", "")], [])
        self.assertEqual(row["java_vendor"], "Azul Zulu Java")
        self.assertIs(row["no_output"], True)


class BuildFindingsTests(unittest.TestCase):
    def test_row_shape_and_values(self) -> None:
        rows = build_findings([rec("147817", TWO_INSTALLS)], [])
        self.assertEqual(len(rows), 2)
        row = rows[0]
        for key in render.FIELDS + ["plugin_output", "truncated", "no_output"]:
            if key != "cmdline_flags":  # only set when the process list names the install
                self.assertIn(key, row)
        self.assertEqual(row["asset_id"], "a-1")
        self.assertEqual(row["asset"], "app01")
        self.assertEqual(row["ip"], "192.0.2.11")
        self.assertEqual(row["fqdn"], "app01.example.test")
        self.assertEqual(row["detection_plugin"], "147817")
        self.assertEqual(row["last_seen"], "2026-11-18T08:00:00Z")
        self.assertEqual(row["plugin_output"], TWO_INSTALLS)
        self.assertEqual(row["cve_plugins"], [])
        self.assertIs(row["no_output"], False)
        self.assertIs(row["managed_by_os"], True)
        self.assertIsNone(rows[1]["managed_by_os"])
        json.dumps(rows)

    def test_dedupe_across_plugins(self) -> None:
        # The low-confidence report arrives first and carries no binary line.
        rows = build_findings([rec("148373", SAME_INSTALL_LOW), rec("147817", SAME_INSTALL_HIGH)], [])
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["detection_plugin"], "147817,148373")
        self.assertEqual(row["java_vendor"], "OpenJDK Java")
        self.assertEqual(row["vendor_confidence"], "high")
        self.assertEqual(row["java_binary"], LINUX_BIN)

    def test_conflicting_versions_are_not_resolved_by_rank(self) -> None:
        low = SAME_INSTALL_LOW.replace("21.0.13", "21.0.14")
        rows = build_findings([rec("147817", SAME_INSTALL_HIGH), rec("148373", low)], [])
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["java_version_raw"], "")
        self.assertEqual(row["version_conflict"], "21.0.13 vs 21.0.14")
        r = assess_runtime(row)[0]
        self.assertEqual((r.value, r.evidence), ("unknown", "plugins disagree: 21.0.13 vs 21.0.14"))
        (out,) = render.enrich(rows, {})
        self.assertEqual(out["verdict"], "Unknown \u2013 verify")
        self.assertEqual(out["reason"], "plugins disagree: 21.0.13 vs 21.0.14")

    def test_same_version_in_other_forms_is_not_a_conflict(self) -> None:
        for high, low in (("17.0.11+9", "17.0.11.9"), ("1.8.0_402-b06", "8.0.402.6"), ("21.0.13", "21.0.13+11"),
                          ("21.0.13", "")):
            rows = build_findings([rec("147817", SAME_INSTALL_HIGH.replace("21.0.13", high)),
                                   rec("148373", SAME_INSTALL_LOW.replace("21.0.13", low))], [])
            self.assertEqual(rows[0]["version_conflict"], "", (high, low))
            self.assertEqual(rows[0]["java_version_raw"], high, (high, low))

    def test_four_part_build_disagrees_with_patch(self) -> None:
        rows = build_findings([rec("147817", SAME_INSTALL_HIGH.replace("21.0.13", "21.0.13.1+2")),
                               rec("148373", SAME_INSTALL_LOW.replace("21.0.13", "21.0.13.9"))], [])
        self.assertEqual(rows[0]["version_conflict"], "21.0.13.1+2 vs 21.0.13.9")

    def test_version_conflict_defaults_empty(self) -> None:
        (row,) = build_findings([rec("147817", SAME_INSTALL_HIGH)], [])
        self.assertEqual(row["version_conflict"], "")
        (row,) = build_findings([rec("147817", "")], [])
        self.assertEqual(row["version_conflict"], "")

    def test_dedupe_fills_blank_fields_from_other_plugin(self) -> None:
        low_with_binary = SAME_INSTALL_LOW + f"  Binary Location  : {LINUX_BIN}\n"
        high_no_binary = SAME_INSTALL_HIGH.replace(f"  Binary Location  : {LINUX_BIN}\n", "")
        rows = build_findings([rec("147817", high_no_binary), rec("148373", low_with_binary)], [])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["java_vendor"], "OpenJDK Java")
        self.assertEqual(rows[0]["java_binary"], LINUX_BIN)

    def test_same_path_on_different_assets_not_merged(self) -> None:
        rows = build_findings([rec("147817", SAME_INSTALL_HIGH, asset_id="a-1"),
                               rec("147817", SAME_INSTALL_HIGH, asset_id="a-2")], [])
        self.assertEqual(len(rows), 2)

    def test_context_attached(self) -> None:
        outputs = [
            rec("147817", SAME_INSTALL_HIGH),
            rec("45432", "Version : Intel(R) Xeon(R) Gold 6430\nVersion : AMD EPYC 9654\n"),
            rec("20094", "The remote host is a VMware virtual machine.\n"),
            rec("48942", "Architecture : x64\n"),
            rec("11936", "Remote operating system : Oracle Linux 9\nConfidence level : 95\n"),
        ]
        (row,) = build_findings(outputs, [])
        self.assertEqual(row["cpu_model"], "Intel(R) Xeon(R) Gold 6430;AMD EPYC 9654")
        self.assertEqual(row["virtualization"], "VMware")
        self.assertEqual(row["arch"], "x64")
        self.assertEqual(row["os"], "Oracle Linux 9")

    def test_context_defaults_and_xen(self) -> None:
        (row,) = build_findings([rec("147817", SAME_INSTALL_HIGH)], [])
        self.assertEqual((row["cpu_model"], row["arch"], row["os"], row["virtualization"]), ("", "", "", ""))
        (row,) = build_findings([rec("147817", SAME_INSTALL_HIGH), rec("35081", "Xen guest")], [])
        self.assertEqual(row["virtualization"], "Xen")

    def test_context_does_not_cross_assets(self) -> None:
        rows = build_findings([rec("147817", SAME_INSTALL_HIGH, asset_id="a-1"),
                               rec("20094", "VMware", asset_id="a-2")], [])
        self.assertEqual(rows[0]["virtualization"], "")

    def test_cve_plugins_attached(self) -> None:
        cve = [{"asset_id": "a-1", "plugin_id": "382091", "state": "ACTIVE"},
               {"asset_id": "a-1", "plugin_id": 382045, "state": "RESURFACED"},
               {"asset_id": "a-1", "plugin_id": "382091", "state": "ACTIVE"},
               {"asset_id": "a-2", "plugin_id": "999", "state": "ACTIVE"}]
        (row,) = build_findings([rec("147817", SAME_INSTALL_HIGH)], cve)
        self.assertEqual(row["asset_cve_plugins"], ["382091", "382045"])
        # An OpenJDK install not managed by the OS is in scope for neither plugin.
        self.assertEqual(row["cve_plugins"], [])

    def test_cve_plugins_attached_by_scope(self) -> None:
        oracle = SAME_INSTALL_HIGH.replace(LINUX_PATH, "/opt/oracle/jdk-17/").replace(
            "OpenJDK Java", "Oracle Java").replace(LINUX_BIN, "/opt/oracle/jdk-17/bin/java")
        corretto = SAME_INSTALL_HIGH.replace(LINUX_PATH, "/opt/corretto-17/").replace(
            "OpenJDK Java", "Amazon Corretto Java").replace(LINUX_BIN, "/opt/corretto-17/bin/java")
        managed = SAME_INSTALL_HIGH + "  Managed by OS    : True\n"
        cve = [{"asset_id": "a-1", "plugin_id": p, "state": "ACTIVE"}
               for p in ("382091", "382045", "382312", "382347", "382319", "382332", "382309", "382489", "399999")]
        rows = build_findings([rec("147817", oracle + "\n" + corretto + "\n" + managed)], cve)
        by_path = {r["java_path"]: r["cve_plugins"] for r in rows}
        self.assertEqual(by_path["/opt/oracle/jdk-17/"], ["382091", "399999"])
        self.assertEqual(by_path["/opt/corretto-17/"],
                         ["382045", "382312", "382347", "382319", "382332", "382309", "399999"])
        self.assertEqual(by_path[LINUX_PATH],
                         ["382045", "382312", "382347", "382319", "382332", "382309", "382489", "399999"])
        self.assertTrue(all(r["asset_cve_plugins"] == [c["plugin_id"] for c in cve] for r in rows))

    def test_fixed_cve_findings_ignored(self) -> None:
        cve = [{"asset_id": "a-1", "plugin_id": "382091", "state": "FIXED"}]
        (row,) = build_findings([rec("147817", SAME_INSTALL_HIGH)], cve)
        self.assertEqual(row["cve_plugins"], [])
        self.assertEqual(row["asset_cve_plugins"], [])

    def test_new_and_other_cve_states_kept(self) -> None:
        cve = [{"asset_id": "a-1", "plugin_id": "382091", "state": "FIXED"},
               {"asset_id": "a-1", "plugin_id": "382045", "state": "NEW"},
               {"asset_id": "a-1", "plugin_id": "999001", "state": "reopened"}]
        (row,) = build_findings([rec("147817", SAME_INSTALL_HIGH)], cve)
        self.assertEqual(row["asset_cve_plugins"], ["382045", "999001"])
        self.assertEqual(row["cve_plugins"], ["999001"])

    def test_pathless_truncated_install_kept_as_row(self) -> None:
        (row,) = build_findings([rec("147817", "  Path             :\n    ... (truncated)\n")], [])
        self.assertEqual(row["asset_id"], "a-1")
        self.assertIs(row["truncated"], True)
        self.assertIs(row["no_output"], False)
        self.assertEqual((row["java_path"], row["java_binary"]), ("", ""))

    def test_pathless_install_does_not_hide_other_installs(self) -> None:
        output = SAME_INSTALL_HIGH + "\n  Path             :\n    ... (truncated)\n"
        rows = build_findings([rec("147817", output)], [])
        self.assertEqual(len(rows), 2)
        self.assertEqual([r["truncated"] for r in rows], [False, True])

    def test_cut_inside_label_keeps_asset(self) -> None:
        (row,) = build_findings([rec("147817", "  Pa")], [])
        self.assertEqual(row["asset_id"], "a-1")
        self.assertIs(row["no_output"], True)
        self.assertIs(row["truncated"], False)

    def test_cut_before_any_install_flags_truncated(self) -> None:
        (row,) = build_findings([rec("147817", "Nessus detected 3 installs of Java:\n    ... (truncated)")], [])
        self.assertIs(row["truncated"], True)
        self.assertIs(row["no_output"], False)

    def test_unrecognised_output_keeps_asset(self) -> None:
        (row,) = build_findings([rec("147817", "The remote host reported something unexpected.\n")], [])
        self.assertEqual(row["asset_id"], "a-1")
        self.assertIs(row["no_output"], True)

    def test_non_java_plugin_makes_no_rows(self) -> None:
        self.assertEqual(build_findings([rec("45432", "Version : X\n")], []), [])

    def test_truncated_flag_carried(self) -> None:
        rows = build_findings([rec("147817", TRUNCATED)], [])
        self.assertEqual([r["truncated"] for r in rows], [False, True])

    def test_last_seen_newest_wins_on_merge(self) -> None:
        rows = build_findings([rec("147817", SAME_INSTALL_HIGH, last_seen="2026-11-01T00:00:00Z"),
                               rec("148373", SAME_INSTALL_LOW, last_seen="2026-11-17T00:00:00Z")], [])
        self.assertEqual(rows[0]["last_seen"], "2026-11-17T00:00:00Z")

    def test_empty_output_gives_placeholder_row(self) -> None:
        rows = build_findings([rec("147817", "")], [])
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertIs(row["no_output"], True)
        self.assertEqual(row["detection_plugin"], "147817")
        for key in ("java_path", "java_version_raw", "java_vendor", "java_binary"):
            self.assertEqual(row[key], "")
        self.assertIsNone(row["managed_by_os"])
        self.assertIs(row["truncated"], False)
        self.assertEqual(row["asset_id"], "a-1")

    def test_placeholder_one_per_asset_and_plugin(self) -> None:
        rows = build_findings([rec("147817", ""), rec("147817", "  \n"), rec("148373", "")], [])
        self.assertEqual(sorted(r["detection_plugin"] for r in rows), ["147817", "148373"])

    def test_placeholder_dropped_when_install_parsed(self) -> None:
        # The same plugin parsed an install on this asset in another record.
        rows = build_findings([rec("148373", ""), rec("148373", SAME_INSTALL_HIGH)], [])
        self.assertEqual(len(rows), 1)
        self.assertIs(rows[0]["no_output"], False)
        self.assertEqual(rows[0]["detection_plugin"], "148373")
        # A complete unified detection output covers every vendor on the asset.
        for unified in ("147817", "148499"):
            rows = build_findings([rec("148373", ""), rec(unified, SAME_INSTALL_HIGH)], [])
            self.assertEqual(len(rows), 1, unified)
            self.assertEqual(rows[0]["detection_plugin"], unified)

    def test_placeholder_kept_when_another_vendor_plugin_parsed(self) -> None:
        oracle8 = ("  Path             : /opt/oracle/jre1.8.0_402/\n  Version          : 8.0.402.6\n"
                   "  Application      : Oracle Java\n"
                   "  Binary Location  : /opt/oracle/jre1.8.0_402/bin/java\n")
        rows = build_findings([rec("64815", oracle8), rec("148373", "")], [])
        self.assertEqual(len(rows), 2)
        placeholder = next(r for r in rows if r["no_output"])
        self.assertEqual(placeholder["detection_plugin"], "148373")
        enriched = render.enrich(rows, {})
        self.assertNotIn("Not impacted", render.asset_rollup(enriched))
        held = next(r for r in enriched if r["no_output"])
        self.assertEqual(held["r"], "unknown")
        self.assertEqual(held["r_evidence"], "plugin 148373 output not retrieved")

    def test_placeholder_kept_when_unified_output_truncated(self) -> None:
        rows = build_findings([rec("148373", ""), rec("147817", TRUNCATED)], [])
        self.assertIn("148373", [r["detection_plugin"] for r in rows if r["no_output"]])

    def test_cut_off_installs_get_a_placeholder(self) -> None:
        output = ("Nessus detected 3 installs of Java:\n\n"
                  "  Path             : /usr/lib/jvm/java-8-openjdk-amd64/\n"
                  "  Version          : 8.0.402\n"
                  "  Application      : OpenJDK Java\n"
                  "  Details          : This Java install appears to be OpenJDK due to the inst\n"
                  "    ... (truncated)\n")
        rows = build_findings([rec("147817", output)], [])
        self.assertEqual(len(rows), 2)
        cut = [r for r in rows if not r["java_path"]]
        self.assertEqual(len(cut), 1)
        self.assertIs(cut[0]["truncated"], True)
        self.assertIs(cut[0]["no_output"], False)
        self.assertEqual(cut[0]["detection_plugin"], "147817")
        enriched = render.enrich(rows, {})
        self.assertNotIn("Not impacted", render.asset_rollup(enriched))
        held = next(r for r in enriched if not r["java_path"])
        self.assertEqual(held["r_evidence"], "installs cut off in plugin output")

    def test_cut_off_single_install_without_header_gets_placeholder(self) -> None:
        output = ("  Path             : /opt/a/\n  Version          : 11.0.20\n"
                  "  Details          : This Java install appears to\n    ... (truncated)\n")
        rows = build_findings([rec("147817", output)], [])
        self.assertEqual(len(rows), 2)
        self.assertNotIn("Not impacted", render.asset_rollup(render.enrich(rows, {})))

    def test_no_placeholder_when_header_count_reached(self) -> None:
        # Both installs announced by the header were read; only the last one is cut short.
        rows = build_findings([rec("147817", TRUNCATED)], [])
        self.assertEqual(len(rows), 2)

    def test_placeholder_kept_for_other_asset(self) -> None:
        rows = build_findings([rec("147817", SAME_INSTALL_HIGH, asset_id="a-1"),
                               rec("147817", "", asset_id="a-2")], [])
        self.assertEqual([r["no_output"] for r in rows], [False, True])


class FindingsCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def run_cli(self, outputs: Path, cve: Path | None = None) -> tuple[str, list[dict]]:
        out = self.tmp / "findings.json"
        argv = ["--outputs", str(outputs), "-o", str(out)]
        if cve is not None:
            argv += ["--cve", str(cve)]
        buf = io.StringIO()
        with redirect_stdout(buf):
            findings.main(argv)
        return buf.getvalue(), json.loads(out.read_text(encoding="utf-8"))

    def test_fixture_run(self) -> None:
        printed, rows = self.run_cli(FIXTURES / "outputs.jsonl", FIXTURES / "cve_findings.json")
        # a-201: 2 installs, a-202: 1 install, a-203: placeholder only and last seen before the CVE plugin,
        # a-204: Oracle 8 plus an unread OpenJDK plugin, a-205: an output cut inside its first of 3 installs,
        # a-206: a cleared OS package flagged by a CVE plugin.
        self.assertEqual(len(rows), 9)
        self.assertEqual(printed.strip(),
                         "assets=6 pairs=9 truncated=2 stale_scans=1 no_output=1 package_only=0 package_unmatched=0")
        by_asset = {}
        for row in rows:
            by_asset.setdefault(row["asset_id"], []).append(row)
        self.assertEqual(by_asset["a-201"][0]["asset_cve_plugins"], ["382091"])
        self.assertEqual(by_asset["a-202"][0]["cve_plugins"], [])
        self.assertEqual(by_asset["a-202"][0]["virtualization"], "VMware")
        self.assertEqual(by_asset["a-202"][0]["arch"], "x64")
        self.assertEqual(by_asset["a-202"][0]["java_path"], "C:\\Program Files\\Java\\jre1.8.0_371\\")
        self.assertIs(by_asset["a-203"][0]["no_output"], True)
        app = {r["java_path"]: r for r in by_asset["a-201"]}
        self.assertEqual(app["/usr/lib/jvm/java-21-openjdk-amd64/"]["cmdline_flags"], ["-XX:-UseBASE64Intrinsics"])
        self.assertNotIn("cmdline_flags", app["/opt/vendor/app/jbr/"])

    def test_stale_scan_count(self) -> None:
        old, new = "2026-11-16T23:59:59Z", "2026-11-17T00:00:00Z"
        outputs = [
            rec("147817", SAME_INSTALL_HIGH, asset_id="a-1", last_seen=old),
            rec("147817", SAME_INSTALL_HIGH, asset_id="a-2", last_seen=new),
            # newest Java detection is fresh, so this asset is not stale
            rec("147817", SAME_INSTALL_HIGH, asset_id="a-3", last_seen=old),
            rec("148373", SAME_INSTALL_LOW, asset_id="a-3", last_seen=new),
            # context plugins do not count as Java detections
            rec("147817", SAME_INSTALL_HIGH, asset_id="a-4", last_seen=old),
            rec("45432", "Version : X\n", asset_id="a-4", last_seen=new),
            rec("147817", SAME_INSTALL_HIGH, asset_id="a-5", last_seen=""),
        ]
        path = self.tmp / "outputs.jsonl"
        path.write_text("".join(json.dumps(r) + "\n" for r in outputs), encoding="utf-8")
        printed, _ = self.run_cli(path)
        self.assertIn("stale_scans=2", printed)

    def test_truncated_count_and_blank_lines(self) -> None:
        path = self.tmp / "outputs.jsonl"
        path.write_text("\n" + json.dumps(rec("147817", TRUNCATED)) + "\n\n", encoding="utf-8")
        printed, rows = self.run_cli(path)
        self.assertIn("truncated=1", printed)
        self.assertEqual(len(rows), 2)

    def test_records_without_identity_rejected(self) -> None:
        nobody = rec("147817", SAME_INSTALL_HIGH, asset_id="", asset="", ip="", fqdn="")
        other = rec("148373", SAME_INSTALL_HIGH.replace(LINUX_PATH, "/opt/x/jdk-17/"), asset_id="", asset="",
                    ip="", fqdn="")
        path = self.tmp / "outputs.jsonl"
        path.write_text("".join(json.dumps(r) + "\n" for r in (nobody, other, rec("147817", SAME_INSTALL_HIGH))),
                        encoding="utf-8")
        printed, rows = self.run_cli(path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["asset_id"], "a-1")
        self.assertIn("WARN: 2 input records have no asset_id, asset or ip; skipped", printed)
        self.assertEqual(build_findings([nobody, other], []), [])

    def test_bad_line_reports_line_number(self) -> None:
        path = self.tmp / "outputs.jsonl"
        path.write_text('{"plugin_id": "147817"}\nnot json\n', encoding="utf-8")
        with self.assertRaises(SystemExit) as ctx:
            self.run_cli(path)
        self.assertIn("2", str(ctx.exception))


class EndToEndTests(unittest.TestCase):
    def test_fixture_outputs_to_verdicts(self) -> None:
        outputs = findings.read_outputs(FIXTURES / "outputs.jsonl")
        cve = findings.read_cve(FIXTURES / "cve_findings.json")
        rows = render.enrich(json.loads(json.dumps(findings.build_findings(outputs, cve))), {})
        by_asset = {}
        for row in rows:
            by_asset.setdefault(row["asset_id"], []).append(row)
        worst = {aid: min((r["verdict"] for r in mine), key=render.ORDER.index) for aid, mine in by_asset.items()}
        self.assertEqual(worst, {
            "a-201": "Affected build \u2013 CPU unconfirmed",
            "a-202": "Not impacted",
            "a-203": "Unknown \u2013 verify",
            "a-204": "Unknown \u2013 verify",   # C1: the unread OpenJDK plugin keeps its row
            "a-205": "Unknown \u2013 verify",   # C2: installs 2 and 3 were cut off
            "a-206": "Unknown \u2013 verify",   # I1: 382489 flags an asset the version rules clear
        })
        self.assertEqual(dict(render.asset_rollup(rows)),
                         {"Affected build \u2013 CPU unconfirmed": 1, "Not impacted": 1, "Unknown \u2013 verify": 4})
        pairs = {}
        for row in rows:
            pairs[row["verdict"]] = pairs.get(row["verdict"], 0) + 1
        self.assertEqual(pairs, {"Affected build \u2013 CPU unconfirmed": 1, "Not impacted": 4, "Unknown \u2013 verify": 4})
        reasons = {r["asset_id"]: r["reason"] for r in rows if r["verdict"] == "Unknown \u2013 verify"}
        self.assertEqual(reasons["a-204"], "plugin 148373 output not retrieved")
        self.assertEqual(reasons["a-205"], "installs cut off in plugin output")
        self.assertEqual(reasons["a-206"], "Tenable plugin 382489 flags this asset")


class RenderCompatTests(unittest.TestCase):
    def test_render_enrich_accepts_built_rows(self) -> None:
        outputs = [json.loads(line) for line in
                   (FIXTURES / "outputs.jsonl").read_text(encoding="utf-8").splitlines()]
        cve = json.loads((FIXTURES / "cve_findings.json").read_text(encoding="utf-8"))
        rows = build_findings(outputs, cve)
        enriched = render.enrich(json.loads(json.dumps(rows)), {})
        self.assertEqual(len(enriched), len(rows))
        self.assertTrue(all(r["verdict"] for r in enriched))


if __name__ == "__main__":
    unittest.main()
