from __future__ import annotations

import csv
import io
import json
import re
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import render

FIXTURES = Path(__file__).parent / "fixtures"


class RenderTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.run_dir = self.tmp / "run"
        self.run_dir.mkdir()
        self.out = self.tmp / "out"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def stage(self, rows: list | None = None) -> Path:
        findings = self.run_dir / "findings.json"
        if rows is None:
            shutil.copy(FIXTURES / "findings.json", findings)
        else:
            findings.write_text(json.dumps(rows), encoding="utf-8")
        return findings

    def run_render(self, findings: Path) -> str:
        buf = io.StringIO()
        with mock.patch.object(render, "find_chrome", return_value=None), redirect_stdout(buf):
            render.main([str(findings), str(self.out)])
        return buf.getvalue()

    def csv_rows(self) -> list[dict]:
        with open(self.out / "report.csv", newline="", encoding="utf-8-sig") as f:
            return list(csv.DictReader(f))

    def html(self) -> str:
        return (self.out / "report.html").read_text(encoding="utf-8")

    def test_outputs_written_and_counts(self) -> None:
        stdout = self.run_render(self.stage())
        self.assertTrue((self.out / "report.csv").exists())
        self.assertTrue((self.out / "report.html").exists())
        expected = len(json.loads((FIXTURES / "findings.json").read_text(encoding="utf-8")))
        self.assertEqual(len(self.csv_rows()), expected)
        self.assertIn("pairs=7", stdout)
        self.assertIn("fixed builds as of 2026-11-18", stdout)

    def test_html_has_no_unsubstituted_placeholders(self) -> None:
        self.run_render(self.stage())
        outside = re.sub(r"<script>.*?</script>", "", self.html(), flags=re.S)
        self.assertIsNone(re.search(r"\$[A-Za-z]", outside))

    def test_rollup_keys_on_asset_id(self) -> None:
        base = {"asset": "dup01", "ip": "192.0.2.70", "fqdn": "", "java_version_raw": "21.0.5",
                "java_path": "/usr/lib/jvm/java-21-openjdk-amd64"}
        rows = render.enrich([dict(base, asset_id="x-1"), dict(base, asset_id="x-2")], {})
        self.assertEqual(sum(render.asset_rollup(rows).values()), 2)

    def test_empty_run_renders(self) -> None:
        stdout = self.run_render(self.stage([]))
        self.assertIn("No Java installs returned by Tenable.", self.html())
        self.assertIn("pairs=0 assets=0", stdout)

    def test_fixed_json_override(self) -> None:
        findings = self.stage()
        (self.run_dir / "fixed.json").write_text(json.dumps({"oracle": {"17": "unknown"}}), encoding="utf-8")
        self.run_render(findings)
        row = next(r for r in self.csv_rows() if r["java_version_raw"] == "17.0.21.1+4")
        self.assertEqual(row["r"], "unknown")

    def test_fixture_verdicts(self) -> None:
        stdout = self.run_render(self.stage())
        rows = self.csv_rows()
        verdicts = {r["asset"]: r["verdict"] for r in rows}
        self.assertEqual(verdicts["app01"], "Affected build \u2013 CPU unconfirmed")
        self.assertEqual(verdicts["WIN01"], "Affected build \u2013 CPU unconfirmed")
        # A unknown with R yes is still an affected build; R unknown is not.
        self.assertEqual(verdicts["ci01"], "Affected build \u2013 CPU unconfirmed")
        self.assertEqual(verdicts["build01"], "Unknown \u2013 verify")
        self.assertEqual(verdicts["db01"], "Not impacted")
        self.assertEqual(verdicts["legacy01"], "Not impacted")
        self.assertIn("  Impacted: 0 assets (0 pairs)", stdout)
        self.assertNotIn("host_check", rows[0])
        self.assertNotIn("Indeterminate", stdout + self.html())
        # Worst first in the CSV.
        self.assertEqual(rows[0]["verdict"], "Affected build \u2013 CPU unconfirmed")

    def test_cmdline_flag_is_evidence_only(self) -> None:
        row = json.loads((FIXTURES / "findings.json").read_text(encoding="utf-8"))[0]
        row["cmdline_flags"] = ["-XX:-UseBASE64Intrinsics"]
        self.run_render(self.stage([row]))
        (out,) = self.csv_rows()
        self.assertEqual(out["verdict"], "Affected build \u2013 CPU unconfirmed")
        self.assertEqual(out["j"], "unknown")
        self.assertIn("confirm with jcmd", out["j_evidence"])
        # A cell that starts with "-" is quoted so a spreadsheet does not read it as a formula.
        self.assertEqual(out["cmdline_flags"], "'-XX:-UseBASE64Intrinsics")

    def test_without_cmdline_flags_no_host(self) -> None:
        row = json.loads((FIXTURES / "findings.json").read_text(encoding="utf-8"))[0]
        (out,) = render.enrich([row], {})
        self.assertEqual(out["j_evidence"], "JVM flags not collected")

    def test_zero_tiles_hidden(self) -> None:
        self.run_render(self.stage())
        tiles = re.search(r'<section class="tiles"[^>]*>(.*?)</section>', self.html(), re.S).group(1)
        captions = re.findall(r'<span class="caption">(.*?)</span>', tiles)
        self.assertNotIn("Impacted", captions)
        self.assertNotIn("Mitigated (temporary)", captions)
        self.assertIn("Affected build \u2013 CPU unconfirmed", captions)
        self.assertIn("Unknown \u2013 verify", captions)
        self.assertIn("Not impacted", captions)
        self.assertIn("Tenable's plugins don't report CPU feature flags or a running JVM's flags yet", self.html())

    def test_nonzero_impacted_tile_shown(self) -> None:
        row = json.loads((FIXTURES / "findings.json").read_text(encoding="utf-8"))[0]
        rows = render.enrich([row], {})
        rows[0]["verdict"] = "Impacted"
        render.write_html(rows, self.tmp / "r.html", "now")
        self.assertIn('<span class="caption">Impacted</span>', (self.tmp / "r.html").read_text(encoding="utf-8"))

    def _cve_row(self, version: str, vendor: str, path: str, plugins: list, asset_id: str = "c-1") -> dict:
        return {"asset_id": asset_id, "asset": "cve01", "ip": "192.0.2.80", "java_version_raw": version,
                "java_vendor": vendor, "java_path": path, "cve_plugins": [], "asset_cve_plugins": plugins}

    def test_cve_hit_lifts_cleared_asset(self) -> None:
        rows = render.enrich([self._cve_row("11.0.25", "OpenJDK Java", "/usr/lib/jvm/java-11-openjdk/",
                                            ["382489"])], {})
        self.assertEqual(rows[0]["verdict"], "Unknown \u2013 verify")
        self.assertEqual(rows[0]["reason"], "Tenable plugin 382489 flags this asset")
        self.assertEqual(rows[0]["r"], "no")

    def test_every_row_of_the_asset_lifted(self) -> None:
        rows = render.enrich([
            self._cve_row("11.0.25", "OpenJDK Java", "/usr/lib/jvm/java-11-openjdk/", ["382045"]),
            self._cve_row("1.8.0_402", "OpenJDK Java", "/usr/lib/jvm/java-8-openjdk/", ["382045"]),
            self._cve_row("11.0.25", "OpenJDK Java", "/usr/lib/jvm/java-11-openjdk/", [], asset_id="c-2"),
        ], {})
        by_asset = {}
        for r in rows:
            by_asset.setdefault(r["asset_id"], set()).add(r["verdict"])
        self.assertEqual(by_asset["c-1"], {"Unknown \u2013 verify"})
        self.assertEqual(by_asset["c-2"], {"Not impacted"})

    def test_oracle_cspu_hit_needs_oracle_17_or_later(self) -> None:
        cleared_11 = self._cve_row("11.0.25", "Oracle Java", "/opt/oracle/jdk-11/", ["382091"])
        self.assertEqual(render.enrich([cleared_11], {})[0]["verdict"], "Not impacted")
        fixed_17 = self._cve_row("17.0.21.1+4", "Oracle Java", "/opt/oracle/jdk-17/", ["382091"])
        (row,) = render.enrich([fixed_17], {})
        self.assertEqual(row["verdict"], "Unknown \u2013 verify")
        self.assertEqual(row["reason"], "Tenable plugin 382091 flags this asset")
        openjdk_17 = self._cve_row("17.0.22+7", "OpenJDK Java", "/usr/lib/jvm/java-17-openjdk/", ["382091"])
        self.assertEqual(render.enrich([openjdk_17], {})[0]["verdict"], "Not impacted")

    def test_cve_hit_falls_back_to_row_plugins(self) -> None:
        row = self._cve_row("11.0.25", "OpenJDK Java", "/usr/lib/jvm/java-11-openjdk/", [])
        del row["asset_cve_plugins"]
        row["cve_plugins"] = ["382489"]
        self.assertEqual(render.enrich([row], {})[0]["verdict"], "Unknown \u2013 verify")

    def test_held_rows_say_why_in_csv(self) -> None:
        base = {"asset_id": "h-1", "asset": "held01", "ip": "192.0.2.90", "java_version_raw": "",
                "java_vendor": "", "java_path": "", "java_binary": "", "cve_plugins": []}
        rows = [dict(base, detection_plugin="148373", no_output=True, truncated=False, plugin_output=""),
                dict(base, asset_id="h-2", detection_plugin="147817", no_output=False, truncated=True),
                dict(base, asset_id="h-3", java_path="/usr/lib/jvm/java-21-openjdk/", version_conflict="21.0.5 vs 21.0.6",
                     no_output=False, truncated=False)]
        self.run_render(self.stage(rows))
        out = {r["asset_id"]: r for r in self.csv_rows()}
        for col in ("truncated", "no_output", "version_conflict"):
            self.assertIn(col, out["h-1"])
        self.assertEqual(out["h-1"]["no_output"], "yes")
        self.assertEqual(out["h-1"]["reason"], "plugin 148373 output not retrieved")
        self.assertEqual(out["h-2"]["truncated"], "yes")
        self.assertEqual(out["h-2"]["reason"], "installs cut off in plugin output")
        self.assertEqual(out["h-3"]["version_conflict"], "21.0.5 vs 21.0.6")
        self.assertEqual(out["h-3"]["reason"], "plugins disagree: 21.0.5 vs 21.0.6")
        self.assertEqual({r["verdict"] for r in out.values()}, {"Unknown \u2013 verify"})

    def test_panel_says_what_tenable_reports(self) -> None:
        self.run_render(self.stage())
        self.assertNotIn("Tenable reports the first two", self.html())
        self.assertIn("Tenable reports the Java build when its plugin output can be read, "
                      "and the architecture only for some hosts.", self.html())

    def test_csv_formula_cells_quoted(self) -> None:
        row = json.loads((FIXTURES / "findings.json").read_text(encoding="utf-8"))[0]
        rows = []
        for i, value in enumerate(("=HYPERLINK(\"x\")", "+1", "-1", "@SUM(A1)", "\tx", "\rx", "plain", "a=b")):
            rows.append(dict(row, asset_id=f"f-{i}", asset=value))
        self.run_render(self.stage(rows))
        got = {r["asset_id"]: r["asset"] for r in self.csv_rows()}
        self.assertEqual(got["f-0"], "'=HYPERLINK(\"x\")")
        self.assertEqual(got["f-1"], "'+1")
        self.assertEqual(got["f-2"], "'-1")
        self.assertEqual(got["f-3"], "'@SUM(A1)")
        self.assertEqual(got["f-4"], "'\tx")
        self.assertEqual(got["f-5"], "'\rx")
        self.assertEqual(got["f-6"], "plain")
        self.assertEqual(got["f-7"], "a=b")

    def test_blank_name_shows_asset_id(self) -> None:
        row = json.loads((FIXTURES / "findings.json").read_text(encoding="utf-8"))[0]
        row.update(asset="", fqdn="", asset_id="id-only-77")
        self.run_render(self.stage([row]))
        self.assertIn("<td>id-only-77</td>", self.html())

    def test_rollup_uses_shared_asset_key(self) -> None:
        from java4shell.inventory import asset_key
        base = {"asset_id": "", "asset": "Dup01", "ip": "192.0.2.70", "fqdn": "", "java_version_raw": "21.0.5",
                "java_path": "/usr/lib/jvm/java-21-openjdk-amd64"}
        rows = render.enrich([dict(base), dict(base, asset="dup01")], {})
        self.assertEqual(asset_key(rows[0]), asset_key(rows[1]))
        self.assertEqual(sum(render.asset_rollup(rows).values()), 1)

    def test_iris_embedded_once_and_hidden_in_print(self) -> None:
        self.run_render(self.stage())
        iris = render.b64(render.ASSETS / "tenable-iris.png")
        self.assertEqual(self.html().count(iris), 1)
        printed = self.html().split("@media print", 1)[1].split("</style>", 1)[0]
        self.assertRegex(printed, r"\.panel \.iris \{ display: none; \}")

    def test_print_text_has_no_faded_colours(self) -> None:
        self.run_render(self.stage())
        printed = self.html().split("@media print", 1)[1].split("</style>", 1)[0]
        for selector in (".meta dt", ".foot-bar", ".findings h2 span", ".tile span", ".tile .pairs",
                         "td.cond.no", ".eyebrow, .panel .eyebrow"):
            rule = re.search(re.escape(selector) + r"[^{]*\{([^}]*)\}", printed).group(1)
            self.assertNotIn("opacity", rule, selector)
            self.assertIn("color: #5A6062", rule, selector)

    def test_footer_does_not_cite_process_list(self) -> None:
        self.run_render(self.stage())
        about = self.html().split('class="foot-about"', 1)[1].split("</div>", 1)[0]
        self.assertNotIn("process list", about)

    def test_values_are_html_escaped(self) -> None:
        row = json.loads((FIXTURES / "findings.json").read_text(encoding="utf-8"))[0]
        row["asset"] = "<b>evil</b>"
        self.run_render(self.stage([row]))
        self.assertNotIn("<b>evil</b>", self.html())
        self.assertIn("&lt;b&gt;evil&lt;/b&gt;", self.html())


if __name__ == "__main__":
    unittest.main()
