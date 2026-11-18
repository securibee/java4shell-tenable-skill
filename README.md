# Java4Shell Tenable Skill

A Claude Code skill that reports exposure to Java4Shell from your own Tenable data. Java4Shell is CVE-2026-114938, a memory corruption flaw in the OpenJDK Base64 decoder. It pulls Java inventory and findings through the [Tenable Hexa AI MCP](https://docs.tenable.com/vulnerability-management/Content/getting-started/hexa-AI-MCP.htm), decides a verdict for each Java install, and writes the result as an HTML page, a PDF and a CSV.

The affected lines, Oracle fixed builds, CPU requirements and mitigations come from Tenable Research's [Java4Shell FAQ](https://www.tenable.com/blog/java4shell-cve-2026-114938-frequently-asked-questions-about-openjdk-rce-vulnerability).

## Why most results are "Affected build – CPU unconfirmed"

Per the FAQ, a Java install is exposed only when all of these hold:

- **R, affected runtime.** Java 17 (17.0.6 and newer), 21, 25 or 27 below the vendor's fixed build. Also the non-LTS lines 18–20, 22–24 and 26, which carry the flaw and get no fix; Oracle's Java 8 Enterprise Performance Pack; and Azul Prime below its fixed release, on every line including 8 and 11. The OpenJDK advisory does not list standard Java 8 or 11.
- **A, x86-64.** ARM64 is not affected.
- **C, AVX-512 VBMI.** On Linux the CPU must report the `avx512f`, `avx512bw`, `avx512vbmi` and `bmi2` flags. The skill also requires `avx512vl`, to stay on the cautious side.
- **J, intrinsic on.** The JVM uses its accelerated Base64 path, which is the default.

Tenable data usually settles R and A. It can rule C out when the CPU model is too old, but no Tenable plugin reports a CPU's instruction-set flags or the flags a running JVM uses yet. So installs on affected builds show as Affected build – CPU unconfirmed, and Impacted and Mitigated (temporary) stay empty until a plugin reports those flags. The skill uses only Tenable products and plugins, so one run does the whole job.

## What it does

1. Checks that the Tenable Hexa AI MCP tools are loaded. If they are missing, it prints the setup command and stops.
2. Re-reads the FAQ for the current Oracle fixed builds and mitigations, reads Tenable's [public plugin list for the CVE](https://www.tenable.com/cve/CVE-2026-114938/plugins), and asks Tenable's plugin database for every plugin covering the CVE, with the sensors each one supports. It reads each CVE plugin's public description and reports any that mention AVX-512 or VBMI, which this version does not read yet. If the FAQ's Oracle table has changed, it writes an override file so the report uses the new builds.
3. Finds every asset with an open Java detection finding, reads each plugin's output for install path, version and vendor, and adds CPU, architecture and virtualization context. When an output names no vendor, the vendor-specific detection plugin implies it. It reads each asset's record (`workbenches_get_asset_info`) for its name, IP and operating system; the OS string usually names the architecture (for example `el9.x86_64`), which settles the x86-64 check for most Linux hosts. It also collects CVE findings, and Java package findings from container and cloud scans, which the detection plugins can't see. At the time of writing the plugins are:

   | Plugin | Name | Role |
   |---|---|---|
   | 147817, 148499 | Java Detection and Identification (Linux / Unix, Windows) | detection |
   | 148373, 148707 | OpenJDK Java Detection (Linux / Unix, Windows) | detection |
   | 64815, 33545 | Oracle Java Runtime Environment (JRE) Detection (Unix, Windows) | detection |
   | 169699, 171539 | Temurin Java Detection (Linux / Unix, Windows) | detection |
   | 148374, 148706 | Azul Zulu Java Detection (Linux / Unix, Windows) | detection |
   | 148376, 148708 | Amazon Corretto Java Detection (Linux / Unix, Windows) | detection |
   | 148375, 148705 | AdoptOpenJDK Java Detection (Linux / Unix, Windows) | detection |
   | 148372, 148709 | IBM Java Detection (Linux / Unix, Windows) | detection |
   | 45432, 48942, 20094 | Processor Information, Windows OS version and architecture, VMware guest detection | context |
   | 382091 | Oracle Java SE Oracle CSPU Nov 2026 (Java4Shell) | CVE finding |
   | 382045 | Amazon Corretto Java 17.x < 17.0.21.1.2 Multiple Vulnerabilities | CVE finding |
   | 382309, 382312, 382319, 382332, 382347 | Amazon Linux 2 and 2023 Corretto package updates | CVE finding |
   | 382489 | Linux Distros Unpatched Vulnerability: CVE-2026-114938 | CVE finding |

   CVE findings are supporting evidence, never a verdict on their own. 382091 checks the version only and also covers other Oracle CSPU flaws, including on Java 8 and 11, so a hit there does not mean Java4Shell exposure. A CVE finding can still stop a clear: when the version rules would make an asset Not impacted but one of these plugins flags it, every install on the asset becomes Unknown – verify. For 382091 that happens only when the asset has an Oracle install on Java 17 or later.

4. Runs `findings.py`, which writes one row per asset and Java install to `findings.json`.
5. Runs `render.py`, which assesses each install and writes the report.
6. Summarizes the run in the chat: counts by verdict, the ten worst assets, every Impacted, Affected build – CPU unconfirmed and Unknown – verify asset (name, IP, asset ID), coverage per detection plugin, stale scans, plugins still in Tenable's pipeline, cloud workload coverage, Java vendors no CVE plugin covers yet, and the mitigations.

The skill only reads data. It never launches scans, creates tags, builds exposure initiatives or changes anything in Tenable. The summary lists the assets so you can tag them yourself. It never connects to your hosts and needs nothing from them.

## Prerequisites

- **Claude Code.**
- **Tenable One Foundation or Advanced.** Hexa AI MCP must be turned on under Settings > Hexa AI, and your role must be Standard User or higher. The Hexa MCP is not available in FedRAMP Moderate environments.
- **Tenable API keys**, generated under Settings > My Account > API Keys.
- **Python 3.9 or newer.** `findings.py` and `render.py` use only the standard library.
- **Google Chrome or Chromium** for the PDF. Without either, the HTML and CSV are still written and the PDF is skipped with a warning.

## Install

1. Add the Tenable Hexa AI MCP server to Claude Code, using your own keys:

   ```bash
   claude mcp add --transport http tenable https://cloud.tenable.com/mcp \
     --header "X-ApiKeys: accessKey=<ACCESS_KEY>;secretKey=<SECRET_KEY>"
   ```

2. Clone this repository into your Claude Code skills directory:

   ```bash
   git clone https://github.com/securibee/java4shell-tenable-skill ~/.claude/skills/java4shell-tenable
   ```

3. Restart Claude Code so it loads both the MCP server and the skill.

## Usage

Run `/java4shell-tenable`, or ask Claude something like "run the Java4Shell report" or "which of our assets are exposed to Java4Shell?".

A run takes several minutes. Most of that is Hexa calls, and the skill backs off if Tenable rate-limits it.

## Output

Each run writes to `~/Dev/java4shell-reports/<YYYY-MM-DD-HHMM>/`:

| File | Contents |
|---|---|
| `report.html` | A self-contained page with verdict tiles, what Tenable data can't see, mitigations and a sortable findings table. It has a PDF button and needs no network access to view. |
| `report.pdf` | A US Letter landscape version. |
| `report.csv` | Every install with all fields, each condition (R, A, C, J) with its evidence, the verdict, confidence, priority hint and fixed build. |
| `findings.json` | The rows the report was built from. |
| `outputs.jsonl`, `cve_findings.json`, `package_findings.json` | The Tenable data `findings.py` read. |
| `fixed.json` | Present only when the FAQ's Oracle fixed builds differ from the built-in table. |

`render.py` gives each install one of these verdicts. An asset takes the worst verdict of its installs.

| Verdict | Meaning |
|---|---|
| Impacted | Affected runtime, x86-64, and the CPU flags confirmed. The intrinsic is on or unknown (on is the default). No Tenable plugin reports CPU flags yet, so this tile shows only when something lands here. |
| Affected build – CPU unconfirmed | Affected runtime, x86-64 or architecture unknown, and the CPU not ruled out. Most affected installs land here today. |
| Unknown – verify | Tenable data can't settle the runtime and nothing rules exposure out. Examples: a version string that is ambiguous at the fixed build, plugins that report different versions for one install, a detection plugin whose output wasn't retrieved, an output cut off before all its installs, or a CVE plugin that flags an asset the version rules would clear. |
| Mitigated (temporary) | Could otherwise be exposed, but a live JVM reports the intrinsic off. The flag is lost on restart unless it is set permanently; patch anyway. No Tenable plugin reports live JVM flags yet, so this tile shows only when something lands here. A mitigation option seen on a process command line is shown as evidence only. |
| Not impacted | The runtime is not affected, the host is not x86-64, or the CPU lacks the required flags. |

Each install also carries an exposure confidence: high when both the CPU and live JVM flags are confirmed, medium when the runtime is settled and the CPU is either checked or ruled out by its model, and low otherwise. It also carries a priority hint, which flags applications Calif reports as exploitable (Keycloak, Jira, Confluence, Artifactory, Jenkins and PingFederate before login; Kafka, Solr, Elasticsearch, Gerrit and Spinnaker after login) and runtimes bundled with a product rather than managed by the OS. Priority only ranks rows; it never changes a verdict.

You can re-render from saved findings without calling Tenable again:

```bash
python3 ~/.claude/skills/java4shell-tenable/render.py <run folder>/findings.json <run folder>
```

## Data flows

- **Tenable Hexa AI MCP** (`https://cloud.tenable.com/mcp`). The skill sends read-only queries with your API keys. It uses `plugins_search_plugins`, `tenable_one_search_findings`, `tenable_one_search_assets`, `workbenches_get_asset_info` and `workbenches_get_vulnerability_outputs`.
- **Your LLM provider.** As with any MCP server, the asset data Hexa returns passes through Claude Code to the model you use.
- **tenable.com.** The skill fetches the Tenable Research FAQ, the public CVE plugin page and each CVE plugin's public page once per run.
- **No network access from `findings.py` or `render.py`.** They write local files, and `render.py` runs a local headless Chrome for the PDF. The font, logo and images are embedded in the HTML. The report's external references are links, which only open if you click them.

## Known limitations

- **Tenable plugins don't report CPU or JVM flags yet.** Installs on affected builds stay Affected build – CPU unconfirmed until they do.
- **Process-list flags are not read today.** `findings.py` can read the `-XX` options of Java command lines from the Unix / Linux Running Processes Information plugin (110483), as evidence only, but the skill doesn't fetch that plugin: Hexa cuts its output short before the Java command lines.
- **Version strings can be ambiguous at the fix boundary.** Some reported versions can be read as either a patch level or a build number. When the skill can't tell whether an install is below or at the fixed build, it reports Unknown – verify rather than guess.
- **Fixed builds are as of 2026-11-18.** Vendors ship fixes on their own schedules. The skill re-reads the FAQ for Oracle Java SE on each run; other vendors use the built-in table, whose date is printed in the report. Check your vendor's advisory.
- **Bundled runtimes may be missed.** Java runtimes that ship inside an application are often found only when the scan has thorough tests enabled.
- **Plugin output is limited to ten hosts per call.** Hexa returns up to 10 outputs per call, with no next page, and cuts long outputs short. The skill repeats each detection call across age windows from 7 to 365 days and merges the results, and calls the context plugins with no window and 7- and 30-day windows. When a detection plugin's output for an asset wasn't retrieved, that plugin keeps a row "plugin <id> output not retrieved", unless the same plugin reported installs on the asset or the asset has a complete output from Java Detection and Identification (147817 or 148499). When an output is cut short, the installs before the cut are kept, the value right before the cut is dropped, and the asset gets a row "installs cut off in plugin output" unless the output's "Nessus detected N installs" header shows every install was read. Either row is Unknown – verify, so the asset can't come out Not impacted. The installs behind the cut stay unseen until a rescan or a fuller output.
- **Container and cloud assets are found through package findings only.** The detection plugins don't run on them, so the skill searches container and cloud scan findings for Java package names. A Java package with no finding against it stays invisible, and a package finding carries no version, so its row is judged by the Java line alone.
- **Cloud workload coverage depends on Tenable shipping a Cloud Security plugin for the CVE.** The skill reports whether one exists at run time.

## Repository layout

```
SKILL.md              skill instructions Claude Code loads
findings.py           Tenable outputs and findings -> findings.json
render.py             findings.json [+ fixed.json] -> report.csv, report.html, report.pdf
java4shell/           version parsing, conditions and verdicts, plugin output parsing
assets/report.html    report template (design tokens from the CyberAgents Exchange website)
assets/*              Work Sans font with its license (OFL.txt), Tenable logo and iris
tests/                unittest suite with synthetic fixtures
```

Run the tests with `python3 -m unittest discover -s tests -t .`.

## License

MIT, copyright Tenable, Inc. See [LICENSE](LICENSE).

The bundled Work Sans font is licensed separately under the SIL Open Font License 1.1 ([assets/OFL.txt](assets/OFL.txt)). The Tenable name, logo and iris mark are trademarks of Tenable, Inc. They are included only to brand the generated reports and are not licensed under MIT.
