---
name: java4shell-tenable
description: Java4Shell (CVE-2026-114938) exposure report from Tenable data via the Tenable Hexa AI MCP. Use when someone asks which assets are exposed to Java4Shell, wants a Java4Shell report, or asks about Java runtimes affected by the OpenJDK Base64 flaw in Tenable One Vulnerability Management.
---

# Java4Shell Tenable Skill

Builds one exposure report for Java4Shell. The data comes from the **Tenable Hexa AI MCP** and nothing else: every asset, install and finding in the report traces back to a Hexa tool call made during this run. The only other inputs are Tenable's public pages (the FAQ, the CVE plugin list and plugin descriptions). Only Tenable products and plugins are used, end to end.

Source of truth for the CVE, Oracle fixed builds and mitigations: [Tenable Research Java4Shell FAQ](https://www.tenable.com/blog/java4shell-cve-2026-114938-frequently-asked-questions-about-openjdk-rce-vulnerability).

**Read-only.** Never write to Tenable: no tags, no exposure initiatives, no scans, no exports. Never connect to a host.

`render.py` decides every verdict from four conditions: affected runtime (R), x86-64 (A), a CPU with AVX-512 VBMI (C) and the Base64 intrinsic left on (J). Your job is complete, faithful input files; the step 6 statement explains the verdicts to the user.

## Plugins

| Plugin | Name | Role |
|---|---|---|
| 147817 | Java Detection and Identification (Linux / Unix) | detection |
| 148499 | Java Detection and Identification (Windows) | detection |
| 148373, 148707 | OpenJDK Java Detection (Linux / Unix, Windows) | detection |
| 64815, 33545 | Oracle Java Runtime Environment (JRE) Detection (Unix, Windows) | detection |
| 169699, 171539 | Temurin Java Detection (Linux / Unix, Windows) | detection |
| 148374, 148706 | Azul Zulu Java Detection (Linux / Unix, Windows) | detection |
| 148376, 148708 | Amazon Corretto Java Detection (Linux / Unix, Windows) | detection |
| 148375, 148705 | AdoptOpenJDK Java Detection (Linux / Unix, Windows) | detection |
| 148372, 148709 | IBM Java Detection (Linux / Unix, Windows) | detection |
| 45432 | Processor Information (via DMI) | context: CPU model |
| 48942 | Microsoft Windows SMB Registry: OS Version and Processor Architecture | context: architecture |
| 20094 | VMware Virtual Machine Detection | context: virtualization |

Detection plugins carry each install's path, version and vendor; `findings.py` parses them. CVE plugins come from step 2 and are evidence only.

## Steps

1. **Preflight.** Look for the Hexa tools in your tool list, e.g. `mcp__tenable__workbenches_get_vulnerability_outputs` (the prefix follows whatever name the server was added under). If they are absent, stop and give the user this setup, then end the run:
   ```
   claude mcp add --transport http tenable https://cloud.tenable.com/mcp \
     --header "X-ApiKeys: accessKey=<ACCESS_KEY>;secretKey=<SECRET_KEY>"
   ```
   Requirements: Tenable One Foundation or Advanced, **Enable Hexa AI MCP** turned on in Hexa AI settings, API keys from Settings > My Account > API Keys, and Standard User or higher. Restart Claude Code after adding the server.
   *Done when the Hexa tools are callable, or the user has the setup block.*

2. **Coverage.** Create the run folder `~/Dev/java4shell-reports/<YYYY-MM-DD-HHMM>/` (`<run>` below). Then:
   - **FAQ:** WebFetch the FAQ URL above. Take the CVE, the Oracle Java SE fixed builds, the mitigations, Calif's application list, and the exploitation status (whether exploitation in the wild is known, whether the CVE is in CISA KEV, and any public exploit or PoC the FAQ names), with the date the FAQ gives for it. Compare it with `FIXED` and `EPP_FIXED_UPDATE` in `java4shell/versions.py` (the 8.0 Performance Pack fix is update `EPP_FIXED_UPDATE`). If the FAQ's table differs, write `<run>/fixed.json` and tell the user what changed:
     `{"oracle": {"17": "17.0.21.2"}, "oracle-epp": {"8": "8.0.515.0"}}`
     A newer fix overrides the version (`a.b.c.d`; Performance Pack update N is `8.0.N.0` under `oracle-epp`). A build the FAQ marks as withdrawn or disputed becomes `"unknown"`. Only Oracle Java SE comes from the FAQ; other vendors stay on the in-code table. If the fetch fails, carry on and say so in the summary.
   - **Public plugin list:** WebFetch `https://www.tenable.com/cve/CVE-2026-114938/plugins`. Note the released plugins and the "Coming Soon" (pipeline) entries.
   - **Plugin search:** call `plugins_search_plugins(cve="CVE-2026-114938")`, page through every page, and merge by plugin ID. Each result's `Supported Sensors` field gives the source (use `Sensor` only when `Supported Sensors` is missing): `nessus`, `nessus_agent` and `continuous_assessment` are `VM`; `tenable_was` is `WAS`; a Cloud Security or container sensor is `Cloud`. Any other sensor is `VM`, and the summary lists it by name. A plugin listed under several sensors is one plugin; record every sensor it lists.
   - **Plugin descriptions:** for each CVE plugin, WebFetch its public page `https://www.tenable.com/plugins/nessus/<id>` and read the description. If it mentions `AVX-512`, `AVX512` or `VBMI`, note "CPU-aware plugin <id>; this version of the skill does not read its output yet" for the summary.
   - **New vendor plugins:** watch for and name any CVE plugin that is new for OpenJDK (the `openjdk_*` plugin family), Azul Zulu, Eclipse Temurin or Microsoft Build of OpenJDK.
   Print the CVE plugins (ID, source, sensors, name), the pipeline entries, any released plugin on the public page that the search did not return, any CPU-aware plugin, and any unmapped sensor.
   *Done when the search has been paged to the end, both pages and every CVE plugin's description have been fetched (or their failure noted), and `fixed.json` exists if and only if the FAQ differs.*

3. **Pull data.** Read each tool's schema before calling it. Back off and retry on HTTP 429.
   - **Enumerate assets per detection plugin.** For each detection plugin, call `tenable_one_search_findings` with `filters` = `[{"property":"finding_detection_id","operator":"contains","value":["<plugin id>"]},{"property":"state","operator":"!=","value":["FIXED"]}]`. Use `contains`: `=` matches nothing on this property. `contains` also matches longer IDs, so keep only findings whose name contains "Java". A `FIXED` finding never has workbench output, so it is left out here. Page with `offset` while `total` exceeds what you have. Findings carry the asset ID but no name or IP: record each asset ID, and the finding's last-seen time when one is returned.
   - **Plugin output.** For each detection plugin, call `workbenches_get_vulnerability_outputs(plugin_id)`, then repeat it with `age` set to 7, 14, 30, 90, 180 and 365. Each call returns at most 10 hosts (the **10-host cap**) and has no next page. Merge by Asset ID. Skip the age repeats when the no-age call returned fewer than 10 hosts (an age filter can only narrow that set), or when the plugin enumerated no assets. Take identity from each output's host line (see **Host line** below). Pass the plugin output through unchanged, including a trailing `... (truncated)`; `findings.py` handles it.
   - **Asset info for every enumerated asset.** Call `workbenches_get_asset_info(asset_id)` once per enumerated asset. Write an `outputs.jsonl` line with `"plugin_id": "asset_info"` whose `output` holds just the lines `findings.py` reads: `Hostnames`, `IPv4 Addresses`, `FQDN`, `Operating System` and `Last Seen`. The `Operating System` line (for example `...el9.x86_64` or `...-arm64`) settles A for most Linux hosts. The same record supplies identity for assets with no retrieved detection output: `asset` from `Hostnames` (the first one), `ip` from `IPv4 Addresses` by the IP choice rule, `fqdn` from `FQDN` (blank when it reads `N/A`), and `last_seen` from `Last Seen`.
   - **Write `<run>/outputs.jsonl` as you go:** append each tool result's lines the moment it arrives, so nothing waits to be copied in bulk. One JSON object per line: `{"asset_id", "asset", "ip", "fqdn", "plugin_id", "output", "last_seen"}`. `last_seen` is the host line's `Last Seen`. Every enumerated asset with no retrieved output for a plugin still gets a line for that plugin with `"output": ""`, so it shows as Unknown – verify instead of disappearing. Fill those lines' `asset`, `ip`, `fqdn` and `last_seen` from the asset info above. Enumeration findings carry no last-seen time, so `last_seen` is `""` only when the lookup also has none.
   - **Context plugins** 45432, 48942 and 20094: call `workbenches_get_vulnerability_outputs` once each with no age window, then with `age` set to 7 and 30. Each call covers every asset with the plugin, not just Java assets, and returns at most 10 hosts, so only a few hits land on Java assets. Append lines to `outputs.jsonl` only for assets already enumerated. Write no empty-output lines for context plugins.
   - **CVE findings.** Call `tenable_one_search_findings` with `filters` = `[{"property":"finding_cves","operator":"=","value":["CVE-2026-114938"]}]`, paged. Findings don't carry a plugin ID, so match each finding's name to the step 2 plugin list. Write `<run>/cve_findings.json` as a list of `{"asset_id", "plugin_id", "state"}`. Keep every state except `FIXED`; `findings.py` filters too.
   - **Package findings** (container and cloud assets, which the detection plugins can't see). For each term `openjdk`, `temurin`, `corretto`, `zulu`, `graalvm`, `jre` and `jdk`, make one `tenable_one_search_findings` call with `filters` = `[{"property":"finding_name","operator":"contains","value":["<term>"]},{"property":"sensor_type","operator":"=","value":["CONSEC","CLOUD_SCAN"]},{"property":"state","operator":"!=","value":["FIXED"]}]`, and page it fully with `offset`. If a term still returns more than 1,000 findings, stop paging it and report that term as incomplete in the summary. De-duplicate by finding ID across terms. Fill `asset`, `ip` and `fqdn` with the asset lookup above (`workbenches_get_asset_info`), and `asset_class` from `tenable_one_search_assets` with `filters` = `[{"property":"asset_id","operator":"=","value":["<id>", ...]}]` (up to 100 IDs per call; blank is fine). Write `<run>/package_findings.json` as a list of `{"asset_id", "asset", "ip", "fqdn", "name", "state", "asset_class"}`. `findings.py` keeps only assets with no detection row.
   *Done when every detection plugin has a recorded result count (assets enumerated and assets with output), every context plugin has a count of assets with output, every enumerated asset has an `asset_info` line, the CVE and package searches are paged to the end (or a package term is reported as incomplete), and the three files exist. Zero counts as a result; a plugin you never queried does not.*

   **Host line** (reference for step 3). Each workbench output starts with:
   `Host: Hostname: <name>, Asset ID: <uuid>, IPv4: <ip>[, <ip>...], [IPv6: ...,] First Seen: <iso>, Last Seen: <iso>`
   - Split it on the label names, not on commas: IP lists contain commas.
   - There is no FQDN label. Leave `fqdn` empty unless the hostname is itself an FQDN (its last label is alphabetic and not `localdomain`).
   - **IP choice** (host lines and asset info alike): the first IPv4 that is not loopback (127.0.0.0/8), link-local (169.254.0.0/16), `172.17.0.1` or `192.168.122.1`; if every IPv4 is excluded, the first IPv4.

4. **Build `findings.json`.** Run:
   ```
   python3 <this skill's directory>/findings.py --outputs <run>/outputs.jsonl --cve <run>/cve_findings.json --packages <run>/package_findings.json -o <run>/findings.json
   ```
   It prints `assets= pairs= truncated= stale_scans= no_output= package_only= package_unmatched=`, and a `WARN:` line when input records name no asset (no asset ID, name or IP; they are skipped). Keep the line for steps 5 and 6.
   *Done when `<run>/findings.json` exists and the counts line was printed.*

5. **Render.** Run `python3 <this skill's directory>/render.py <run>/findings.json <run>`. It reads `<run>/fixed.json` when present, and prints `pairs=`, one line per verdict (assets and pairs), the fixed-builds date, any `WARN:` lines and the file paths.
   *Done when `report.csv`, `report.html` and `report.pdf` exist (or a WARN says why the PDF was skipped) and render's `pairs=` equals findings.py's `pairs=`.*

6. **Summarize.** Give the user:
   - asset and pair counts per verdict (Impacted, Affected build – CPU unconfirmed, Unknown – verify, Mitigated (temporary), Not impacted), from the render output
   - the ten worst assets with verdict, reason and priority hint (from `report.csv`)
   - this statement: "Tenable's plugins don't report CPU feature flags or a running JVM's flags yet, so installs on affected builds show as 'Affected build – CPU unconfirmed' until they do. 'Unknown – verify' means Tenable data could not settle the build. A mitigation option seen on a process command line is evidence only. An unknown input never counts as Not impacted."
   - every Impacted, Affected build – CPU unconfirmed and Unknown – verify asset (name, IP, asset ID), so the user can tag them or build an exposure initiative in Tenable themselves. If there are more than 100, list the first 100 and point to the `verdict` column in `report.csv`.
   - coverage per detection plugin: assets with output / assets enumerated
   - `no_output`, `truncated` and `stale_scans` from findings.py; describe `stale_scans` as assets that "need a credentialed or agent rescan"
   - `package_only`: assets found only through package findings, `package_unmatched`: package findings on other assets whose names matched no Java package name (check them by hand), and any package term reported as incomplete
   - each CVE plugin with its result count, and the pipeline plugins from the public page, listed as "coming"
   - any CPU-aware plugin from step 2, as "CPU-aware plugin <id>; this version of the skill does not read its output yet", any new OpenJDK, Zulu, Temurin or Microsoft CVE plugin, and any sensor step 2 could not map
   - cloud workload coverage: if no CVE plugin lists a Cloud Security or cloud workload sensor, say "No Tenable plugin for CVE-2026-114938 lists the Cloud Security sensor yet, so cloud workloads have no Tenable CVE coverage; package findings may still show some." Otherwise name the plugins that do.
   - vendor gaps: group the rows in `findings.json` by `java_vendor`. A row whose `managed_by_os` is true counts as covered by 382489 (distribution packages). Rows with `detection_plugin` "package finding" form one group, "package finding". Rows with a blank `java_vendor` form one group, "vendor unknown". For each group no CVE plugin covers, judged from the plugin names (Oracle → 382091; Corretto → 382045 and the Amazon Linux ALAS checks), say "<vendor>: no Tenable CVE plugin yet; verdicts come from the version rules only."
   - exploitation status from the FAQ (in-the-wild, CISA KEV, public exploit or PoC) with its as-of date, and the time the FAQ was fetched
   - the fixed-builds as-of date, and whether `fixed.json` was written
   - mitigations: `-XX:-UseBASE64Intrinsics` (preferred) or `-XX:UseAVX=2` (x86-64 only; Java on ARM64 will not start with it). Verify with `jcmd <pid> VM.flags`, and remove the flag after patching. They reduce exposure but do not fix it.
   - the file paths, and a link to the FAQ
   - that the skill made no changes in Tenable
   *Done when every item above is in the reply.*
