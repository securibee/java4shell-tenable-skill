from __future__ import annotations

import itertools
import unittest

from java4shell.conditions import (
    REQUIRED_FLAGS,
    assess_arch,
    assess_cpu,
    assess_flags,
    confidence,
    cpu_rules_out,
    decide,
    priority,
)
from java4shell.model import (
    AFFECTED_CPU_UNCONFIRMED,
    IMPACTED,
    MITIGATED,
    NOT_IMPACTED,
    ORDER,
    UNKNOWN_VERIFY,
    Condition,
    HostEvidence,
)

ALL_FLAGS = frozenset({"avx512f", "avx512bw", "avx512_vbmi", "bmi2", "avx512vl"})


def host(**kw) -> HostEvidence:
    base = dict(
        cpu_flags=None, cpu_source="", runtime_version=None, os_arch=None,
        default_flags=None, live_flags=None, live_skip_reason="",
        cmdline_flags=(), collected_at="2026-11-18T00:00:00Z", stale=False,
    )
    base.update(kw)
    return HostEvidence(**base)


def cond(value: str, evidence: str = "e") -> Condition:
    return Condition(value, evidence)


class ArchTests(unittest.TestCase):
    def test_arch_sources(self):
        self.assertEqual(assess_arch({}, host(os_arch="aarch64")).value, "no")
        self.assertEqual(assess_arch({}, host(os_arch="amd64")).value, "yes")
        self.assertEqual(assess_arch({}, host(os_arch="i386")).value, "no")
        self.assertEqual(assess_arch({"arch": "x64"}).value, "yes")
        self.assertEqual(assess_arch({"arch": "x86"}).value, "no")
        self.assertEqual(assess_arch({"arch": "arm64"}).value, "no")
        self.assertEqual(assess_arch({"arch": "aarch64"}).value, "no")
        self.assertEqual(
            assess_arch({"java_path": "/usr/lib/jvm/java-21-openjdk-i386/"}).value, "no")
        self.assertEqual(
            assess_arch({"java_path": "/usr/lib/jvm/java-21-openjdk-amd64/"}).value, "yes")
        self.assertEqual(assess_arch({}).value, "unknown")

    def test_host_beats_row(self):
        self.assertEqual(assess_arch({"arch": "x64"}, host(os_arch="arm64")).value, "no")

    def test_conflicting_path_tokens_unknown(self):
        self.assertEqual(assess_arch({"java_path": "/opt/x64/arm64/jre"}).value, "unknown")

    def test_path_arch_tokens_on_segment_boundaries(self):
        for path, value in (("/opt/tools/x64dbg/jre/", "unknown"), ("/opt/fooarm64bar/jre/", "unknown"),
                            ("/opt/vendor/xi686y/jre/", "unknown"),
                            ("/usr/lib/jvm/java-21-openjdk-amd64/", "yes"),
                            ("/usr/lib/jvm/java-17-openjdk-17.0.9.0.9-2.el9.x86_64/", "yes"),
                            ("C:\\Program Files\\jdk-17_windows-x64_bin\\", "yes"),
                            ("/opt/jdk-21-aarch64/", "no"), ("/usr/lib/jvm/java-11-openjdk-i386/", "no")):
            self.assertEqual(assess_arch({"java_path": path}).value, value, path)

    def test_apple_silicon(self):
        self.assertEqual(assess_arch({"os": "macOS 14.2 (arm64)"}).value, "no")
        self.assertEqual(assess_arch({"os": "macOS 14.2"}).value, "unknown")


class CpuTests(unittest.TestCase):
    def test_cpu_host_flags(self):
        c = assess_cpu({}, host(cpu_flags=ALL_FLAGS))
        self.assertEqual(c.value, "yes")
        c = assess_cpu({}, host(cpu_flags=ALL_FLAGS - {"bmi2"}))
        self.assertEqual(c.value, "no")
        self.assertIn("bmi2", c.evidence)

    def test_required_flags(self):
        self.assertEqual(
            REQUIRED_FLAGS, ("avx512f", "avx512bw", "avx512vbmi", "bmi2", "avx512vl"))

    def test_cpu_rule_out(self):
        for m in (
            "Intel(R) Xeon(R) Gold 6248 CPU @ 2.50GHz",
            "Intel(R) Xeon(R) CPU E5-2620 v4 @ 2.10GHz",
            "AMD EPYC 7763 64-Core Processor",
            "Intel Xeon Processor (Cascadelake)",
        ):
            self.assertIsNotNone(cpu_rules_out(m), m)
        for m in (
            "Intel(R) Xeon(R) Platinum 8358 CPU @ 2.60GHz",
            "AMD EPYC 9654 96-Core Processor",
            "Intel Xeon Processor (Icelake)",
            "Intel(R) Xeon(R) 6980P",
            "Some Future CPU",
        ):
            self.assertIsNone(cpu_rules_out(m), m)

    def test_cpu_rule_out_reason(self):
        self.assertEqual(
            cpu_rules_out("Intel(R) Xeon(R) Gold 6248 CPU @ 2.50GHz"),
            "Intel Xeon Scalable 2nd gen (Cascade Lake): no AVX-512 VBMI")

    def test_more_rule_outs(self):
        for m in ("Intel(R) Xeon(R) CPU X5650 @ 2.67GHz", "Intel(R) Core(TM) i7-8700 CPU",
                  "AMD Ryzen 9 5950X 16-Core Processor", "AMD Opteron(tm) Processor 6174",
                  "Intel(R) Atom(TM) CPU C3758", "Intel(R) Celeron(R) G4900",
                  "Intel(R) Xeon(R) Gold 6248R CPU", "Intel(R) Core(TM) i7-8650U CPU @ 1.90GHz",
                  "Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz", "Haswell-noTSX", "EPYC-Rome",
                  "AMD Ryzen 5 PRO 4650G", "AMD Ryzen Threadripper PRO 3995WX 64-Cores",
                  "AMD Ryzen Threadripper 3970X 32-Core Processor"):
            self.assertIsNotNone(cpu_rules_out(m), m)
        for m in ("Intel(R) Core(TM) i7-1165G7", "Intel(R) Core(TM) i3-8121U CPU @ 2.20GHz",
                  "Intel(R) Core(TM) i5-8114Y CPU", "Intel(R) Core(TM) i9-12900K",
                  "AMD Ryzen 9 7950X 16-Core Processor", "Intel(R) Xeon(R) Gold 6338 CPU",
                  "AMD EPYC 9124 16-Core Processor", "EPYC-Genoa", "Icelake-Server",
                  "Intel(R) Xeon(R) Platinum 8480+", "Sapphirerapids"):
            self.assertIsNone(cpu_rules_out(m), m)

    def test_bare_epyc_and_ryzen_numbers_not_ruled_out(self):
        for m in ("EPYC", "AMD EPYC", "EPYC-v4", "AMD EPYC Processor", "AMD Ryzen 9 7950X @ 4501 MHz",
                  "AMD Ryzen AI 9 HX 370 @ 2000 MHz", "AMD Ryzen 7 7840U w/ Radeon 780M Graphics 4501"):
            self.assertIsNone(cpu_rules_out(m), m)

    def test_cpu_model_never_yes(self):
        c = assess_cpu({"cpu_model": "Intel(R) Xeon(R) Platinum 8358 CPU @ 2.60GHz"})
        self.assertEqual(c.value, "unknown")
        self.assertEqual(c.evidence, "CPU flags not in Tenable data")

    def test_cpu_ruled_out_by_model(self):
        c = assess_cpu({"cpu_model": "Intel(R) Xeon(R) Gold 6248 CPU; Intel(R) Xeon(R) Gold 6248 CPU"})
        self.assertEqual(c.value, "no")

    def test_cpu_mixed_models_not_ruled_out(self):
        c = assess_cpu({"cpu_model": "Intel(R) Xeon(R) Gold 6248 CPU; Intel(R) Xeon(R) Platinum 8358 CPU"})
        self.assertEqual(c.value, "unknown")

    def test_empty_flags_do_not_clear(self):
        self.assertEqual(assess_cpu({}, host(cpu_flags=frozenset())).value, "unknown")

    def test_no_data(self):
        self.assertEqual(assess_cpu({}).value, "unknown")
        self.assertEqual(assess_cpu({"cpu_model": " ; "}).value, "unknown")


class FlagTests(unittest.TestCase):
    def test_flags(self):
        self.assertEqual(
            assess_flags({}, host(live_flags={"UseBASE64Intrinsics": False, "UseAVX": 3})).value, "no")
        self.assertEqual(
            assess_flags({}, host(live_flags={"UseBASE64Intrinsics": True, "UseAVX": 3})).value, "yes")
        self.assertEqual(
            assess_flags({}, host(live_flags={"UseBASE64Intrinsics": True, "UseAVX": 2})).value, "no")
        c = assess_flags({}, host(cmdline_flags=("-XX:-UseBASE64Intrinsics",)))
        self.assertEqual(c.value, "unknown")
        self.assertIn("confirm with jcmd", c.evidence)
        c = assess_flags({}, host(cmdline_flags=("-XX:UseAVX=2",)))
        self.assertIn("confirm with jcmd", c.evidence)

    def test_string_values(self):
        c = assess_flags({}, host(live_flags={"UseBASE64Intrinsics": "true", "UseAVX": "3"}))
        self.assertEqual(c.value, "yes")

    def test_partial_live_flags_unknown(self):
        self.assertEqual(
            assess_flags({}, host(live_flags={"UseBASE64Intrinsics": True})).value, "unknown")

    def test_defaults_only(self):
        c = assess_flags({}, host(default_flags={"UseAVX": 3}))
        self.assertEqual(c.value, "unknown")
        self.assertEqual(c.evidence, "defaults only: UseAVX=3")

    def test_no_host(self):
        self.assertEqual(assess_flags({}).value, "unknown")
        self.assertEqual(assess_flags({}, host()).value, "unknown")


class DecideTests(unittest.TestCase):
    def test_decide_table(self):
        y, u, n = cond("yes"), cond("unknown"), cond("no")
        # Impacted: R, A and C yes; J yes or unknown.
        self.assertEqual(decide(y, y, y, u), (IMPACTED, "R, A and C all yes"))
        self.assertEqual(decide(y, y, y, y)[0], IMPACTED)
        # Affected build, CPU unconfirmed: R yes, A yes or unknown, C unknown.
        self.assertEqual(decide(y, y, u, u), (AFFECTED_CPU_UNCONFIRMED, "CPU flags not in Tenable data"))
        self.assertEqual(decide(y, u, u, y)[0], AFFECTED_CPU_UNCONFIRMED)
        # Unknown, verify: anything else not cleared.
        self.assertEqual(decide(u, y, u, u), (UNKNOWN_VERIFY, "unknown: R, C, J"))
        self.assertEqual(decide(u, y, y, y), (UNKNOWN_VERIFY, "unknown: R"))
        self.assertEqual(decide(y, u, y, u), (UNKNOWN_VERIFY, "unknown: A, J"))
        # Mitigated: J no, nothing else no.
        self.assertEqual(decide(y, y, u, n)[0], MITIGATED)
        self.assertEqual(decide(y, y, y, n)[0], MITIGATED)
        self.assertEqual(decide(u, u, u, n)[0], MITIGATED)
        # Not impacted: R, A or C no.
        v, reason = decide(u, cond("no", "32-bit"), u, u)
        self.assertEqual(v, NOT_IMPACTED)
        self.assertTrue(reason.startswith("A:"))

    def test_order(self):
        self.assertEqual(ORDER, [IMPACTED, AFFECTED_CPU_UNCONFIRMED, UNKNOWN_VERIFY, MITIGATED, NOT_IMPACTED])
        self.assertEqual(AFFECTED_CPU_UNCONFIRMED, "Affected build \u2013 CPU unconfirmed")
        self.assertEqual(UNKNOWN_VERIFY, "Unknown \u2013 verify")

    def test_affected_vs_unknown(self):
        y, u, n = cond("yes"), cond("unknown"), cond("no")
        self.assertEqual(decide(y, u, u, u)[0], AFFECTED_CPU_UNCONFIRMED)
        self.assertEqual(decide(u, y, u, u)[0], UNKNOWN_VERIFY)
        self.assertEqual(decide(y, y, u, n)[0], MITIGATED)

    def test_first_no_wins(self):
        v, reason = decide(cond("no", "fixed"), cond("no", "arm"), cond("yes"), cond("yes"))
        self.assertEqual(v, NOT_IMPACTED)
        self.assertEqual(reason, "R: fixed")

    def test_no_beats_mitigation(self):
        self.assertEqual(decide(cond("yes"), cond("yes"), cond("no"), cond("no"))[0], NOT_IMPACTED)

    def test_unknown_never_clears(self):
        for combo in itertools.product(("yes", "unknown"), repeat=4):
            r, a, c, j = (cond(v) for v in combo)
            self.assertNotEqual(decide(r, a, c, j)[0], NOT_IMPACTED, combo)


class ConfidenceTests(unittest.TestCase):
    def test_high(self):
        h = host(cpu_flags=ALL_FLAGS, live_flags={"UseBASE64Intrinsics": True, "UseAVX": 3})
        self.assertEqual(
            confidence(cond("yes"), cond("yes"), cond("yes"), cond("yes"), h), "high")

    def test_medium_host_cpu(self):
        h = host(cpu_flags=ALL_FLAGS)
        self.assertEqual(
            confidence(cond("yes"), cond("yes"), cond("yes"), cond("unknown"), h), "medium")

    def test_medium_model_rule_out(self):
        self.assertEqual(
            confidence(cond("yes"), cond("yes"), cond("no"), cond("unknown"), None), "medium")

    def test_low(self):
        self.assertEqual(
            confidence(cond("unknown"), cond("yes"), cond("no"), cond("unknown"), None), "low")
        self.assertEqual(
            confidence(cond("yes"), cond("yes"), cond("unknown"), cond("unknown"), None), "low")


class PriorityTests(unittest.TestCase):
    def test_priority(self):
        p = priority({"java_path": "/opt/atlassian/jira/jre/"})
        self.assertIn("pre-auth product: Jira", p)
        self.assertIn("bundled runtime", p)
        self.assertEqual(
            priority({"java_path": "/usr/lib/jvm/java-21-openjdk-amd64/", "managed_by_os": True}), "")

    def test_post_auth_and_os_path(self):
        self.assertEqual(
            priority({"java_path": "/opt/kafka/jre", "managed_by_os": True}),
            "post-auth product: Kafka")
        self.assertEqual(priority({"java_path": "/usr/java/latest", "managed_by_os": False}), "")

    def test_empty_row(self):
        self.assertEqual(priority({}), "")


if __name__ == "__main__":
    unittest.main()
