import unittest
from unittest import mock

from winaudit.checks import Context
from winaudit.checks import accounts, cve, firewall, startup, uac
from winaudit.models import Severity, Status
from winaudit.runner import _run_one
from winaudit.checks import CheckDef

CTX = Context(is_admin=False)


def statuses(findings):
    return {f.id: f.status for f in findings}


class FirewallTest(unittest.TestCase):
    def test_disabled_public_profile_is_high_fail(self):
        data = [
            {"Name": "Domain", "Enabled": "True", "DefaultInboundAction": "Block"},
            {"Name": "Public", "Enabled": "False", "DefaultInboundAction": "Block"},
            {"Name": "Private", "Enabled": "True", "DefaultInboundAction": "Allow"},
        ]
        with mock.patch.object(firewall, "run_ps", return_value=data):
            fs = firewall.firewall(CTX)
        s = statuses(fs)
        self.assertEqual(s["firewall.domain"], Status.PASS)
        self.assertEqual(s["firewall.public"], Status.FAIL)
        self.assertEqual(s["firewall.private"], Status.WARN)
        self.assertEqual(next(f for f in fs if f.id == "firewall.public").severity, Severity.HIGH)


class UacTest(unittest.TestCase):
    def test_uac_off(self):
        with mock.patch.object(uac, "read_value", side_effect=lambda k, n, d=None: 0 if n == "EnableLUA" else d):
            fs = uac.uac(CTX)
        self.assertEqual(fs[0].status, Status.FAIL)

    def test_silent_elevation(self):
        vals = {"EnableLUA": 1, "ConsentPromptBehaviorAdmin": 0}
        with mock.patch.object(uac, "read_value", side_effect=lambda k, n, d=None: vals.get(n, d)):
            fs = uac.uac(CTX)
        self.assertEqual(statuses(fs)["uac.prompt"], Status.FAIL)


class AccountsTest(unittest.TestCase):
    def test_guest_enabled(self):
        users = [
            {"Name": "Convidado", "Enabled": True, "PasswordRequired": False, "Sid": "S-1-5-21-1-2-3-501"},
            {"Name": "ana", "Enabled": True, "PasswordRequired": True, "Sid": "S-1-5-21-1-2-3-1001"},
        ]
        admins = [{"Name": "PC\\ana"}]

        def fake(cmd, **_):
            return users if "Get-LocalUser" in cmd else admins

        with mock.patch.object(accounts, "run_ps", side_effect=fake), \
             mock.patch.object(accounts.getpass, "getuser", return_value="ana"):
            fs = accounts.accounts(CTX)
        s = statuses(fs)
        self.assertEqual(s["accounts.guest"], Status.FAIL)
        self.assertEqual(s["accounts.daily_admin"], Status.WARN)


class StartupClassifyTest(unittest.TestCase):
    def test_encoded_powershell(self):
        sev, _ = startup.classify("powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA")
        self.assertEqual(sev, Severity.HIGH)

    def test_temp_folder(self):
        sev, _ = startup.classify(r'"C:\Users\x\AppData\Local\Temp\upd.exe" /silent')
        self.assertEqual(sev, Severity.MEDIUM)

    def test_normal_program(self):
        self.assertIsNone(startup.classify(r'"C:\Program Files\Spotify\Spotify.exe" --autostart'))


def nvd_cve(criteria, vulnerable=True, platform=None, desc="bug", **bounds):
    matches = [dict(criteria=criteria, vulnerable=vulnerable, **bounds)]
    if platform:
        matches.append({"criteria": platform, "vulnerable": False})
    return {"id": "CVE-X", "descriptions": [{"lang": "en", "value": desc}],
            "configurations": [{"nodes": [{"cpeMatch": matches}]}]}


class CveFilterTest(unittest.TestCase):
    A = "cpe:2.3:a:rarlab:winrar:*:*:*:*:*:*:*:*"

    def test_version_in_range(self):
        self.assertTrue(cve.affects(nvd_cve(self.A, versionEndExcluding="7.13"), "rarlab", "winrar", "7.10"))

    def test_version_already_fixed(self):
        self.assertFalse(cve.affects(nvd_cve(self.A, versionEndExcluding="7.10"), "rarlab", "winrar", "7.10"))

    def test_numeric_not_lexical_compare(self):
        self.assertFalse(cve.affects(nvd_cve(self.A, versionEndExcluding="7.9"), "rarlab", "winrar", "7.10"))

    def test_unbounded_wildcard_ignored(self):
        self.assertFalse(cve.affects(nvd_cve(self.A), "rarlab", "winrar", "7.10"))

    def test_other_product_ignored(self):
        c = nvd_cve("cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*", versionEndExcluding="99")
        self.assertFalse(cve.affects(c, "nodejs", "node.js", "22.1.0"))

    def test_android_only_ignored(self):
        c = nvd_cve("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", versionEndExcluding="150",
                    platform="cpe:2.3:o:google:android:-:*:*:*:*:*:*:*")
        self.assertFalse(cve.affects(c, "google", "chrome", "133.0.1"))
        c2 = nvd_cve("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", versionEndExcluding="150",
                     platform="cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*")
        self.assertTrue(cve.affects(c2, "google", "chrome", "133.0.1"))

    def test_android_only_by_description(self):
        c = nvd_cve("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", versionEndExcluding="150",
                    desc="Incorrect UI in Google Chrome on Android prior to 150")
        self.assertFalse(cve.affects(c, "google", "chrome", "133.0.1"))

    def test_catalog_matching(self):
        apps = [{"name": "WinRAR 7.10 (64-bit)", "version": "7.10.0"},
                {"name": "Python 3.11.9 (64-bit)", "version": "3.11.9150.0"},
                {"name": "Spotify", "version": "1.2"}]
        cpes = [c for _, c in cve.match_catalog(apps)]
        self.assertIn("cpe:2.3:a:rarlab:winrar:7.10:*:*:*:*:*:*:*", cpes)
        self.assertIn("cpe:2.3:a:python:python:3.11.9:*:*:*:*:*:*:*", cpes)
        self.assertEqual(len(cpes), 2)


    def test_catalog_openvpn_connect_is_not_openvpn(self):
        apps = [{"name": "OpenVPN Connect", "version": "3.9.0"}]
        self.assertEqual(cve.match_catalog(apps)[0][1], "cpe:2.3:a:openvpn:connect:3.9.0:*:*:*:*:*:*:*")

    def test_catalog_postgres_version_suffix(self):
        apps = [{"name": "PostgreSQL 16", "version": "16.13-2"}]
        self.assertEqual(cve.match_catalog(apps)[0][1], "cpe:2.3:a:postgresql:postgresql:16.13:*:*:*:*:*:*:*")


class KevTest(unittest.TestCase):
    CPE = "cpe:2.3:a:git-scm:git:2.49.0:*:*:*:*:*:*:*"

    def cves(self):
        return [{"id": "CVE-A", "score": 9.8, "desc": "teorica"},
                {"id": "CVE-B", "score": 5.0, "desc": "explorada"}]

    def test_exploited_raises_severity_and_goes_first(self):
        f = cve._finding("App 1.0", self.CPE, self.cves(), False, {"CVE-B": {"ransomware": False}})
        self.assertEqual(f.status, Status.FAIL)
        self.assertEqual(f.severity, Severity.CRITICAL)  # CVSS 9.8 ja e critica; KEV nao rebaixa
        self.assertIn("1 explorada(s)", f.title)
        self.assertTrue(f.evidence[0].startswith("[EXPLORADA] CVE-B"))

    def test_exploited_medium_becomes_high(self):
        f = cve._finding("App 1.0", self.CPE, [{"id": "CVE-B", "score": 5.0, "desc": "x"}], False,
                         {"CVE-B": {"ransomware": False}})
        self.assertEqual((f.status, f.severity), (Status.FAIL, Severity.HIGH))

    def test_ransomware_is_critical(self):
        f = cve._finding("App 1.0", self.CPE, [{"id": "CVE-B", "score": 5.0, "desc": "x"}], False,
                         {"CVE-B": {"ransomware": True}})
        self.assertEqual(f.severity, Severity.CRITICAL)
        self.assertIn("RANSOMWARE", f.evidence[0])

    def test_without_kev_uses_cvss(self):
        f = cve._finding("App 1.0", self.CPE, [{"id": "CVE-B", "score": 5.0, "desc": "x"}], False, {})
        self.assertEqual((f.status, f.severity), (Status.WARN, Severity.MEDIUM))
        self.assertNotIn("explorada", f.title)

    def test_all_exploited_shown_even_beyond_eight(self):
        cves = [{"id": f"CVE-{i}", "score": 9.0, "desc": ""} for i in range(20)]
        kev = {f"CVE-{i}": {"ransomware": False} for i in range(12)}
        f = cve._finding("App 1.0", self.CPE, cves, False, kev)
        self.assertEqual(len(f.evidence), 12)


class RiskTest(unittest.TestCase):
    # descricoes reais do NVD
    def test_browser_page(self):
        s, imp = cve.classify_cve("Type confusion in V8 in Google Chrome prior to 140.0.7339.185 allowed a remote "
                                  "attacker to potentially exploit heap corruption via a crafted HTML page.")
        self.assertEqual(s, "web")

    def test_sandbox_escape(self):
        s, imp = cve.classify_cve("Use after free in GPU in Google Chrome prior to 150.0.7871.47 allowed a remote "
                                  "attacker who had compromised the renderer process to potentially perform a "
                                  "sandbox escape via a crafted HTML page.")
        self.assertEqual((s, imp), ("web", ["code"]))

    def test_archive(self):
        s, imp = cve.classify_cve("A path traversal vulnerability affecting the Windows version of WinRAR allows the "
                                  "attackers to execute arbitrary code by crafting malicious archive files.")
        self.assertEqual((s, imp), ("file", ["code"]))

    def test_repository(self):
        s, _ = cve.classify_cve("When reading a config value, Git strips any trailing carriage return... "
                                "a malicious repository can cause a submodule to be checked out to an "
                                "altered path.")
        self.assertEqual(s, "repo")

    def test_database_user(self):
        s, imp = cve.classify_cve("Stack buffer overflow in PostgreSQL module refint allows an unprivileged "
                                  "database user to execute arbitrary code as the operating system user.")
        self.assertEqual((s, imp), ("authuser", ["code"]))

    def test_fallback_to_cvss_vector(self):
        self.assertEqual(cve.classify_cve("Bug in Core.", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")[0], "local")
        self.assertEqual(cve.classify_cve("Bug in Core.", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")[0],
                         "network")
        self.assertEqual(cve.classify_cve("Bug in Core.", "")[0], "other")

    def test_summary_groups_and_ranks_exploited_first(self):
        cves = [{"id": "A", "scenario": "web", "impacts": ["code"]},
                {"id": "B", "scenario": "web", "impacts": ["spoof"]},
                {"id": "C", "scenario": "file", "impacts": ["code"]}]
        lines = cve.risk_summary(cves, {"C": {"ransomware": True}})
        self.assertTrue(lines[0].startswith("Abrir ou extrair um arquivo malicioso"))
        self.assertIn("1 falha(s), 1 ja explorada", lines[0])
        self.assertIn("Ela pode permitir executar codigo", lines[0])
        self.assertIn("Visitar um site malicioso", lines[1])
        self.assertIn("1 delas pode permitir executar codigo", lines[1])

    def test_finding_carries_risks(self):
        f = cve._finding("App 1.0", "cpe:2.3:a:x:y:1.0:*:*:*:*:*:*:*",
                         [{"id": "A", "score": 9.0, "desc": "", "scenario": "web", "impacts": ["code"]}], False, {})
        self.assertEqual(len(f.risks), 1)
        self.assertIn("risks", f.to_dict())


class CveAutoTest(unittest.TestCase):
    def test_clean_name(self):
        self.assertEqual(cve.clean_name("Mozilla Firefox (x64 pt-BR) 160.0.1"), "Mozilla Firefox")
        self.assertEqual(cve.clean_name("Burp Suite Community Edition 2025.5.4"), "Burp Suite Community Edition")
        self.assertEqual(cve.clean_name("Cyotek WebCopy version 1.9.1.872"), "Cyotek WebCopy")
        self.assertEqual(cve.clean_name("HWiNFO® 64"), "HWiNFO 64")

    def test_pick_with_extra_product_word(self):
        names = ["cpe:2.3:a:oracle:vm_virtualbox:7.0.0:*:*:*:*:*:*:*"] * 3 + \
                ["cpe:2.3:a:oracle:xvm_virtualbox:3.0:*:*:*:*:*:*:*"]
        self.assertEqual(cve.pick_cpe("Oracle VirtualBox", "Oracle Corporation", names), ("oracle", "vm_virtualbox"))

    def test_pick_exact(self):
        names = ["cpe:2.3:a:docker:desktop:4.1.0:*:*:*:*:*:*:*",
                 "cpe:2.3:a:docker:docker:20.10:*:*:*:*:*:*:*"]
        self.assertEqual(cve.pick_cpe("Docker Desktop", "Docker Inc.", names), ("docker", "desktop"))

    def test_pick_rejects_other_vendor(self):
        # mesmo nome de produto, fabricante diferente: nao arrisca
        names = ["cpe:2.3:a:someone:webcopy:1.0:*:*:*:*:*:*:*"]
        self.assertIsNone(cve.pick_cpe("Cyotek WebCopy", "Cyotek Ltd.", names))

    def test_pick_prefers_popular_near_match(self):
        # dados reais do NVD: oracle:virtualbox tem 8 entradas antigas, vm_virtualbox tem 272
        names = ["cpe:2.3:a:oracle:vm_virtualbox:7.0:*:*:*:*:*:*:*"] * 272 + \
                ["cpe:2.3:a:oracle:virtualbox:1.0:*:*:*:*:*:*:*"] * 8
        self.assertEqual(cve.pick_cpe("Oracle VirtualBox", "Oracle Corporation", names), ("oracle", "vm_virtualbox"))

    def test_pick_rejects_vendor_sharing_one_word(self):
        # dado real: 'Slack' casava com slack_morphism_project
        names = ["cpe:2.3:a:slack_morphism_project:slack_morphism:1.0:*:*:*:*:*:*:*"] * 66
        self.assertIsNone(cve.pick_cpe("Slack", "Slack Technologies Inc.", names))

    def test_pick_ignores_edition_words(self):
        names = ["cpe:2.3:a:portswigger:burp_suite:2023.1:*:*:*:*:*:*:*"]
        self.assertEqual(cve.pick_cpe("Burp Suite Community Edition", "PortSwigger Web Security", names),
                         ("portswigger", "burp_suite"))

    def test_pick_vendor_with_suffix(self):
        names = ["cpe:2.3:a:konghq:insomnia:2023.1:*:*:*:*:*:*:*"]
        self.assertEqual(cve.pick_cpe("Insomnia", "Kong", names), ("konghq", "insomnia"))

    def test_pick_rejects_loose_product(self):
        names = ["cpe:2.3:a:microsoft:teams:1.0:*:*:*:*:*:*:*"]
        self.assertIsNone(cve.pick_cpe("Microsoft Teams Meeting Add-in for Office", "Microsoft", names))

    def test_candidates_skip_private_and_noise(self):
        apps = [{"name": "Roblox Player for alice", "version": "1.0"},
                {"name": "Microsoft Visual C++ 2013 Redistributable (x64)", "version": "12.0"},
                {"name": "Steam", "version": ""},
                {"name": "Oracle VirtualBox 7.1.6", "version": "7.1.6"}]
        with mock.patch.object(cve, "_private_words", return_value=["alice"]):
            names = [c for _, c in cve.auto_candidates(apps)]
        self.assertEqual(names, ["Oracle VirtualBox"])


class StartupCountTest(unittest.TestCase):
    def test_hidden_tasks_not_counted_as_analyzed(self):
        entries = [("HKCU\\Run", "Spotify", r"C:\Spotify.exe"),
                   ("Tarefa agendada", "\\Oculta", "")]
        with mock.patch.object(startup, "collect_entries", return_value=entries):
            fs = {f.id: f for f in startup.startup(CTX)}
        self.assertIn("1 item(ns) analisado(s)", fs["startup.clean"].details)
        self.assertIn("1 tarefa(s)", fs["startup.clean"].details)


class RunnerTest(unittest.TestCase):
    def test_crashing_check_becomes_info(self):
        def boom(ctx):
            raise RuntimeError("kaboom")
        r = _run_one(CheckDef("boom", "X", boom), CTX)
        self.assertEqual(r.findings[0].status, Status.INFO)
        self.assertIn("kaboom", r.error)


if __name__ == "__main__":
    unittest.main()
