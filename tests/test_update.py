import unittest

from winaudit import update
from winaudit.models import Severity

# trecho real da saida do 'winget upgrade' (pt-BR)
WINGET = """\
Nome                                                         ID                                     Versão         Disponível           Origem
-----------------------------------------------------------------------------------------------------------------------------------------------
Epic Games Launcher                                          EpicGames.EpicGamesLauncher            1.3.128.0      1.3.210.0            winget
Git                                                          Git.Git                                2.49.0         2.56.1               winget
HidHide                                                      Nefarius.HidHide                       1.2.128        1.5.230              winget
Soulframe                                                    DigitalExtremes.Soulframe              1.0.0          Preludes-13-Hotfix-5 winget
Ubisoft Connect                                              XPDP2QW12DFSFK                         27.0           174.0.13368          msstore
WinRAR 7.10 (64-bit)                                         RARLab.WinRAR                          7.10.0         7.23.0               winget
6 atualizações disponíveis.

Os seguintes pacotes têm uma atualização disponível, mas exigem direcionamento explícito para atualização:
Nome      ID              Versão  Disponível Origem
---------------------------------------------------
Cursor    Anysphere.Cursor 2.6.12 3.31.15    winget
"""


class ParseTest(unittest.TestCase):
    def test_parse_rows(self):
        rows = update.parse_winget_table(WINGET)
        ids = [r["id"] for r in rows]
        self.assertEqual(ids, ["EpicGames.EpicGamesLauncher", "Git.Git", "Nefarius.HidHide",
                               "DigitalExtremes.Soulframe", "XPDP2QW12DFSFK", "RARLab.WinRAR", "Anysphere.Cursor"])
        winrar = rows[5]
        self.assertEqual((winrar["name"], winrar["version"], winrar["available"], winrar["source"]),
                         ("WinRAR 7.10 (64-bit)", "7.10.0", "7.23.0", "winget"))
        self.assertFalse(winrar["explicit"])
        self.assertTrue(rows[-1]["explicit"])

    def test_english_and_carriage_returns(self):
        text = ("   - \r   \ \rName  Id       Version Available Source\n"
                "-----------------------------------------\n"
                "Git   Git.Git  2.49.0  2.56.1    winget\n"
                "1 upgrades available.\n")
        rows = update.parse_winget_table(text)
        self.assertEqual([(r["name"], r["id"]) for r in rows], [("Git", "Git.Git")])

    def test_empty(self):
        self.assertEqual(update.parse_winget_table("Nenhuma atualização disponível.\n"), [])


class GameTest(unittest.TestCase):
    def row(self, name, pkg_id):
        return {"name": name, "id": pkg_id}

    def test_by_winget_id(self):
        self.assertTrue(update.is_game(self.row("Soulframe", "DigitalExtremes.Soulframe"), None))
        self.assertTrue(update.is_game(self.row("Epic Games Launcher", "EpicGames.EpicGamesLauncher"), None))

    def test_by_name_store_id(self):
        self.assertTrue(update.is_game(self.row("Ubisoft Connect", "XPDP2QW12DFSFK"), None))

    def test_by_registry(self):
        steam = {"name": "Counter-Strike 2", "key": "Steam App 730", "publisher": "", "location": ""}
        self.assertTrue(update.is_game(self.row("Counter-Strike 2", "X"), steam))
        path = {"name": "A Way Out", "key": "x", "publisher": "",
                "location": r"C:\Program Files\EA Games\A Way Out"}
        self.assertTrue(update.is_game(self.row("A Way Out", "X"), path))
        pub = {"name": "VALORANT", "key": "x", "publisher": "Riot Games, Inc", "location": ""}
        self.assertTrue(update.is_game(self.row("VALORANT", "X"), pub))

    def test_not_game(self):
        git = {"name": "Git", "key": "Git_is1", "publisher": "The Git Development Community",
               "location": r"C:\Program Files\Git"}
        self.assertFalse(update.is_game(self.row("Git", "Git.Git"), git))
        self.assertFalse(update.is_game(self.row("HidHide", "Nefarius.HidHide"), None))


class PlanTest(unittest.TestCase):
    def setUp(self):
        self.rows = update.parse_winget_table(WINGET)
        self.apps = [{"name": "Git", "key": "Git_is1", "publisher": "", "location": ""},
                     {"name": "WinRAR 7.10 (64-bit)", "key": "WinRAR", "publisher": "win.rar GmbH", "location": ""},
                     {"name": "Google Chrome", "key": "Google Chrome", "publisher": "Google LLC", "location": ""}]

    def vuln(self, app, sev, exploited):
        return {"app": app, "label": app["name"], "severity": sev, "cves": 3, "exploited": exploited}

    def test_default_only_vulnerable(self):
        vulns = [self.vuln(self.apps[0], Severity.HIGH, 1), self.vuln(self.apps[1], Severity.CRITICAL, 2),
                 self.vuln(self.apps[2], Severity.CRITICAL, 14)]
        plan, games, manual = update.build_plan(self.rows, self.apps, vulns, include_games=False)
        self.assertEqual([r["id"] for r, _ in plan], ["RARLab.WinRAR", "Git.Git"])  # mais grave primeiro
        self.assertEqual([v["label"] for v in manual], ["Google Chrome"])  # sem atualizacao no winget

    def test_all_skips_games_and_pinned(self):
        plan, games, _ = update.build_plan(self.rows, self.apps, None, include_games=False)
        self.assertEqual([r["id"] for r, _ in plan], ["Git.Git", "Nefarius.HidHide", "RARLab.WinRAR"])
        self.assertEqual(len(games), 3)

    def test_all_with_games(self):
        plan, games, _ = update.build_plan(self.rows, self.apps, None, include_games=True)
        self.assertEqual(len(plan), 6)
        self.assertEqual(games, [])


if __name__ == "__main__":
    unittest.main()
