import unittest

from winaudit.models import CheckResult, Severity, Status, failed, info, passed, warn
from winaudit.scoring import compute_score, grade


def result(*findings):
    return [CheckResult("x", "X", list(findings))]


class ScoringTest(unittest.TestCase):
    def test_all_pass_is_100(self):
        self.assertEqual(compute_score(result(passed("a", "a"), info("b", "b"))), 100)

    def test_fail_weights(self):
        self.assertEqual(compute_score(result(failed("a", "a", Severity.CRITICAL, "", ""))), 75)
        self.assertEqual(compute_score(result(failed("a", "a", Severity.HIGH, "", ""))), 85)

    def test_warn_counts_half(self):
        self.assertEqual(compute_score(result(warn("a", "a", Severity.MEDIUM, "", ""))), 96)

    def test_floor_at_zero(self):
        many = [failed(str(i), "x", Severity.CRITICAL, "", "") for i in range(10)]
        self.assertEqual(compute_score(result(*many)), 0)

    def test_grades(self):
        self.assertEqual([grade(s) for s in (95, 85, 75, 65, 10)], list("ABCDF"))

    def test_to_dict_serializes_enums(self):
        d = failed("a", "t", Severity.HIGH, "d", "r").to_dict()
        self.assertEqual((d["status"], d["severity"]), ("FAIL", "high"))


if __name__ == "__main__":
    unittest.main()
