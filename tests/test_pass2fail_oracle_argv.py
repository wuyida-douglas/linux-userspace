from __future__ import annotations

import unittest

from pipeline.pass2fail_verifier import FILE_POV_INPUT, oracle_argv_for


class FilePovOracleArgvTests(unittest.TestCase):
    def test_file_pov_passes_the_prepared_input_path(self):
        contract = {"branch": "FILE-POV", "oracle": {"argv": ["/private/oracle.sh"]}}
        self.assertEqual(
            oracle_argv_for(contract),
            ["/private/oracle.sh", FILE_POV_INPUT],
        )

    def test_other_branches_are_unchanged(self):
        for branch in ("SVC-EXPLOIT", "FILE-EXPLOIT"):
            with self.subTest(branch=branch):
                contract = {"branch": branch, "oracle": {"argv": ["/private/oracle.sh"]}}
                self.assertEqual(oracle_argv_for(contract), ["/private/oracle.sh"])

    def test_it_does_not_mutate_the_contract(self):
        argv = ["/private/oracle.sh"]
        contract = {"branch": "FILE-POV", "oracle": {"argv": argv}}
        oracle_argv_for(contract)
        self.assertEqual(argv, ["/private/oracle.sh"])


if __name__ == "__main__":
    unittest.main()