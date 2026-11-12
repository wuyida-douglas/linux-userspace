from __future__ import annotations

import unittest

from pipeline.prompts import SHARED


class IsolationPromptTests(unittest.TestCase):
    def test_shared_prompt_states_the_isolation_rules(self):
        required = [
            "Do not list, scan, search, find, grep, read, copy or inspect any path outside",
            "Do not read, use or trust any memory",
            "Do not use, copy, mount, read or consult any previously synthesized task",
            "Start from input/",
        ]
        for phrase in required:
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, SHARED)

    def test_shared_prompt_is_used_by_every_stage(self):
        from pipeline import prompts
        for name in ("ROUTE", "SYNTHESIZE", "REVIEW"):
            with self.subTest(stage=name):
                self.assertIn("ISOLATION", getattr(prompts, name))

    def test_file_pov_oracle_receives_the_input_path(self):
        from pipeline.prompts import branch_prompt
        prompt = branch_prompt("FILE-POV")
        self.assertIn("/run/pass2fail/input.bin", prompt)
        self.assertIn("with that path as `$1`", prompt)

    def test_prompts_require_image_leak_and_oracle_breadth_checks(self):
        from pipeline.prompts import REVIEW, SYNTHESIZE
        for phrase in ("Image-leak audit", "Main-visible answer material",
                       "Oracle breadth is a suitability check",
                       "phase-aware negative control"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, REVIEW)
        for phrase in ("not only their Dockerfiles", "main is agent-visible",
                       "no broader than instruction.md's effect A",
                       "phase-aware negative control"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, SYNTHESIZE)

    def test_review_uses_two_decision_levels_and_a_two_key_output(self):
        from pipeline.prompts import REVIEW
        self.assertIn("exactly two decision", REVIEW)
        self.assertIn("suitability failure", REVIEW)
        self.assertIn("advisory note", REVIEW)
        self.assertIn("only these two keys", REVIEW)
        for legacy in ("blocker", "major", "minor"):
            with self.subTest(legacy=legacy):
                self.assertNotIn(legacy, REVIEW)


if __name__ == "__main__":
    unittest.main()