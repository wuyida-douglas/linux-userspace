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


if __name__ == "__main__":
    unittest.main()