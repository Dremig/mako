from __future__ import annotations

import unittest

from web_agent.deliberation import choose_final_proposal


class DeliberationTests(unittest.TestCase):
    def test_choose_final_proposal_prefers_corrector_when_fragile(self) -> None:
        recommender = {
            "analysis": "Use bs4 to parse HTML quickly.",
            "decision": "command",
            "phase": "extract",
            "command": "python3 - <<'PY'\nfrom bs4 import BeautifulSoup\nPY",
            "action": {},
            "success_signal": "routes extracted",
            "next_if_fail": "",
        }
        corrector = {
            "verdict": "fragile",
            "issues": ["depends on bs4"],
            "corrected": {
                "analysis": "Use the structured HTML extractor instead of optional dependencies.",
                "decision": "action",
                "phase": "extract",
                "command": "",
                "action": {"name": "extract_html_attack_surface", "args": {}},
                "success_signal": "endpoint.focus appears",
                "next_if_fail": "",
            },
        }
        final, judge = choose_final_proposal(
            recommender=recommender,
            corrector=corrector,
            active_action="extract_html_attack_surface",
        )
        self.assertEqual(final["decision"], "action")
        self.assertEqual(final["action"]["name"], "extract_html_attack_surface")
        self.assertEqual(judge["decision"], "accept_corrected")

    def test_choose_final_proposal_forces_planner_action_when_missing(self) -> None:
        recommender = {
            "analysis": "Fetch current endpoint.",
            "decision": "command",
            "phase": "probe",
            "command": "curl -si $TARGET_URL/",
            "action": {},
            "success_signal": "response collected",
            "next_if_fail": "",
        }
        corrector = {"verdict": "accept", "issues": [], "corrected": recommender}
        final, judge = choose_final_proposal(
            recommender=recommender,
            corrector=corrector,
            active_action="service_recovery_probe",
        )
        self.assertEqual(final["decision"], "action")
        self.assertEqual(final["action"]["name"], "service_recovery_probe")
        self.assertEqual(judge["decision"], "force_planner_action")


if __name__ == "__main__":
    unittest.main()
