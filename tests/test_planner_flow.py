from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from web_agent.planner import apply_plan_patch, build_plan_patch, current_subtask, fallback_plan
from web_agent.solver_shared import MemoryStore


class PlannerFlowTests(unittest.TestCase):
    def test_fallback_plan_prioritizes_service_recovery_when_empty_reply(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            memory = MemoryStore(Path(td) / "mem.sqlite", run_id="p1")
            memory.upsert_fact("target", "http://127.0.0.1:8080", 1.0, 0)
            memory.upsert_fact("service.http.empty_reply", "true", 0.95, 1)
            plan = fallback_plan(memory)
            titles = [item["title"] for item in plan["subtasks"]]
            self.assertTrue(any("Recover abnormal root service behavior" in title for title in titles))
            active = current_subtask(plan)
            self.assertEqual(active["phase"], "recon")

    def test_build_plan_patch_inserts_followup_endpoint_probe(self) -> None:
        current = {
            "id": "html-surface",
            "title": "Extract routes",
            "phase": "extract",
            "goal": "extract endpoints",
            "success_signal": "endpoint.focus",
            "suggested_action": "extract_html_attack_surface",
            "status": "pending",
        }
        facts = [("endpoint.focus", "/homework", 0.93)]
        patch = build_plan_patch(
            current=current,
            reflection={"failure_reason": "needs_followup"},
            controller_reflection={"failure_cluster": "none"},
            facts=facts,
            result={"returncode": 0},
            gain=0.5,
        )
        self.assertEqual(patch["mark_current"], "completed")
        self.assertTrue(any("Probe focused endpoint /homework" in item["title"] for item in patch["insert_after"]))

    def test_apply_plan_patch_marks_current_and_appends_followups(self) -> None:
        plan = {
            "rationale": "test",
            "subtasks": [
                {
                    "id": "st-1",
                    "title": "Fetch baseline",
                    "phase": "recon",
                    "goal": "baseline",
                    "success_signal": "saved",
                    "suggested_action": "http_probe_with_baseline",
                    "status": "pending",
                }
            ],
        }
        patch = {
            "mark_current": "completed",
            "insert_after": [
                {
                    "title": "Parse HTML routes",
                    "phase": "extract",
                    "goal": "extract routes",
                    "success_signal": "endpoint.focus",
                    "suggested_action": "extract_html_attack_surface",
                }
            ],
        }
        updated = apply_plan_patch(plan, "st-1", patch)
        self.assertEqual(updated["subtasks"][0]["status"], "completed")
        self.assertEqual(updated["subtasks"][1]["suggested_action"], "extract_html_attack_surface")


if __name__ == "__main__":
    unittest.main()
