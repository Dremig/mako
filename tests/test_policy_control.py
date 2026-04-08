from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from web_agent.solver_shared import (
    cluster_for_failure_reason,
    normalize_failure_reason,
    validate_action,
    MemoryStore,
)


class PolicyControlTests(unittest.TestCase):
    def test_failure_reason_normalization(self) -> None:
        self.assertEqual(normalize_failure_reason(""), "none")
        self.assertEqual(normalize_failure_reason("METHOD_NOT_ALLOWED"), "method_not_allowed")
        self.assertEqual(normalize_failure_reason("weird_new_reason"), "needs_followup")

    def test_failure_reason_cluster_mapping(self) -> None:
        self.assertEqual(cluster_for_failure_reason("missing_required_parameter"), "hypothesis_stale")
        self.assertEqual(cluster_for_failure_reason("timeout_without_signal"), "timeout_spiral")
        self.assertEqual(cluster_for_failure_reason("weird_new_reason"), "none")

    def test_validate_action_blocks_discovery_drift_under_semantic_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            memory = MemoryStore(Path(td) / "mem.sqlite", run_id="t1")
            memory.upsert_fact("error.semantic.missing_required_parameter", "true", 0.96, 1)
            memory.upsert_fact("endpoint.focus", "/api/login", 0.90, 1)

            ok, reason = validate_action(
                phase="probe",
                expected_phase="probe",
                command="curl -si $TARGET_URL/robots.txt",
                memory=memory,
                history=[],
                controller_reflection={},
            )
            self.assertFalse(ok)
            self.assertIn("Semantic error recovery", reason)

    def test_validate_action_blocks_non_focused_command_under_missing_parameter(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            memory = MemoryStore(Path(td) / "mem.sqlite", run_id="t1b")
            memory.upsert_fact("error.semantic.missing_required_parameter", "true", 0.96, 1)
            memory.upsert_fact("endpoint.focus", "/api/login", 0.90, 1)

            ok, reason = validate_action(
                phase="probe",
                expected_phase="probe",
                command="curl -si $TARGET_URL/api/profile",
                memory=memory,
                history=[],
                controller_reflection={},
            )
            self.assertFalse(ok)
            self.assertIn("action must focus on /api/login", reason)

    def test_validate_action_blocks_same_family_when_controller_requires_change(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            memory = MemoryStore(Path(td) / "mem.sqlite", run_id="t2")
            history = [{"command": "curl -si $TARGET_URL/", "returncode": 1, "info_gain": 0}]
            policy = {"requirements": {"change_command_family": True}, "failure_cluster": "low_gain_loop"}

            ok, reason = validate_action(
                phase="probe",
                expected_phase="probe",
                command="curl -si $TARGET_URL/login",
                memory=memory,
                history=history,
                controller_reflection=policy,
            )
            self.assertFalse(ok)
            self.assertIn("command family change", reason)

    def test_validate_action_controller_rule_registry_paths(self) -> None:
        cases = [
            {
                "name": "must_avoid_recon_regression",
                "phase": "recon",
                "policy": {"must_avoid": ["Do not regress to recon when entrypoint/vuln signals already exist."]},
                "history": [],
                "expected_ok": False,
                "reason_contains": "recon regression",
            },
            {
                "name": "cluster_repeat_family_block",
                "phase": "probe",
                "policy": {"failure_cluster": "low_gain_loop"},
                "history": [{"command": "curl -si $TARGET_URL/", "returncode": 0, "info_gain": 1}],
                "expected_ok": False,
                "reason_contains": "repeated command family",
            },
            {
                "name": "unknown_cluster_fallback",
                "phase": "probe",
                "policy": {"failure_cluster": "totally_new_cluster_name"},
                "history": [{"command": "curl -si $TARGET_URL/", "returncode": 0, "info_gain": 1}],
                "expected_ok": True,
                "reason_contains": "",
            },
        ]
        with tempfile.TemporaryDirectory() as td:
            memory = MemoryStore(Path(td) / "mem.sqlite", run_id="t3")
            for case in cases:
                with self.subTest(case=case["name"]):
                    ok, reason = validate_action(
                        phase=case["phase"],
                        expected_phase="probe",
                        command="curl -si $TARGET_URL/login",
                        memory=memory,
                        history=case["history"],
                        controller_reflection=case["policy"],
                    )
                    self.assertEqual(ok, case["expected_ok"])
                    if case["reason_contains"]:
                        self.assertIn(case["reason_contains"], reason)
                    else:
                        self.assertEqual(reason, "")


if __name__ == "__main__":
    unittest.main()
