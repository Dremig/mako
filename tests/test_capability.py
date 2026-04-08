from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from web_agent.capability import detect_capability_gap, resolve_capability_gap
from web_agent.solver_shared import MemoryStore


class CapabilityTests(unittest.TestCase):
    def test_detects_optional_python_dependency_gap(self) -> None:
        gap = detect_capability_gap(
            {"decision": "command", "command": "python3 -c 'from bs4 import BeautifulSoup; print(1)'"},
            {"python3": "/usr/bin/python3"},
        )
        self.assertEqual(gap["kind"], "optional_python_dependency")
        self.assertEqual(gap["dependency"], "beautifulsoup4")

    def test_prefers_reusing_planner_action_over_install(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            memory = MemoryStore(Path(td) / "mem.sqlite", run_id="cap1")
            memory.upsert_fact("artifact.dir", td, 1.0, 0)
            result = resolve_capability_gap(
                proposal={"decision": "command", "command": "python3 -c 'from bs4 import BeautifulSoup'"},
                active_action="extract_html_attack_surface",
                available_tools={"python3": "/usr/bin/python3"},
                memory=memory,
                artifact_dir=Path(td),
            )
            self.assertEqual(result["selected"], "reuse_existing_action")
            self.assertEqual(result["proposal"]["decision"], "action")
            self.assertEqual(result["proposal"]["action"]["name"], "extract_html_attack_surface")

    def test_writes_helper_when_no_planner_action_exists(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            memory = MemoryStore(Path(td) / "mem.sqlite", run_id="cap2")
            memory.upsert_fact("artifact.dir", td, 1.0, 0)
            memory.upsert_fact("artifact.html_file", str(Path(td) / "root.body"), 1.0, 0)
            memory.upsert_fact("target", "http://127.0.0.1:12345/", 1.0, 0)
            Path(td, "root.body").write_text("<a href='/admin'>admin</a>", encoding="utf-8")
            result = resolve_capability_gap(
                proposal={"decision": "command", "command": "python3 -c 'from bs4 import BeautifulSoup'"},
                active_action="",
                available_tools={"python3": "/usr/bin/python3"},
                memory=memory,
                artifact_dir=Path(td),
            )
            self.assertEqual(result["selected"], "write_helper_script")
            self.assertTrue(result["performed"])
            self.assertIn("html_surface_helper.py", result["proposal"]["command"])
            self.assertTrue(Path(result["artifact"]).exists())


if __name__ == "__main__":
    unittest.main()
