from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from web_agent.logistics import build_logistics_request, classify_tool_family, perform_logistics_request


class LogisticsTests(unittest.TestCase):
    def test_classify_tool_family(self) -> None:
        self.assertEqual(classify_tool_family("beautifulsoup4"), "python_package")
        self.assertEqual(classify_tool_family("zsteg"), "cli_tool")
        self.assertEqual(classify_tool_family("stegsolve"), "gui_tool")

    def test_build_install_request_for_python_dependency(self) -> None:
        request = build_logistics_request(
            {
                "selected": "install_dependency",
                "gap": {"dependency": "beautifulsoup4"},
            }
        )
        self.assertEqual(request["kind"], "environment_setup")
        self.assertEqual(request["tool_family"], "python_package")
        self.assertIn("python3 -m pip install", request["command"])

    def test_build_install_request_for_gui_tool_has_no_default_command(self) -> None:
        request = build_logistics_request(
            {
                "selected": "install_dependency",
                "gap": {"tool": "stegsolve"},
            }
        )
        self.assertEqual(request["tool_family"], "gui_tool")
        self.assertEqual(request["command"], "")

    def test_perform_logistics_request_noop_without_command(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            result = perform_logistics_request(
                request={"command": ""},
                run_shell_command=lambda *args, **kwargs: {"returncode": 1, "stdout": "", "stderr": ""},
                env={},
                artifact_dir=Path(td),
                timeout=5,
            )
            self.assertFalse(result["performed"])
            self.assertEqual(result["returncode"], 0)


if __name__ == "__main__":
    unittest.main()
