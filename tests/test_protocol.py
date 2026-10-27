"""Exercise the actual FastMCP server through two real stdio sessions."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import verify_server


ROOT = Path(__file__).resolve().parents[1]


class ProtocolTests(unittest.TestCase):
    def test_real_stdio_workflow_with_contaminated_parent_environment(self):
        env = os.environ.copy()
        env.update({"KALI_TARGET_ALLOWLIST": "example.invalid",
                    "KALI_TARGET_DENYLIST": "fixture.invalid",
                    "ENGAGEMENT_ATTRIBUTION": "Authorization: synthetic-do-not-inherit",
                    "HTTP_SAVE_BODY_EVIDENCE": "1", "MSF_PORT": "not-a-port"})
        result = subprocess.run(
            [sys.executable, str(ROOT / "verify_server.py"), "--json", "--timeout", "90"],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        response = json.loads(result.stdout)
        self.assertTrue(response["ok"])
        self.assertGreaterEqual(response["tool_count"], len(verify_server.REQUIRED_TOOLS))
        self.assertEqual(len(response["checks"]), 4)
        self.assertEqual(response["transport"], "python-stdio")

    def test_docker_parameters_never_authorize_targets_or_enable_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            params = verify_server._server_params(Path(tmp), docker=True, image="fixture:local")
        self.assertEqual(params.command, "docker")
        self.assertEqual(params.args[params.args.index("--network") + 1], "none")
        self.assertEqual(params.args[params.args.index("--cap-drop") + 1], "ALL")
        self.assertIn("KALI_TARGET_ALLOWLIST=", params.args)
        self.assertNotIn("--cap-add=NET_RAW", params.args)
        self.assertEqual(params.args[-1], "fixture:local")

    def test_verification_failure_is_nonzero(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "verify_server.py"), "--json", "--timeout", "0.000001"],
            cwd=ROOT, capture_output=True, text=True, timeout=45,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(json.loads(result.stdout)["ok"])

    def test_checks_survive_optimized_python(self):
        result = subprocess.run(
            [sys.executable, "-O", "-c",
             "from verify_server import _require; _require(False, 'expected check failure')"],
            cwd=ROOT, capture_output=True, text=True, timeout=45,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected check failure", result.stderr)

    def test_invalid_timeout_rejected_before_startup(self):
        for value in ("0", "-1", "nan", "inf", "301"):
            with self.subTest(value=value):
                with self.assertRaises(Exception):
                    verify_server._positive_seconds(value)


if __name__ == "__main__":
    unittest.main()
