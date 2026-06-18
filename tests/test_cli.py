from __future__ import annotations

import json
import subprocess
import sys
import unittest

def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "cloud_egress_ip_ranges", *args],
        check=False,
        text=True,
        capture_output=True,
    )


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        result = run_cli("build", "--offline-fixtures")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_help_lists_commands_without_serve(self) -> None:
        result = run_cli("--help")
        self.assertEqual(result.returncode, 0)
        for command in ["build", "lookup", "explain", "sources", "stats"]:
            self.assertIn(command, result.stdout)
        self.assertNotIn("serve", result.stdout)

    def test_lookup_returns_json(self) -> None:
        result = run_cli("lookup", "1.1.1.1")
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertGreater(len(payload["matches"]), 0)

    def test_explain_returns_human_text(self) -> None:
        result = run_cli("explain", "1.1.1.1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("provider=cloudflare", result.stdout)
        self.assertIn("confidence=", result.stdout)
        self.assertIn("exact serverless attribution is not claimed", result.stdout)

    def test_sources_and_stats(self) -> None:
        sources = run_cli("sources")
        stats = run_cli("stats")
        self.assertEqual(sources.returncode, 0, sources.stderr)
        self.assertEqual(stats.returncode, 0, stats.stderr)
        self.assertIn("cloudflare_ips_v4", sources.stdout)
        self.assertGreaterEqual(json.loads(stats.stdout)["classified_lists"], 40)

    def test_invalid_ip_is_nonzero(self) -> None:
        result = run_cli("lookup", "not-an-ip")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid IP address", result.stderr)

    def test_missing_feed_is_nonzero(self) -> None:
        result = run_cli("stats", "--feed", "dist/missing.json")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing.json", result.stderr)


if __name__ == "__main__":
    unittest.main()
