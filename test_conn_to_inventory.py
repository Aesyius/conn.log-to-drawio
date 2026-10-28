import csv
import io
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import conn_to_inventory


ROOT = Path(__file__).resolve().parent


class ValidIPTests(unittest.TestCase):
    def test_normalizes_valid_addresses(self):
        self.assertEqual(conn_to_inventory.valid_ip(" 2001:0db8::1 "), "2001:db8::1")
        self.assertEqual(conn_to_inventory.valid_ip("192.0.2.1"), "192.0.2.1")

    def test_rejects_empty_and_invalid_values(self):
        self.assertIsNone(conn_to_inventory.valid_ip(None))
        self.assertIsNone(conn_to_inventory.valid_ip("  "))
        self.assertIsNone(conn_to_inventory.valid_ip("not-an-ip"))


class ConnToInventoryTests(unittest.TestCase):
    def invoke(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", ["conn_to_inventory.py", *map(str, args)]):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as error:
                    conn_to_inventory.main()
        return error.exception.code, stdout.getvalue(), stderr.getvalue()

    def test_converts_zeek_log_deterministically_and_deduplicates_edges(self):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".log") as source:
            source.write("#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.resp_h\n")
            source.write("#types\ttime\tstring\taddr\taddr\n")
            source.write("1\ta\t192.0.2.2\t192.0.2.1\n")
            source.write("2\tb\t192.0.2.2\t192.0.2.1\n")
            source.write("3\tc\t192.0.2.1\t192.0.2.1\n")
            source.flush()

            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(sys, "argv", ["conn_to_inventory.py", source.name, "--format", "drawio"]):
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    conn_to_inventory.main()

        output = stdout.getvalue()
        self.assertIn("# label: %ip%", output)
        rows = list(csv.DictReader(io.StringIO(output.split("# layout: auto\n", 1)[1])))
        self.assertEqual(rows, [
            {"id": "n1", "ip": "192.0.2.1", "targets": ""},
            {"id": "n2", "ip": "192.0.2.2", "targets": "n1"},
        ])
        self.assertIn("Converted 2 IPs and 1 unique directed relationships.", stderr.getvalue())

    def test_ingests_conn_log_from_this_repository(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", ["conn_to_inventory.py", str(ROOT / "conn.log"), "--format", "drawio"]):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                conn_to_inventory.main()
        self.assertIn("# label: %ip%", stdout.getvalue())
        self.assertIn("id,ip,targets", stdout.getvalue())
        self.assertIn("Converted ", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
