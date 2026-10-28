import csv
import io
import ipaddress
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

import inventory_to_drawio
import conn_to_inventory


ROOT = Path(__file__).resolve().parent
FIELDS = ["hostname", "ip", "role", "zone", "parent", "row", "links"]


class PipelineTests(unittest.TestCase):
    def test_in_memory_pipeline(self):
        source = io.StringIO(
            "#fields\tid.orig_h\tid.resp_h\n192.0.2.1\t192.0.2.2\n"
        )
        ips, edges = conn_to_inventory.read_connections(source)
        inventory = io.StringIO()
        conn_to_inventory.write_csv(inventory, ips, edges)
        self.assertFalse(inventory.closed)
        inventory.seek(0)
        nodes, aliases = inventory_to_drawio.read_inventory(inventory)
        xml, edge_count, bands = inventory_to_drawio.render(nodes, aliases)
        self.assertEqual(ET.fromstring(xml).tag, "mxfile")
        self.assertEqual(set(nodes), {"192.0.2.1", "192.0.2.2"})
        self.assertEqual((edge_count, bands), (1, 1))

    def test_invalid_input_raises_without_exiting(self):
        with self.assertRaisesRegex(ValueError, "#fields"):
            conn_to_inventory.read_connections(io.StringIO(""))
        with self.assertRaisesRegex(ValueError, "Missing destination field"):
            conn_to_inventory.read_connections(io.StringIO("#fields\tid.orig_h\n"))
        with self.assertRaisesRegex(ValueError, "Inventory needs"):
            inventory_to_drawio.read_inventory(io.StringIO(""))

    def run_script(self, script, *args, input=None):
        result = subprocess.run(
            [sys.executable, str(ROOT / script), *map(str, args)],
            input=input, capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def assert_inventory(self, text, expected_ips, expected_edges):
        reader = csv.DictReader(io.StringIO(text))
        self.assertEqual(reader.fieldnames, FIELDS)
        rows = list(reader)
        self.assertEqual(len(rows), len(expected_ips))
        self.assertEqual({r["ip"] for r in rows}, expected_ips)
        actual_edges = set()
        for row in rows:
            self.assertEqual(row["hostname"], row["ip"])
            for field in ("role", "zone", "parent", "row"):
                self.assertEqual(row[field], "")
            targets = row["links"].split(";") if row["links"] else []
            self.assertEqual(len(targets), len(set(targets)))
            actual_edges.update((row["ip"], target) for target in targets)
        self.assertEqual(actual_edges, expected_edges)

    def assert_diagram(self, path, expected_ips, expected_edges):
        cells = ET.parse(path).findall(".//mxCell")
        vertices = {c.attrib["id"]: c.attrib["value"].removeprefix("<b>").removesuffix("</b>")
                    for c in cells if c.get("vertex") == "1"}
        self.assertEqual(set(vertices.values()), expected_ips)
        edges = [c for c in cells if c.get("edge") == "1"]
        self.assertEqual(len(edges), len(expected_edges))
        self.assertEqual(
            {(vertices[c.attrib["source"]], vertices[c.attrib["target"]]) for c in edges},
            expected_edges,
        )

    def test_full_conn_log_inventory_and_drawio_file_input(self):
        # Independent reference: read Zeek's declared fields with a TSV reader.
        ips, edges = set(), set()
        with (ROOT / "conn.log").open() as source:
            for line in source:
                if line.startswith("#fields\t"):
                    fields = line.rstrip().split("\t")[1:]
                    break
            reader = csv.DictReader(
                (line for line in source if line.strip() and not line.startswith("#")),
                fieldnames=fields, delimiter="\t", quoting=csv.QUOTE_NONE,
            )
            for row in reader:
                endpoints = []
                for field in ("id.orig_h", "id.resp_h"):
                    try:
                        address = str(ipaddress.ip_address(row[field]))
                    except ValueError:
                        address = None
                    endpoints.append(address)
                    if address:
                        ips.add(address)
                src, dst = endpoints
                if src and dst and src != dst:
                    edges.add((src, dst))
        self.assertTrue(edges)
        result = self.run_script("conn_to_inventory.py", ROOT / "conn.log")
        self.assert_inventory(result.stdout, ips, edges)
        with tempfile.TemporaryDirectory() as temp:
            inventory = Path(temp) / "inventory.csv"
            diagram = Path(temp) / "network.drawio"
            inventory.write_text(result.stdout, encoding="utf-8")
            nodes, aliases = inventory_to_drawio.load(inventory)
            self.assertEqual(set(nodes), ips)
            self.assertEqual(set(aliases), ips)
            rendered = self.run_script("inventory_to_drawio.py", inventory, "-o", diagram)
            self.assertNotIn("warning:", rendered.stdout)
            self.assert_diagram(diagram, ips, edges)

    def test_stdin_pipeline_ipv6_multiple_links_and_cycles(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "conn.log"
            diagram = Path(temp) / "network.drawio"
            source.write_text(
                "#separator \\x09\n#fields\tid.resp_h\tid.orig_h\n"
                "#types\taddr\taddr\n"
                "192.0.2.2\t192.0.2.1\n"
                "192.0.2.2\t192.0.2.1\n"
                "2001:0db8::1\t192.0.2.1\n"
                "192.0.2.1\t192.0.2.2\n"
                "192.0.2.1\t192.0.2.1\n"
                "-\t192.0.2.3\n#close\t2026-10-27\n",
                encoding="utf-8",
            )
            ips = {"192.0.2.1", "192.0.2.2", "192.0.2.3", "2001:db8::1"}
            edges = {("192.0.2.1", "192.0.2.2"), ("192.0.2.2", "192.0.2.1"),
                     ("192.0.2.1", "2001:db8::1")}
            result = self.run_script("conn_to_inventory.py", source)
            self.assert_inventory(result.stdout, ips, edges)
            self.assertEqual(result.stdout, self.run_script("conn_to_inventory.py", source).stdout)
            self.run_script("inventory_to_drawio.py", "-", "-o", diagram, input=result.stdout)
            self.assert_diagram(diagram, ips, edges)


if __name__ == "__main__":
    unittest.main()
