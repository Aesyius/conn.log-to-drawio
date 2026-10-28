import io
import math
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from copy import deepcopy
from pathlib import Path

from conn_to_inventory import read_connections, write_csv
from inventory_to_drawio import read_inventory, render
from traffic_map import (
    Traffic, focus, group_subnets, radial_layout, read_metrics, write_connections,
)


ROOT = Path(__file__).resolve().parent


def inventory(ips, edges):
    stream = io.StringIO()
    write_csv(stream, set(ips), set(edges))
    stream.seek(0)
    return read_inventory(stream)


class TrafficTests(unittest.TestCase):
    def test_cli_help_flags(self):
        for script in ("conn_to_inventory.py", "inventory_to_drawio.py"):
            for flag in ("-h", "--help"):
                with self.subTest(script=script, flag=flag):
                    result = subprocess.run(
                        [sys.executable, str(ROOT / script), flag],
                        text=True, capture_output=True, timeout=10,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("Examples:", result.stdout)
                    self.assertIn("--connections", result.stdout)
                    self.assertIn("unique directed", result.stdout)

    def test_counts_bytes_and_metrics_roundtrip(self):
        source = io.StringIO(
            "#fields\tid.orig_h\tid.resp_h\torig_bytes\tresp_bytes\n"
            "192.0.2.1\t192.0.2.2\t100\t200\n"
            "192.0.2.1\t192.0.2.2\t-\t50\n"
            "192.0.2.2\t192.0.2.1\t25\t0\n"
            "192.0.2.1\t192.0.2.1\t10\t10\n"
            "192.0.2.3\t-\t0\t0\n"
        )
        traffic = {}
        ips, edges = read_connections(source, metrics=traffic)
        self.assertEqual(traffic, {
            ("192.0.2.1", "192.0.2.2"): Traffic(2, 350),
            ("192.0.2.2", "192.0.2.1"): Traffic(1, 25),
        })
        self.assertEqual(set(traffic), edges)
        self.assertIn("192.0.2.3", ips)
        stream = io.StringIO()
        write_connections(stream, traffic)
        stream.seek(0)
        self.assertEqual(read_metrics(stream, {ip: ip for ip in ips}), traffic)

    def test_peer_ranking_bidirectional_threshold_and_isolated_center(self):
        ips = [f"192.0.2.{i}" for i in range(1, 5)]
        a, b, c, d = ips
        traffic = {(a, b): Traffic(4, 10), (b, a): Traffic(4, 10),
                   (c, a): Traffic(7, 100), (c, d): Traffic(20, 500)}
        nodes, _ = inventory(ips, traffic)
        kept, edges, center = focus(nodes, traffic, a, top_peers=1)
        self.assertEqual(set(kept), {a, b})
        self.assertEqual(set(edges), {(a, b), (b, a)})
        kept, _, _ = focus(nodes, traffic, a, top_peers=1, rank_by="bytes")
        self.assertEqual(set(kept), {a, c})
        kept, edges, _ = focus(nodes, traffic, a, top_peers=1, min_connections=8)
        self.assertEqual(set(kept), {a})
        self.assertFalse(edges)
        self.assertEqual(center, a)
        with self.assertRaisesRegex(ValueError, "Unknown center"):
            focus(nodes, traffic, "missing")
        with self.assertRaisesRegex(ValueError, "positive"):
            focus(nodes, traffic, top_peers=0)

    def test_subnet_aggregation_conserves_internal_and_external_traffic(self):
        center, a, b, c = "10.0.0.1", "192.0.2.1", "192.0.2.2", "2001:db8::1"
        traffic = {(a, center): Traffic(3, 300), (b, center): Traffic(2, 200),
                   (a, b): Traffic(4, 400), (c, center): Traffic(1, 100)}
        nodes, _ = inventory([center, a, b, c], traffic)
        grouped, aggregated = group_subnets(nodes, traffic, center)
        self.assertEqual(set(grouped), {"10.0.0.0/24", "192.0.2.0/24", "2001:db8::/64"})
        self.assertEqual(grouped["192.0.2.0/24"]["device_count"], 2)
        self.assertEqual(aggregated["192.0.2.0/24", "10.0.0.0/24"], Traffic(5, 500))
        self.assertTrue(grouped["10.0.0.0/24"]["contains_center"])
        self.assertEqual(aggregated["192.0.2.0/24", "192.0.2.0/24"], Traffic(4, 400))
        self.assertEqual(sum(s.connections for s in aggregated.values()), 10)
        self.assertEqual(sum(s.bytes for s in aggregated.values()), 1000)
        with self.assertRaisesRegex(ValueError, "prefixes"):
            group_subnets(nodes, traffic, center, ipv4_prefix=33)

        xml, edge_count, _ = render(grouped, {name: name for name in grouped},
                                    center="10.0.0.0/24", traffic=aggregated)
        root = ET.fromstring(xml)
        all_vertices = root.findall(".//mxCell[@vertex='1']")
        vertices = [v for v in all_vertices if not v.get("id").startswith("members-")]
        lists = {v.get("id"): v for v in all_vertices if v.get("id").startswith("members-")}
        self.assertEqual(len(vertices), 3)
        self.assertEqual(len(lists), 3)
        for vertex in vertices:
            self.assertIn("verticalAlign=top", vertex.get("style"))
            self.assertIn("verticalLabelPosition=middle", vertex.get("style"))
            self.assertRegex(vertex.get("value"), r"^<b>[^<]+/\d+</b>")
            member_list = lists[f"members-{vertex.get('id')}"]
            box = vertex.find("mxGeometry")
            geometry = member_list.find("mxGeometry")
            self.assertGreater(float(geometry.get("x")), float(box.get("x")) + float(box.get("width")))
            self.assertEqual(geometry.get("y"), box.get("y"))
        member_text = " ".join(v.get("value") for v in lists.values())
        for ip in (center, a, b, c):
            self.assertIn(ip, member_text)
        edges = root.findall(".//mxCell[@edge='1']")
        self.assertEqual(edge_count, 2)
        for edge in edges:
            self.assertNotEqual(edge.get("source"), edge.get("target"))
            self.assertIn("endArrow=block", edge.get("style"))
            self.assertEqual(edge.get("value"), "")


class LayoutTests(unittest.TestCase):
    @staticmethod
    def position(node):
        return node["x"] + node["w"] / 2, node["y"] + node["h"] / 2

    def test_radial_distance_disconnected_components_and_determinism(self):
        ips = [f"192.0.2.{i}" for i in range(1, 7)]
        a, b, c, d, e, f = ips
        traffic = {(a, b): Traffic(1), (a, c): Traffic(1), (c, d): Traffic(1),
                   (e, f): Traffic(1)}
        nodes, _ = inventory(ips, traffic)
        original = deepcopy(nodes)
        radial_layout(nodes, traffic, a)
        positions = {name: self.position(node) for name, node in nodes.items()}
        self.assertEqual(len(set(positions.values())), len(nodes))
        radius = math.dist(positions[a], positions[b])
        self.assertAlmostEqual(math.dist(positions[a], positions[c]), radius)
        self.assertGreater(math.dist(positions[a], positions[d]), radius)
        self.assertGreater(math.dist(positions[a], positions[e]), radius * 2)
        reversed_nodes = dict(reversed(list(original.items())))
        radial_layout(reversed_nodes, dict(reversed(list(traffic.items()))), a)
        for name in nodes:
            self.assertEqual(self.position(reversed_nodes[name]), positions[name])

    def test_large_ring_spills_without_node_overlap(self):
        ips = [f"192.0.2.{i}" for i in range(1, 62)]
        traffic = {(ips[0], ip): Traffic(1) for ip in ips[1:]}
        nodes, _ = inventory(ips, traffic)
        radial_layout(nodes, traffic, ips[0])
        points = [self.position(node) for node in nodes.values()]
        radii = {round(math.dist(points[0], p)) for p in points[1:]}
        self.assertGreater(len(radii), 1)
        for i, point in enumerate(points):
            for other in points[i + 1:]:
                self.assertGreaterEqual(math.dist(point, other), 219)

    def test_manual_inventory_uses_tree_and_radial_unique_unlabelled_edges(self):
        nodes, alias = read_inventory(io.StringIO(
            "hostname,ip,role,parent,links\n"
            "router,192.0.2.1,router,,\n"
            "server,192.0.2.2,server,router,\n"
        ))
        render(nodes, alias)
        self.assertGreater(nodes["server"]["y"], nodes["router"]["y"])
        ips = ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
        traffic = {(ips[0], ips[1]): Traffic(100, 1000), (ips[0], ips[2]): Traffic(1, 10)}
        nodes, alias = inventory(ips, traffic)
        xml, count, _ = render(nodes, alias, traffic=traffic)
        edges = ET.fromstring(xml).findall(".//mxCell[@edge='1']")
        self.assertEqual(count, 2)
        widths = []
        for edge in edges:
            style = dict(part.split("=", 1) for part in edge.get("style").split(";") if part)
            widths.append(float(style["strokeWidth"]))
        self.assertEqual(widths, [2, 2])
        self.assertTrue(all(edge.get("value") == "" for edge in edges))
        self.assertNotIn("connections", xml)
        self.assertNotIn("bytes", xml)

    def test_repeated_observations_emit_one_edge_per_directed_pair(self):
        source = io.StringIO(
            "#fields\tid.orig_h\tid.resp_h\n"
            + "192.0.2.1\t192.0.2.2\n" * 10
            + "192.0.2.2\t192.0.2.1\n"
        )
        traffic = {}
        ips, pairs = read_connections(source, metrics=traffic)
        nodes, aliases = inventory(ips, pairs)
        xml, count, _ = render(nodes, aliases, traffic=traffic)
        edges = ET.fromstring(xml).findall(".//mxCell[@edge='1']")
        self.assertEqual(count, 2)
        self.assertEqual(len({(e.get("source"), e.get("target")) for e in edges}), 2)
        self.assertTrue(all(edge.get("value") == "" for edge in edges))

    def test_cli_metrics_filtered_and_grouped_view(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            metrics, csv_path, diagram = temp / "edges.csv", temp / "inventory.csv", temp / "map.drawio"
            result = subprocess.run(
                [sys.executable, str(ROOT / "conn_to_inventory.py"), str(ROOT / "conn.log"),
                 "--connections", str(metrics)], text=True, capture_output=True, timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            csv_path.write_text(result.stdout, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ROOT / "inventory_to_drawio.py"), str(csv_path),
                 "--connections", str(metrics), "--layout", "radial", "--top-peers", "10",
                 "--rank-by", "bytes", "--group-by", "subnet", "-o", str(diagram)],
                text=True, capture_output=True, timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Filtered out", result.stderr)
            vertices = [v for v in ET.parse(diagram).findall(".//mxCell[@vertex='1']")
                        if not v.get("id").startswith("members-")]
            self.assertGreater(len(vertices), 0)
            self.assertLessEqual(len(vertices), 11)


if __name__ == "__main__":
    unittest.main()
