"""Traffic aggregation, focused views, and deterministic radial positioning."""

import csv
import ipaddress
import math
from collections import defaultdict, deque
from copy import deepcopy
from dataclasses import dataclass


@dataclass(frozen=True)
class Traffic:
    connections: int = 0
    bytes: int = 0

    def __add__(self, other):
        return Traffic(self.connections + other.connections, self.bytes + other.bytes)


CONNECTION_FIELDS = ("source", "target", "connections", "bytes")


def write_connections(stream, traffic):
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(CONNECTION_FIELDS)
    for (source, target), stats in sorted(traffic.items()):
        writer.writerow([source, target, stats.connections, stats.bytes])


def read_metrics(stream, aliases):
    reader = csv.DictReader(stream)
    if not set(CONNECTION_FIELDS).issubset(reader.fieldnames or []):
        raise ValueError("Connections CSV needs source,target,connections,bytes columns")
    traffic = {}
    for row in reader:
        source, target = aliases.get(row["source"]), aliases.get(row["target"])
        if source is None or target is None:
            raise ValueError("Connections CSV contains an endpoint absent from inventory")
        stats = Traffic(int(row["connections"]), int(row["bytes"]))
        if stats.connections < 1 or stats.bytes < 0:
            raise ValueError("Connection counts must be positive and bytes non-negative")
        key = source, target
        traffic[key] = traffic.get(key, Traffic()) + stats
    return traffic


def inventory_edges(nodes, aliases):
    """Resolve directed inventory edges; retain user-supplied link labels."""
    edges = {}
    for name, node in nodes.items():
        if node["parent"]:
            edges[node["parent"], name] = ""
        for item in filter(None, node["links"].split(";")):
            target, _, label = item.partition("|")
            target = aliases.get(target.strip())
            if target is not None and target != name:
                edges[name, target] = label.strip()
    return edges


def choose_center(nodes, traffic, rank_by="connections"):
    scores = dict.fromkeys(nodes, 0)
    for (source, target), stats in traffic.items():
        scores[source] += getattr(stats, rank_by)
        scores[target] += getattr(stats, rank_by)
    return min(nodes, key=lambda name: (-scores[name], name))


def focus(nodes, traffic, center=None, top_peers=None, min_connections=1, rank_by="connections"):
    """Filter directed edges first, then rank direct peers in both directions."""
    if not nodes:
        raise ValueError("No devices to display")
    if center is not None and center not in nodes:
        raise ValueError(f"Unknown center: {center}")
    if top_peers is not None and top_peers < 1:
        raise ValueError("--top-peers must be positive")
    if min_connections < 1:
        raise ValueError("--min-connections must be positive")
    center = center or choose_center(nodes, traffic, rank_by)
    edges = {edge: stats for edge, stats in traffic.items()
             if stats.connections >= min_connections}
    keep = set(nodes)
    if min_connections > 1:
        keep = {name for edge in edges for name in edge} | {center}
    if top_peers is not None:
        scores = defaultdict(int)
        for (source, target), stats in edges.items():
            if source == center and target != center:
                scores[target] += getattr(stats, rank_by)
            elif target == center and source != center:
                scores[source] += getattr(stats, rank_by)
        peers = sorted(scores, key=lambda name: (-scores[name], name))[:top_peers]
        keep = set(peers) | {center}
    return ({name: deepcopy(nodes[name]) for name in sorted(keep)},
            {edge: stats for edge, stats in edges.items() if set(edge) <= keep}, center)


def group_subnets(nodes, traffic, center, ipv4_prefix=24, ipv6_prefix=64):
    """Aggregate all IPs into subnets, retaining internal traffic for accounting."""
    if not 0 <= ipv4_prefix <= 32 or not 0 <= ipv6_prefix <= 128:
        raise ValueError("Subnet prefixes must be 0..32 for IPv4 and 0..128 for IPv6")
    mapping, groups = {}, defaultdict(list)
    for name, node in nodes.items():
        key = name
        try:
            address = ipaddress.ip_address(node["ip"])
        except ValueError:
            pass
        else:
            prefix = ipv4_prefix if address.version == 4 else ipv6_prefix
            key = str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))
        mapping[name] = key
        groups[key].append(name)
    grouped = {}
    for key, members in sorted(groups.items()):
        node = deepcopy(nodes[members[0]])
        node["name"] = key
        if key != members[0] or len(members) > 1:
            node.update(ip=key, display_name=key, is_subnet=True,
                        role="", zone="", w=max(220, len(key) * 10), h=100,
                        style="rounded=1;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;")
        node["device_count"] = len(members)
        node["member_ips"] = sorted(
            {nodes[name]["ip"] for name in members},
            key=lambda ip: (ipaddress.ip_address(ip).version, int(ipaddress.ip_address(ip)))
            if node.get("is_subnet") else (0, ip),
        )
        if node.get("is_subnet"):
            # Reserve space for the adjacent member list during radial placement.
            node["member_list_width"] = max(260, max(map(len, node["member_ips"])) * 8 + 30)
            node["w"] += node["member_list_width"]
            node["h"] = max(node["h"], 30 + 20 * len(node["member_ips"]))
        node["contains_center"] = center in members
        grouped[key] = node
    aggregated = {}
    for (source, target), stats in traffic.items():
        key = mapping[source], mapping[target]
        aggregated[key] = aggregated.get(key, Traffic()) + stats
    return grouped, aggregated


def radial_layout(nodes, traffic, center=None):
    """BFS rings represent communication distance, not router hops.

    Wide rings spill onto additional circles. Disconnected components occupy
    separate square tiles. Labels and node dimensions determine ring spacing.
    """
    if not nodes:
        raise ValueError("No devices to display")
    if center is not None and center not in nodes:
        raise ValueError(f"Unknown center: {center}")
    adjacency = {name: set() for name in nodes}
    for source, target in traffic:
        if source != target:
            adjacency[source].add(target)
            adjacency[target].add(source)
    spacing = max(220, max(max(n["w"], n["h"], len(n.get("display_name", name)) * 7) + 60
                           for name, n in nodes.items()))
    remaining = set(nodes)
    components = []
    roots = [center] if center else []
    # Sort once to avoid quadratic scans when many devices are isolated.
    roots.extend(sorted(nodes, key=lambda name: (-len(adjacency[name]), name)))
    for root in roots:
        if root not in remaining:
            continue
        remaining.remove(root)
        queue = deque([(root, 0)])
        levels = defaultdict(list)
        while queue:
            name, depth = queue.popleft()
            levels[depth].append(name)
            for peer in sorted(adjacency[name]):
                if peer in remaining:
                    remaining.remove(peer)
                    queue.append((peer, depth + 1))
        positions = {root: (0.0, 0.0)}
        radius = 0
        for depth in sorted(levels):
            if depth == 0:
                continue
            level = sorted(levels[depth])
            offset = 0
            while offset < len(level):
                radius += spacing
                capacity = max(1, int(math.pi / math.asin(spacing / (2 * radius))))
                ring = level[offset:offset + capacity]
                for index, name in enumerate(ring):
                    angle = 2 * math.pi * index / len(ring) - math.pi / 2
                    positions[name] = radius * math.cos(angle), radius * math.sin(angle)
                offset += capacity
        components.append((positions, radius))
    tile = 2 * max(radius for _, radius in components) + 2 * spacing
    columns = math.ceil(math.sqrt(len(components)))
    for index, (positions, _) in enumerate(components):
        cx = (index % columns + 0.5) * tile
        cy = (index // columns + 0.5) * tile
        for name, (x, y) in positions.items():
            node = nodes[name]
            node.update(x=cx + x - node["w"] / 2, y=cy + y - node["h"] / 2,
                        band=0, depth=0)
    return 1, []
