#!/usr/bin/env python3
"""
Build a network map (.drawio) from an inventory CSV. Generated inventories use
radial communication rings; inventories with physical parents use a tree.

Usage:
    python3 inventory_to_drawio.py inventory.csv -o network_map.drawio
    python3 conn_to_inventory.py conn.log | python3 inventory_to_drawio.py - -o network_map.drawio

Then in draw.io (app.diagrams.net or desktop): File > Open from > Device,
or just drag the .drawio file onto the draw.io window.

Inventory columns:
    hostname   name shown on the map (and used by parent/links to refer to it)
    ip         IP shown under the name
    role       cloud, router, core_switch, switch, firewall, workstation,
               server, edge, plc   (anything else gets a generic box)
    zone       zone box to draw around it, e.g. "IT Network", "OT Network"
               (leave blank for the cloud and firewalls)
    parent     hostname (or IP) of the device it plugs into
    row        optional: force the device onto a lower row in its zone
    links      optional extra connections, ';'-separated, each "hostname" or
               "hostname|label", e.g. "wan-sw01.ot.acme.test|WAN"

Everything below a firewall is placed in the next zone down.
"""
import argparse
import csv
import sys
from collections import Counter, defaultdict
from contextlib import nullcontext
from xml.sax.saxutils import escape, quoteattr

from traffic_map import (
    Traffic, choose_center, focus, group_subnets, inventory_edges,
    radial_layout, read_metrics,
)

NET = ("html=1;outlineConnect=0;fillColor=#CCCCCC;strokeColor=#6881B3;gradientColor=none;"
       "gradientDirection=north;strokeWidth=2;shape=mxgraph.networks.")
ROLES = {  # role: (style, width, height)
    "cloud":       (NET + "cloud;", 90, 50),
    "router":      ("strokeColor=#ffffff;html=1;pointerEvents=1;dashed=0;fillColor=#036897;"
                    "strokeWidth=2;outlineConnect=0;shape=mxgraph.cisco.routers.router;", 62, 42),
    "core_switch": (NET + "switch;", 100, 30),
    "switch":      (NET + "hub;", 100, 30),
    "firewall":    (NET + "firewall;", 55, 55),
    "workstation": (NET + "pc;", 52, 36),
    "server":      (NET + "server;", 36, 50),
    "edge":        (NET + "desktop_pc;", 30, 60),
    "plc":         (NET + "supercomputer;", 42, 46),
}
DEFAULT_ROLE = ("rounded=1;html=1;fillColor=#f5f5f5;strokeColor=#666666;", 60, 40)
LABEL = ("verticalLabelPosition=bottom;verticalAlign=top;labelPosition=center;align=center;"
         "fontSize=10;fontColor=#333333;whiteSpace=nowrap;")
ZONE_COLORS = [("#FFFDF5", "#D6B656"), ("#F7FAFF", "#6C8EBF"), ("#F7FFF7", "#82B366"), ("#FFF7F7", "#B85450")]
LINK = "shape=link;edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;strokeColor=#333333;endArrow=none;"
TREE_LINK = LINK + "exitX=0.5;exitY=1;exitDx=0;exitDy=0;entryX=0.5;entryY=0;entryDx=0;entryDy=0;"

SLOT = 170        # horizontal space per leaf device (fits a hostname label)
LABEL_H = 34      # space under an icon for the two label lines
ROW_GAP = 45      # vertical gap between rows
MARGIN = 40


def load(path):
    source = nullcontext(sys.stdin) if path == "-" else open(path, newline="", encoding="utf-8-sig")
    with source as f:
        return read_inventory(f)


def read_inventory(stream):
    """Read inventory from a text stream and resolve parent and IP aliases."""
    rows = [{(k or "").strip().lower(): (v or "").strip() for k, v in r.items()} for r in csv.DictReader(stream)]
    if not rows or "hostname" not in rows[0]:
        raise ValueError("Inventory needs at least hostname, ip, role and parent columns.")
    nodes, alias = {}, {}
    for i, r in enumerate(rows):
        name = r["hostname"] or r.get("ip", "")
        if not name or name in nodes:
            continue
        style, w, h = ROLES.get(r.get("role", "").lower(), DEFAULT_ROLE)
        nodes[name] = dict(name=name, ip=r.get("ip", ""), role=r.get("role", "").lower(),
                           zone=r.get("zone", ""), parent=r.get("parent", ""),
                           row=int(r["row"]) if r.get("row", "").isdigit() else None,
                           links=r.get("links", ""), style=style, w=w, h=h,
                           id=f"n{i}", children=[])
        alias[name] = name
        if r.get("ip"):
            alias.setdefault(r["ip"], name)
    for n in nodes.values():
        p = alias.get(n["parent"])
        if n["parent"] and not p:
            print(f"warning: parent '{n['parent']}' of {n['name']} not found, treating as top level")
        n["parent"] = p if p != n["name"] else None
        if n["parent"]:
            nodes[n["parent"]]["children"].append(n["name"])
    return nodes, alias


def layout(nodes):
    roots = [n for n in nodes.values() if not n["parent"]]
    if not roots:
        raise ValueError("No top-level device found (one row needs an empty parent).")

    # band = zone layer (increments below each firewall); depth = row within the band
    def assign(n, band, depth):
        n["band"], n["depth"] = band, (n["row"] if n["row"] is not None else depth)
        for c in n["children"]:
            if n["role"] == "firewall":
                assign(nodes[c], band + 1, 0)
            else:
                assign(nodes[c], band, depth + 1)
    for r in roots:
        assign(r, 0, 0)

    # horizontal: tidy tree, firewalls are leaves in their band; their subtree is its own forest
    def width(n):
        kids = [] if n["role"] == "firewall" else n["children"]
        n["sw"] = max(SLOT, sum(width(nodes[c]) for c in kids))
        return n["sw"]

    def place(n, left):
        kids = [] if n["role"] == "firewall" else n["children"]
        if kids:
            x = left + (n["sw"] - sum(nodes[c]["sw"] for c in kids)) / 2
            for c in kids:
                place(nodes[c], x)
                x += nodes[c]["sw"]
            n["cx"] = (nodes[kids[0]]["cx"] + nodes[kids[-1]]["cx"]) / 2
        else:
            n["cx"] = left + n["sw"] / 2

    def place_forest(rts, center):
        total = sum(width(r) for r in rts)
        x = center - total / 2
        for r in rts:
            place(r, x)
            x += r["sw"]
        for r in rts:  # recurse into firewall subtrees below this forest
            for f in walk(r):
                if f["role"] == "firewall" and f["children"]:
                    place_forest([nodes[c] for c in f["children"]], f["cx"])

    def walk(n):
        yield n
        if n["role"] != "firewall":
            for c in n["children"]:
                yield from walk(nodes[c])

    place_forest(roots, 0)

    # vertical: rows per band, firewalls sit on the line between bands
    bands = max(n["band"] for n in nodes.values()) + 1
    y = MARGIN
    boundaries = []
    for b in range(bands):
        members = [n for n in nodes.values() if n["band"] == b and n["role"] != "firewall"]
        rowh = defaultdict(int)
        for n in members:
            rowh[n["depth"]] = max(rowh[n["depth"]], n["h"])
        tops = {}
        for d in sorted(rowh):
            tops[d] = y
            y += rowh[d] + LABEL_H + ROW_GAP
        for n in members:
            n["y"] = tops[n["depth"]] + rowh[n["depth"]] - n["h"]  # bottom-align icons in a row
        fws = [n for n in nodes.values() if n["band"] == b and n["role"] == "firewall"]
        if fws:
            fh = max(f["h"] for f in fws)
            boundary = y + fh / 2
            for f in fws:
                f["y"] = boundary - f["h"] / 2
            boundaries.append(boundary)
            y = boundary + fh / 2 + LABEL_H + ROW_GAP

    for n in nodes.values():
        n["x"] = n["cx"] - n["w"] / 2
    shift = MARGIN + SLOT / 2 - min(n["x"] for n in nodes.values())
    for n in nodes.values():
        n["x"] += shift
    return bands, boundaries


def zones(nodes, bands, boundaries):
    zoned = [n for n in nodes.values() if n["zone"]]
    if not zoned:
        return []
    left = min(n["x"] for n in zoned) - 40
    right = max(n["x"] + n["w"] for n in zoned) + 40
    out = []
    for b in range(bands):
        members = [n for n in zoned if n["band"] == b]
        if not members:
            continue
        name = Counter(n["zone"] for n in members).most_common(1)[0][0]
        top = boundaries[b - 1] if b > 0 and b - 1 < len(boundaries) else min(n["y"] for n in members) - 45
        bottom = boundaries[b] if b < len(boundaries) else max(n["y"] + n["h"] for n in members) + LABEL_H + 30
        fill, stroke = ZONE_COLORS[b % len(ZONE_COLORS)]
        out.append((f"z{b}", name, left, top, right - left, bottom - top, fill, stroke))
    return out


def cell_vertex(cid, value, style, x, y, w, h):
    return (f'<mxCell id="{cid}" value={quoteattr(value)} style={quoteattr(style)} vertex="1" parent="1">'
            f'<mxGeometry x="{x:.0f}" y="{y:.0f}" width="{w:.0f}" height="{h:.0f}" as="geometry"/></mxCell>')


def cell_edge(cid, src, dst, style, value=""):
    return (f'<mxCell id="{cid}" value={quoteattr(value)} style={quoteattr(style)} edge="1" parent="1" '
            f'source="{src}" target="{dst}"><mxGeometry relative="1" as="geometry"/></mxCell>')


def render(nodes, alias, layout_mode="auto", center=None, traffic=None, rank_by="connections"):
    """Lay out nodes in place and return (draw.io XML, edge count, band count)."""
    if layout_mode == "auto":
        layout_mode = "tree" if any(n["parent"] for n in nodes.values()) else "radial"
    if not nodes:
        raise ValueError("No devices to display")
    if layout_mode not in ("tree", "radial"):
        raise ValueError(f"Unknown layout: {layout_mode}")
    labels = inventory_edges(nodes, alias)
    if traffic is None:
        traffic = {edge: Traffic(1) for edge in labels}
    if layout_mode == "radial":
        center = center or choose_center(nodes, traffic, rank_by)
        bands, boundaries = radial_layout(nodes, traffic, center)
        zone_boxes = []
    else:
        bands, boundaries = layout(nodes)
        zone_boxes = zones(nodes, bands, boundaries)

    cells = ['<mxCell id="0"/>', '<mxCell id="1" parent="0"/>']
    for zid, name, x, y, w, h, fill, stroke in zone_boxes:
        cells.append(cell_vertex(zid, name, f"rounded=0;html=1;fillColor={fill};strokeColor={stroke};"
                                 "verticalAlign=top;align=left;spacingLeft=10;spacingTop=6;"
                                 "fontStyle=1;fontSize=12;container=0;", x, y, w, h))
    for n in nodes.values():
        if n.get("is_subnet"):
            label = f"<b>{escape(n['ip'])}</b><br><br>{n['device_count']} devices"
            label_style = ("verticalLabelPosition=middle;verticalAlign=top;labelPosition=center;"
                           "align=center;spacingTop=12;fontSize=16;whiteSpace=wrap;")
            list_width = n["member_list_width"]
            box_width = n["w"] - list_width
            cells.append(cell_vertex(n["id"], label, n["style"] + label_style,
                                     n["x"], n["y"], box_width, n["h"]))
            members = "<b>IP addresses</b><br>" + "<br>".join(
                escape(ip) for ip in n["member_ips"]
            )
            cells.append(cell_vertex(
                f"members-{n['id']}", members,
                "text;html=1;strokeColor=none;fillColor=none;align=left;verticalAlign=top;"
                "whiteSpace=wrap;fontSize=12;spacingTop=8;",
                n["x"] + box_width + 15, n["y"], list_width - 15, n["h"],
            ))
            continue
        else:
            name = n.get("display_name", n["name"])
            label = f"<b>{escape(name)}</b>"
            if n["ip"] and n["ip"] != name:
                label += f"<br>{escape(n['ip'])}"
            label_style = LABEL
        cells.append(cell_vertex(n["id"], label, n["style"] + label_style,
                                 n["x"], n["y"], n["w"], n["h"]))
    e = 0
    if layout_mode == "radial":
        for source, target in sorted(traffic):
            if source == target:
                continue
            e += 1
            label = labels.get((source, target), "")
            arrow = "block" if nodes[source].get("is_subnet") or nodes[target].get("is_subnet") else "none"
            cells.append(cell_edge(
                f"e{e}", nodes[source]["id"], nodes[target]["id"],
                f"html=1;rounded=1;endArrow={arrow};endFill=1;strokeColor=#6881B3;strokeWidth=2;"
                "fontSize=10;labelBackgroundColor=#ffffff;", label,
            ))
    for n in nodes.values() if layout_mode == "tree" else []:
        if n["parent"]:
            e += 1
            cells.append(cell_edge(f"e{e}", nodes[n["parent"]]["id"], n["id"], TREE_LINK))
    for n in nodes.values() if layout_mode == "tree" else []:
        for item in filter(None, (s.strip() for s in n["links"].split(";"))):
            target, _, text = item.partition("|")
            t = alias.get(target.strip())
            if not t:
                print(f"warning: link target '{target}' from {n['name']} not found")
                continue
            e += 1
            cells.append(cell_edge(f"e{e}", n["id"], nodes[t]["id"],
                                   LINK + "fontSize=10;labelBackgroundColor=#ffffff;", text.strip()))

    xml = ('<mxfile host="app.diagrams.net"><diagram name="Network map" id="netmap">'
           '<mxGraphModel grid="1" gridSize="10" page="0" math="0" shadow="0"><root>'
            + "".join(cells) + "</root></mxGraphModel></diagram></mxfile>")
    return xml, e, bands


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("Examples:\n"
                "  python3 inventory_to_drawio.py inventory.csv --layout radial --top-peers 50 -o radial.drawio\n"
                "  python3 inventory_to_drawio.py inventory.csv --group-by subnet -o subnets.drawio\n"
                "  python3 inventory_to_drawio.py inventory.csv --connections connections.csv "
                "--rank-by bytes --top-peers 50 -o busiest.drawio\n\n"
                "Edges represent unique directed pairs, without count/byte labels.\n"
                "Subnet boxes show CIDRs at the top, with arrows between subnets.\n"
                "Metrics affect ranking/filtering only. Radial rings are communication relationships, not router hops."),
    )
    ap.add_argument("inventory", help="Inventory CSV path, or - to read standard input")
    ap.add_argument("-o", "--output", default="network_map.drawio")
    ap.add_argument("--layout", choices=("auto", "tree", "radial"), default="auto",
                    help="auto: tree for inventories with parents, otherwise radial")
    ap.add_argument("--center", help="Central hostname or IP (default: most active device)")
    ap.add_argument("--connections", help="Traffic metrics CSV from conn_to_inventory.py")
    ap.add_argument("--top-peers", type=int, help="Show the center and its N highest-ranked direct peers")
    ap.add_argument("--min-connections", type=int, default=1, help="Minimum count per directed pair")
    ap.add_argument("--rank-by", choices=("connections", "bytes"), default="connections")
    ap.add_argument("--group-by", choices=("subnet",), help="Group all hosts into CIDR boxes with inter-subnet arrows")
    ap.add_argument("--ipv4-prefix", type=int, default=24, help="IPv4 subnet prefix length (default: 24)")
    ap.add_argument("--ipv6-prefix", type=int, default=64, help="IPv6 subnet prefix length (default: 64)")
    args = ap.parse_args(argv)
    try:
        nodes, alias = load(args.inventory)
        mode = args.layout
        if mode == "auto":
            mode = "tree" if any(n["parent"] for n in nodes.values()) else "radial"
        view_options = args.center or args.top_peers is not None or args.group_by or args.min_connections != 1
        if mode == "tree" and (view_options or args.connections or args.rank_by != "connections"):
            raise ValueError("Traffic metrics and focused views require --layout radial")
        if not args.connections and (args.min_connections != 1 or args.rank_by == "bytes"):
            raise ValueError("--min-connections and byte ranking require --connections")
        labels = inventory_edges(nodes, alias)
        traffic = {edge: Traffic(1) for edge in labels}
        if args.connections:
            with open(args.connections, newline="", encoding="utf-8-sig") as stream:
                traffic = read_metrics(stream, alias)
            if set(traffic) != set(labels):
                raise ValueError("Connections CSV must describe exactly the inventory's directed links")
        center = None
        if args.center:
            center = alias.get(args.center)
            if center is None:
                raise ValueError(f"Unknown center: {args.center}")
        if mode == "radial":
            original_nodes, original_edges = len(nodes), len(traffic)
            original_count = sum(stats.connections for stats in traffic.values())
            nodes, traffic, center = focus(nodes, traffic, center, args.top_peers,
                                           args.min_connections, args.rank_by)
            excluded_count = original_count - sum(stats.connections for stats in traffic.values())
            print(f"Filtered out {original_nodes - len(nodes)} devices, "
                  f"{original_edges - len(traffic)} relationships, {excluded_count} connections.",
                  file=sys.stderr)
            if args.group_by:
                nodes, traffic = group_subnets(nodes, traffic, center,
                                               args.ipv4_prefix, args.ipv6_prefix)
                center = next(name for name, node in nodes.items() if node["contains_center"])
                alias = {name: name for name in nodes}
                for i, node in enumerate(nodes.values()):
                    node.update(id=f"n{i}", parent=None, children=[], links="")
            else:
                alias = {key: name for key, name in alias.items() if name in nodes}
            print(f"Radial center: {center}; displaying {len(nodes)} nodes.", file=sys.stderr)
        xml, e, bands = render(nodes, alias, mode, center,
                               traffic if mode == "radial" else None, args.rank_by)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(xml)
    except (OSError, ValueError) as error:
        ap.error(str(error))
    print(f"{len(nodes)} devices, {e} links, {bands} zone layer(s) -> {args.output}")
    print("Open it in draw.io: File > Open from > Device (or drag the file onto the draw.io window).")


if __name__ == "__main__":
    main()
