#!/usr/bin/env python3
"""Convert a raw Zeek conn.log into inventory CSV for inventory_to_drawio.py.

Usage:
  python3 conn_to_inventory.py conn.log > inventory.csv
  python3 inventory_to_drawio.py inventory.csv -o network.drawio
  python3 conn_to_inventory.py conn.log | python3 inventory_to_drawio.py - -o network.drawio

Use --format drawio for draw.io's Arrange > Insert > Advanced > CSV dialog.
"""

import argparse
import csv
import ipaddress
import sys

from traffic_map import Traffic, write_connections


HEADER = """# label: %ip%
# identity: id
# namespace: passive-map-
# style: rounded=1;whiteSpace=wrap;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;
# connect: {"from":"targets","to":"id","style":"endArrow=block;endFill=1;"}
# width: 150
# height: 60
# ignore: id,targets
# nodespacing: 40
# levelspacing: 100
# layout: auto
"""


def valid_ip(value):
    """Return a normalized IP address, or None if the value isn't an IP."""
    value = (value or "").strip()
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


INVENTORY_FIELDS = ("hostname", "ip", "role", "zone", "parent", "row", "links")


def read_connections(stream, source_field="id.orig_h", destination_field="id.resp_h", metrics=None):
    """Read a Zeek TSV stream, returning unique IPs and directed relationships.

    Metadata, blank lines and truncated records are skipped. Valid endpoints
    are retained even when their peer is invalid; self-links are omitted.
    """
    nodes = set()
    edges = set()
    fields = None
    for line in stream:
        if line.startswith("#fields\t"):
            fields = line.rstrip("\r\n").split("\t")[1:]
            break
    if not fields:
        raise ValueError("Input is not a Zeek log or is missing its #fields header")
    for label, field in (("source", source_field), ("destination", destination_field)):
        if field not in fields:
            raise ValueError(f"Missing {label} field {field!r}; found {fields}")

    source_index = fields.index(source_field)
    destination_index = fields.index(destination_field)
    byte_indices = [fields.index(field) for field in ("orig_bytes", "resp_bytes") if field in fields]
    for line in stream:
        if not line.strip() or line.startswith("#"):
            continue
        values = line.rstrip("\r\n").split("\t")
        if len(values) <= max(source_index, destination_index):
            continue
        source = valid_ip(values[source_index])
        destination = valid_ip(values[destination_index])
        if source:
            nodes.add(source)
        if destination:
            nodes.add(destination)
        if source and destination and source != destination:
            edges.add((source, destination))
            if metrics is not None:
                byte_count = 0
                for index in byte_indices:
                    try:
                        byte_count += max(0, int(values[index]))
                    except (ValueError, IndexError):
                        pass
                key = source, destination
                metrics[key] = metrics.get(key, Traffic()) + Traffic(1, byte_count)
    return nodes, edges


def ip_sort_key(ip):
    address = ipaddress.ip_address(ip)
    return address.version, int(address)


def write_csv(stream, nodes, edges, output_format="inventory"):
    """Write deterministic inventory or draw.io-dialog CSV to a text stream."""
    if output_format not in ("inventory", "drawio"):
        raise ValueError(f"Unknown output format: {output_format}")
    ordered_nodes = sorted(nodes, key=ip_sort_key)
    ids = {ip: f"n{i}" for i, ip in enumerate(ordered_nodes, start=1)}
    targets = {ip: set() for ip in ordered_nodes}
    for source, destination in edges:
        targets[source].add(destination)

    writer = csv.writer(stream, lineterminator="\n")
    if output_format == "inventory":
        # A connection is not evidence of a physical parent or a device role.
        # Use IPs as names so every semicolon-separated link resolves in inventory_to_drawio.py.
        writer.writerow(INVENTORY_FIELDS)
    else:
        stream.write(HEADER)
        writer.writerow(["id", "ip", "targets"])
    for ip in ordered_nodes:
        destinations = sorted(targets[ip], key=ip_sort_key)
        if output_format == "inventory":
            writer.writerow([ip, ip, "", "", "", "", ";".join(destinations)])
        else:
            writer.writerow([ids[ip], ip, ",".join(ids[dest] for dest in destinations)])


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("Examples:\n"
                "  python3 conn_to_inventory.py conn.log --connections connections.csv > inventory.csv\n"
                "  python3 conn_to_inventory.py conn.log --format drawio > drawio-import.csv\n\n"
                "Repeated observations become one unique directed IP-pair link.\n"
                "Optional metrics retain counts and bytes for ranking/filtering; they are not diagram labels."),
    )
    parser.add_argument("input", help="Raw Zeek conn.log file")
    parser.add_argument(
        "--format", choices=("inventory", "drawio"), default="inventory",
        help="Output format (default: inventory for inventory_to_drawio.py)",
    )
    parser.add_argument("--source", default="id.orig_h", help="Source IP field")
    parser.add_argument("--destination", default="id.resp_h", help="Destination IP field")
    parser.add_argument("--connections", help="Write source,target,connections,bytes metrics CSV")
    args = parser.parse_args(argv)
    try:
        metrics = {} if args.connections else None
        with open(args.input, newline="", encoding="utf-8-sig") as stream:
            nodes, edges = read_connections(stream, args.source, args.destination, metrics)
        if args.connections:
            with open(args.connections, "w", newline="", encoding="utf-8") as stream:
                write_connections(stream, metrics)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    write_csv(sys.stdout, nodes, edges, args.format)

    print(
        f"Converted {len(nodes)} IPs and {len(edges)} unique directed "
        "relationships.",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
