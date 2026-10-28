# zeek-to-drawio

Convert raw tab-separated Zeek connection logs into an inventory CSV and a draw.io network diagram. Requires Python 3; uses only the standard library.

## Run

Both command-line parts support `-h` and `--help`, including examples:

```bash
python3 conn_to_inventory.py --help
python3 inventory_to_drawio.py --help
```

```bash
python3 conn_to_inventory.py conn.log > inventory.csv
python3 inventory_to_drawio.py inventory.csv -o network.drawio
```

Or pipe the inventory directly:

```bash
python3 conn_to_inventory.py conn.log | python3 inventory_to_drawio.py - -o network.drawio
```

Open `network.drawio` in draw.io. Inventory columns are `hostname,ip,role,zone,parent,row,links`. IPs become hostnames, and unique observed connections become semicolon-separated links. Roles, zones and physical parents are left blank: connection logs do not establish them. You can enrich the inventory manually; see `python3 inventory_to_drawio.py --help` for supported roles and link labels. Host links are drawn without arrows; subnet links have directional arrows.

The converter locates `id.orig_h` and `id.resp_h` using the log's `#fields` header. Override these with `--source` and `--destination`. It normalizes IPv4/IPv6 addresses, deduplicates connections, omits self-links, and emits stable numeric-IP ordering.

For draw.io's **Arrange → Insert → Advanced → CSV** dialog instead, use:

```bash
python3 conn_to_inventory.py conn.log --format drawio > drawio-import.csv
```

This alternative output is not inventory input for `inventory_to_drawio.py`.

## Radial maps and focused views

The default `--layout auto` uses radial layout when no device has a physical
parent, and tree layout otherwise. Radial layout centers the most active device
and arranges connected peers in rings. Disconnected components are placed in
separate tiles; large rings spill onto additional circles to avoid crowding.
Rings describe communication relationships, **not traceroute hops**. Radial
views do not draw the tree layout's zone boxes.

Generate inventory and traffic metrics from the same log:

```bash
python3 conn_to_inventory.py conn.log --connections connections.csv > inventory.csv
```

Start with the 50 busiest direct peers of the automatically chosen center:

```bash
python3 inventory_to_drawio.py inventory.csv --connections connections.csv \
  --layout radial --top-peers 50 -o radial.drawio
```

Choose a specific center by adding `--center <IP-or-hostname>`. Without
`--top-peers`, all devices remain visible, including disconnected components.
The center is chosen before filtering. Peer ranking sums incoming and outgoing
counts with deterministic name-based tie breaking. Links between selected peers
are retained too. To rank by bytes and suppress low-count directed pairs:

```bash
python3 inventory_to_drawio.py inventory.csv --connections connections.csv \
  --layout radial --top-peers 50 --rank-by bytes --min-connections 5 \
  -o busiest.drawio
```

Collapse peers into subnets for an overview:

```bash
python3 inventory_to_drawio.py inventory.csv --connections connections.csv \
  --layout radial --group-by subnet -o subnets.drawio
```

- Subnets default to IPv4 `/24` and IPv6 `/64`; change these using
  `--ipv4-prefix` and `--ipv6-prefix`. The center host is grouped too, and its
  subnet becomes the center of the view.
- Each subnet is a large box with its CIDR at the top and device count beneath.
  Its member IP addresses are listed beside the box in numeric order. When
  filtering is enabled, the list contains only the hosts retained in the view.
  One arrow is drawn per unique directed subnet pair. Internal traffic is
  retained for accounting but is not drawn as a self-loop.
- Filtering happens **before** grouping: minimum directed-pair count, then
  top direct peers, then subnet aggregation. Exclusions are reported on stderr.
- `connections.csv` contains `source,target,connections,bytes`. Counts represent
  Zeek records per directed IP pair; bytes sum `orig_bytes` and `resp_bytes`.
  Missing/unset byte fields count as zero. Invalid endpoints and self-links are
  excluded, just as in the inventory. Use metrics from the same conversion;
  mismatched endpoints or directed links are rejected.
- Edges have uniform thickness and no generated count/byte labels. Each unique
  directed IP pair produces one edge, regardless of how many log records it has;
  reverse-direction traffic remains a separate edge. Metrics are used only for
  ranking and filtering. Without metrics, each unique inventory
  relationship has weight one; byte ranking and minimum-count filtering require
  `--connections`.
- `--layout tree` retains the original physical-parent layout. Traffic metrics,
  centering, filtering and grouping require radial layout.

## Examples for every flag

### Log converter: `conn_to_inventory.py`

```bash
# -h / --help: show usage and examples (either spelling works).
python3 conn_to_inventory.py -h
python3 conn_to_inventory.py --help

# --format inventory: explicitly select inventory output (the default).
python3 conn_to_inventory.py conn.log --format inventory > inventory.csv

# --format drawio: produce input for draw.io's CSV import dialog instead.
python3 conn_to_inventory.py conn.log --format drawio > drawio-import.csv

# --source / --destination: choose endpoint fields declared in #fields.
# This example reverses the normal originator-to-responder direction.
python3 conn_to_inventory.py conn.log --source id.resp_h --destination id.orig_h > reversed.csv

# --connections: save metrics alongside the inventory written to stdout.
python3 conn_to_inventory.py conn.log --connections connections.csv > inventory.csv
```

### Diagram renderer: `inventory_to_drawio.py`

The following examples use `inventory.csv` and `connections.csv` generated by
the last command above. Replace `192.0.2.1` with an IP or hostname actually in
your inventory. `enriched.csv` means an inventory you have manually populated
with physical `parent` relationships.

```bash
# -h / --help: show usage and examples.
python3 inventory_to_drawio.py -h
python3 inventory_to_drawio.py --help

# -o / --output: choose the output file (either spelling works).
python3 inventory_to_drawio.py inventory.csv -o network.drawio
python3 inventory_to_drawio.py inventory.csv --output network.drawio

# --layout auto: choose radial or tree based on the inventory (the default).
python3 inventory_to_drawio.py inventory.csv --layout auto -o automatic.drawio

# --layout radial: arrange communication peers in rings.
python3 inventory_to_drawio.py inventory.csv --layout radial -o radial.drawio

# --layout tree: use physical parent relationships for layered placement.
python3 inventory_to_drawio.py enriched.csv --layout tree -o tree.drawio

# --center: choose the central host explicitly.
python3 inventory_to_drawio.py inventory.csv --layout radial --center 192.0.2.1 -o centered.drawio

# --connections: use observed counts for automatic center/peer ranking.
python3 inventory_to_drawio.py inventory.csv --layout radial --connections connections.csv -o traffic.drawio

# --top-peers: retain the center and its 50 highest-ranked direct peers.
python3 inventory_to_drawio.py inventory.csv --layout radial --connections connections.csv --top-peers 50 -o peers.drawio

# --min-connections: retain directed pairs with at least five observations.
python3 inventory_to_drawio.py inventory.csv --layout radial --connections connections.csv --min-connections 5 -o filtered.drawio

# --rank-by connections: rank by observation count (the default with metrics).
python3 inventory_to_drawio.py inventory.csv --layout radial --connections connections.csv --rank-by connections --top-peers 50 -o by-count.drawio

# --rank-by bytes: rank by total observed bytes instead.
python3 inventory_to_drawio.py inventory.csv --layout radial --connections connections.csv --rank-by bytes --top-peers 50 -o by-bytes.drawio

# --group-by subnet: draw CIDR boxes, member IP lists and inter-subnet arrows.
python3 inventory_to_drawio.py inventory.csv --layout radial --group-by subnet -o subnets.drawio

# --ipv4-prefix: aggregate IPv4 hosts into /16 rather than default /24 groups.
python3 inventory_to_drawio.py inventory.csv --layout radial --group-by subnet --ipv4-prefix 16 -o ipv4-subnets.drawio

# --ipv6-prefix: aggregate IPv6 hosts into /48 rather than default /64 groups.
python3 inventory_to_drawio.py inventory.csv --layout radial --group-by subnet --ipv6-prefix 48 -o ipv6-subnets.drawio

# Positional '-' reads inventory from stdin instead of a file.
python3 conn_to_inventory.py conn.log | python3 inventory_to_drawio.py - -o network.drawio
```

## Development

```bash
python3 -m unittest discover -v
```

The integration suite uses the local `conn.log`, checks every endpoint and relationship through CSV and XML, and writes generated files to temporary directories. Layout tests also verify ring spacing, disconnected components, deterministic positions, weighted filtering and conservation of subnet traffic totals.

Reusable functions live alongside the CLI entrypoints: `read_connections()` and `write_csv()` handle text streams; `read_inventory()` resolves inventory nodes and aliases; `render()` lays out nodes in place and returns XML plus edge and layer counts. Both `main(argv=None)` functions accept explicit argument lists.

`traffic_map.py` owns traffic metrics, focused views, subnet aggregation and radial
geometry. Pass a dictionary as `metrics=` to `read_connections()` to collect
`Traffic` values without changing its `(nodes, edges)` return value. `focus()`
copies selected nodes; `radial_layout()` mutates their coordinates in place.
