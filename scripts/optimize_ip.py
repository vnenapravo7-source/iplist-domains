#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Literal


Kind = Literal["ip", "net"]


@dataclass
class Stats:
    total: int = 0
    unique: int = 0
    duplicates: int = 0
    invalid: int = 0
    redundant_networks: int = 0
    collapsed_networks: int = 0
    covered_ips: int = 0


@dataclass
class Entry:
    kind: Kind
    value: ipaddress._BaseAddress | ipaddress._BaseNetwork
    sources: set[str] = field(default_factory=set)


def normalize(line: str) -> str:
    return line.strip().replace("\r", "")


def is_comment(line: str) -> bool:
    return line.startswith("#")


def is_empty(line: str) -> bool:
    return line == ""


def parse_source_header(line: str) -> set[str] | None:
    """
    Supported comment formats:

      # fb-ip
      # optimized from: fb-ip, inst-ip
    """
    text = line[1:].strip()
    if not text:
        return None

    lower = text.lower()
    if lower.startswith("optimized from:"):
        payload = text.split(":", 1)[1].strip()
        if not payload:
            return set()
        return {part.strip() for part in payload.split(",") if part.strip()}

    return {text}


def entry_key(kind: Kind, value: ipaddress._BaseAddress | ipaddress._BaseNetwork) -> tuple[str, str]:
    return (kind, str(value))


def sort_key(entry: Entry) -> tuple[int, int, int, int]:
    if entry.kind == "net":
        net = entry.value
        assert isinstance(net, ipaddress._BaseNetwork)
        return (
            net.version,
            int(net.network_address),
            net.prefixlen,
            0,
        )

    ip = entry.value
    assert isinstance(ip, ipaddress._BaseAddress)
    return (
        ip.version,
        int(ip),
        0,
        1,
    )


def network_sort_key(entry: Entry) -> tuple[int, int, int]:
    net = entry.value
    assert isinstance(net, ipaddress._BaseNetwork)
    return (
        net.version,
        int(net.network_address),
        net.prefixlen,
    )


def ip_sort_key(entry: Entry) -> tuple[int, int]:
    ip = entry.value
    assert isinstance(ip, ipaddress._BaseAddress)
    return (
        ip.version,
        int(ip),
    )


def can_merge_networks(a: ipaddress._BaseNetwork, b: ipaddress._BaseNetwork) -> bool:
    if a.version != b.version:
        return False
    if a.prefixlen != b.prefixlen:
        return False
    if a.network_address > b.network_address:
        return False

    # two sibling networks only
    if a.broadcast_address + 1 != b.network_address:
        return False

    return a.supernet() == b.supernet()


def parse_file(path: Path) -> tuple[list[Entry], Stats]:
    """
    Parses a file and returns unique entries with source tracking.
    """
    stats = Stats()
    seen: dict[tuple[str, str], Entry] = {}

    current_sources = {path.stem}

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = normalize(raw)

        if is_empty(line):
            continue

        if is_comment(line):
            parsed = parse_source_header(line)
            if parsed is not None and parsed:
                current_sources = parsed
            elif parsed == set():
                current_sources = {path.stem}
            continue

        stats.total += 1

        try:
            if "/" in line:
                value = ipaddress.ip_network(line, strict=False)
                kind: Kind = "net"
            else:
                value = ipaddress.ip_address(line)
                kind = "ip"
        except ValueError:
            stats.invalid += 1
            print(f"WARNING: invalid entry: {line}")
            continue

        key = entry_key(kind, value)
        entry = seen.get(key)

        if entry is None:
            seen[key] = Entry(kind=kind, value=value, sources=set(current_sources))
        else:
            entry.sources.update(current_sources)
            stats.duplicates += 1

    entries = list(seen.values())
    stats.unique = len(entries)

    return entries, stats


def remove_redundant_networks(entries: list[Entry], stats: Stats) -> list[Entry]:
    """
    Removes networks already covered by a broader network.
    Sources are merged into the keeping network.
    """
    if len(entries) < 2:
        return entries

    ordered = sorted(entries, key=network_sort_key)
    kept: list[Entry] = []
    removed = 0

    for entry in ordered:
        net = entry.value
        assert isinstance(net, ipaddress._BaseNetwork)

        covered = False
        for existing in kept:
            existing_net = existing.value
            assert isinstance(existing_net, ipaddress._BaseNetwork)

            if net.version == existing_net.version and net.subnet_of(existing_net):
                existing.sources.update(entry.sources)
                removed += 1
                covered = True
                break

        if not covered:
            kept.append(Entry(kind="net", value=net, sources=set(entry.sources)))

    stats.redundant_networks += removed
    return kept


def collapse_networks(entries: list[Entry], stats: Stats) -> list[Entry]:
    """
    Collapses adjacent sibling networks while preserving source sets.
    """
    if len(entries) < 2:
        return entries

    ordered = sorted(entries, key=network_sort_key)
    merged: list[Entry] = []
    merges = 0

    for entry in ordered:
        net = entry.value
        assert isinstance(net, ipaddress._BaseNetwork)

        current = Entry(kind="net", value=net, sources=set(entry.sources))

        while merged:
            last = merged[-1]
            last_net = last.value
            assert isinstance(last_net, ipaddress._BaseNetwork)

            if can_merge_networks(last_net, current.value):
                supernet = last_net.supernet()
                current = Entry(
                    kind="net",
                    value=supernet,
                    sources=last.sources | current.sources,
                )
                merged.pop()
                merges += 1
                continue

            break

        merged.append(current)

    stats.collapsed_networks += merges
    return merged


def remove_ips_inside_networks(ip_entries: list[Entry], net_entries: list[Entry], stats: Stats) -> list[Entry]:
    """
    Removes IPs already covered by any existing network.
    Sources of removed IPs are merged into the covering network.
    """
    if not net_entries:
        return ip_entries

    result: list[Entry] = []

    for ip_entry in ip_entries:
        ip = ip_entry.value
        assert isinstance(ip, ipaddress._BaseAddress)

        covered_by: Entry | None = None

        for net_entry in net_entries:
            net = net_entry.value
            assert isinstance(net, ipaddress._BaseNetwork)

            if ip in net:
                covered_by = net_entry
                break

        if covered_by is None:
            result.append(Entry(kind="ip", value=ip, sources=set(ip_entry.sources)))
        else:
            covered_by.sources.update(ip_entry.sources)
            stats.covered_ips += 1

    return result


def optimize_entries(entries: list[Entry], stats: Stats) -> list[Entry]:
    networks = [entry for entry in entries if entry.kind == "net"]
    ips = [entry for entry in entries if entry.kind == "ip"]

    networks = remove_redundant_networks(networks, stats)
    networks = collapse_networks(networks, stats)
    ips = remove_ips_inside_networks(ips, networks, stats)

    return networks + ips


def group_entries(entries: list[Entry]) -> list[tuple[tuple[str, ...], list[Entry]]]:
    groups: dict[tuple[str, ...], list[Entry]] = {}

    for entry in entries:
        key = tuple(sorted(entry.sources))
        groups.setdefault(key, []).append(entry)

    ordered_groups = []
    for key in sorted(groups.keys()):
        ordered_groups.append((key, sorted(groups[key], key=sort_key)))

    return ordered_groups


def write_file(path: Path, entries: list[Entry]) -> None:
    grouped = group_entries(entries)

    out: list[str] = []

    for sources, group in grouped:
        if sources:
            out.append(f"# optimized from: {', '.join(sources)}")
        else:
            out.append("# optimized from: unknown")
        out.append("")

        for entry in group:
            out.append(str(entry.value))

        out.append("")

    path.write_text("\n".join(out), encoding="utf-8")


def print_stats(path: Path, stats: Stats, entries: list[Entry]) -> None:
    networks = sum(1 for entry in entries if entry.kind == "net")
    ips = sum(1 for entry in entries if entry.kind == "ip")

    print()
    print("=" * 60)
    print(path.name)
    print("=" * 60)
    print(f"Total entries        : {stats.total}")
    print(f"Unique entries       : {stats.unique}")
    print(f"Duplicates removed   : {stats.duplicates}")
    print(f"Invalid entries      : {stats.invalid}")
    print(f"Redundant networks   : {stats.redundant_networks}")
    print(f"Collapsed networks   : {stats.collapsed_networks}")
    print(f"IPs covered by CIDR  : {stats.covered_ips}")
    print(f"Result networks      : {networks}")
    print(f"Result IPs           : {ips}")
    print(f"Final entries        : {len(entries)}")
    print("=" * 60)
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Optimize IPv4 list with source tracking")
    parser.add_argument("file", help="Path to txt file")
    args = parser.parse_args()

    path = Path(args.file)

    if not path.exists():
        raise SystemExit(f"{path} not found")

    entries, stats = parse_file(path)
    optimized = optimize_entries(entries, stats)
    optimized = sorted(optimized, key=sort_key)

    write_file(path, optimized)
    print_stats(path, stats, optimized)


if __name__ == "__main__":
    main()
