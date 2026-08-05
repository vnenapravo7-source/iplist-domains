#!/usr/bin/env python3

import argparse
import ipaddress
from pathlib import Path


class Stats:
    def __init__(self):
        self.total = 0
        self.unique = 0
        self.duplicates = 0
        self.covered = 0
        self.collapsed = 0


def normalize(line: str) -> str:
    return line.strip().replace("\r", "")


def is_comment(line: str) -> bool:
    return line.startswith("#")


def is_empty(line: str) -> bool:
    return line == ""


def parse_file(path: Path):
    """
    Возвращает:
        comments
        ips
        networks
        stats
    """

    comments = []
    ips = []
    networks = []

    stats = Stats()

    seen = set()

    for raw in path.read_text(encoding="utf-8").splitlines():

        line = normalize(raw)

        if is_empty(line):
            continue

        if is_comment(line):
            comments.append(line)
            continue

        stats.total += 1

        if line in seen:
            stats.duplicates += 1
            continue

        seen.add(line)

        try:
            if "/" in line:
                networks.append(
                    ipaddress.ip_network(
                        line,
                        strict=False,
                    )
                )
            else:
                ips.append(
                    ipaddress.ip_address(line)
                )

        except ValueError:
            print(f"WARNING: invalid entry: {line}")

    stats.unique = len(seen)

    return comments, ips, networks, stats


def write_file(path: Path, comments, networks, ips):

    out = []

    if comments:
        out.extend(comments)
        out.append("")

    for net in networks:
        out.append(str(net))

    for ip in ips:
        out.append(str(ip))

    out.append("")

    path.write_text(
        "\n".join(out),
        encoding="utf-8",
    )

def remove_ips_inside_networks(ips, networks, stats):
    """
    Удаляет IP, которые уже покрываются существующими CIDR.
    """

    if not networks:
        return ips

    result = []

    for ip in ips:
        covered = False

        for net in networks:
            if ip in net:
                covered = True
                stats.covered += 1
                break

        if not covered:
            result.append(ip)

    return result


def remove_redundant_networks(networks, stats):
    """
    Удаляет сети, полностью входящие в более крупные сети.
    """

    if len(networks) < 2:
        return networks

    ordered = sorted(
        networks,
        key=lambda n: (
            int(n.network_address),
            n.prefixlen,
        ),
    )

    result = []

    removed = 0

    for net in ordered:

        covered = False

        for existing in result:

            if (
                net.version == existing.version
                and net.subnet_of(existing)
            ):
                covered = True
                removed += 1
                break

        if not covered:
            result.append(net)

    stats.collapsed += removed

    return result


def collapse_networks(networks, stats):
    """
    Объединяет соседние сети.
    """

    before = len(networks)

    collapsed = list(
        ipaddress.collapse_addresses(networks)
    )

    stats.collapsed += before - len(collapsed)

    return collapsed


def sort_networks(networks):

    return sorted(
        networks,
        key=lambda n: (
            int(n.network_address),
            n.prefixlen,
            n.version,
        ),
    )


def sort_ips(ips):

    return sorted(
        ips,
        key=lambda ip: (
            int(ip),
            ip.version,
        ),
    )


def optimize(comments, ips, networks, stats):

    networks = remove_redundant_networks(
        networks,
        stats,
    )

    networks = collapse_networks(
        networks,
        stats,
    )

    ips = remove_ips_inside_networks(
        ips,
        networks,
        stats,
    )

    networks = sort_networks(networks)

    ips = sort_ips(ips)

    return comments, ips, networks

def print_stats(path: Path, stats, networks, ips):

    print()
    print("=" * 60)
    print(path.name)
    print("=" * 60)
    print(f"Total entries      : {stats.total}")
    print(f"Unique entries     : {stats.unique}")
    print(f"Duplicates removed : {stats.duplicates}")
    print(f"IPs covered by CIDR: {stats.covered}")
    print(f"CIDR merged        : {stats.collapsed}")
    print(f"Result networks    : {len(networks)}")
    print(f"Result IPs         : {len(ips)}")
    print(f"Final entries      : {len(networks) + len(ips)}")
    print("=" * 60)
    print()


def main():

    parser = argparse.ArgumentParser(
        description="Optimize IPv4 list"
    )

    parser.add_argument(
        "file",
        help="Path to txt file",
    )

    args = parser.parse_args()

    path = Path(args.file)

    if not path.exists():
        raise SystemExit(f"{path} not found")

    comments, ips, networks, stats = parse_file(path)

    comments, ips, networks = optimize(
        comments,
        ips,
        networks,
        stats,
    )

    write_file(
        path,
        comments,
        networks,
        ips,
    )

    print_stats(
        path,
        stats,
        networks,
        ips,
    )


if __name__ == "__main__":
    main()
