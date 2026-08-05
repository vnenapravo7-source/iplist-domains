#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Stats:
    total: int = 0
    unique: int = 0
    duplicates: int = 0
    invalid: int = 0
    covered: int = 0


@dataclass
class Entry:
    domain: str
    sources: set[str] = field(default_factory=set)


def normalize(line: str) -> str:
    return line.strip().replace("\r", "")


def is_empty(line: str) -> bool:
    return line == ""


def is_comment(line: str) -> bool:
    return line.startswith("#")


def parse_source_header(line: str) -> set[str] | None:
    """
    Supported comment formats:

      # fb-domains
      # optimized from: fb-domains, inst-domains
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


def normalize_domain(raw: str) -> str | None:
    """
    Normalizes a domain name.

    Rules:
    - lower-case
    - strip trailing dot
    - treat '*.example.com' as 'example.com'
    """
    text = raw.strip().lower().rstrip(".")
    if not text:
        return None

    if text.startswith("*."):
        text = text[2:]

    if " " in text or "/" in text:
        return None

    if text.startswith(".") or text.endswith("."):
        return None

    # basic sanity check
    if "." not in text:
        return None

    return text


def is_subdomain(child: str, parent: str) -> bool:
    return child == parent or child.endswith("." + parent)


def sort_key(entry: Entry) -> tuple[int, int, str]:
    return (
        entry.domain.count("."),
        len(entry.domain),
        entry.domain,
    )


def parse_file(path: Path) -> tuple[list[Entry], Stats]:
    stats = Stats()
    seen: dict[str, Entry] = {}

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

        domain = normalize_domain(line)
        if domain is None:
            stats.invalid += 1
            print(f"WARNING: invalid entry: {line}")
            continue

        entry = seen.get(domain)
        if entry is None:
            seen[domain] = Entry(domain=domain, sources=set(current_sources))
        else:
            entry.sources.update(current_sources)
            stats.duplicates += 1

    entries = list(seen.values())
    stats.unique = len(entries)
    return entries, stats


def remove_covered_domains(entries: list[Entry], stats: Stats) -> list[Entry]:
    """
    Keeps a parent domain and removes any subdomain below it.

    Example:
      google.com
      mail.google.com
      a.b.google.com

    Result:
      google.com
    """
    if len(entries) < 2:
        return entries

    ordered = sorted(entries, key=sort_key)
    kept: list[Entry] = []

    for entry in ordered:
        covered_by = None
        for existing in kept:
            if is_subdomain(entry.domain, existing.domain):
                covered_by = existing
                break

        if covered_by is None:
            kept.append(Entry(domain=entry.domain, sources=set(entry.sources)))
        else:
            covered_by.sources.update(entry.sources)
            stats.covered += 1

    return kept


def group_entries(entries: list[Entry]) -> list[tuple[tuple[str, ...], list[Entry]]]:
    groups: dict[tuple[str, ...], list[Entry]] = {}

    for entry in entries:
        key = tuple(sorted(entry.sources))
        groups.setdefault(key, []).append(entry)

    ordered_groups: list[tuple[tuple[str, ...], list[Entry]]] = []
    for key in sorted(groups.keys()):
        ordered_groups.append((key, sorted(groups[key], key=lambda e: e.domain)))

    return ordered_groups


def write_file(path: Path, entries: list[Entry]) -> None:
    if not entries:
        path.write_text("", encoding="utf-8")
        return

    out: list[str] = []
    for sources, group in group_entries(entries):
        if sources:
            out.append(f"# optimized from: {', '.join(sources)}")
        else:
            out.append("# optimized from: unknown")
        out.append("")
        for entry in group:
            out.append(entry.domain)
        out.append("")

    path.write_text("\n".join(out), encoding="utf-8")


def print_stats(path: Path, stats: Stats, entries: list[Entry]) -> None:
    print()
    print("=" * 60)
    print(path.name)
    print("=" * 60)
    print(f"Total entries      : {stats.total}")
    print(f"Unique entries     : {stats.unique}")
    print(f"Duplicates removed : {stats.duplicates}")
    print(f"Invalid entries    : {stats.invalid}")
    print(f"Covered by parent  : {stats.covered}")
    print(f"Result domains     : {len(entries)}")
    print(f"Final entries      : {len(entries)}")
    print("=" * 60)
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Optimize domain list with source tracking")
    parser.add_argument("file", help="Path to txt file")
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        raise SystemExit(f"{path} not found")

    entries, stats = parse_file(path)
    optimized = remove_covered_domains(entries, stats)

    # Stable output order
    optimized = sorted(optimized, key=lambda e: e.domain)

    write_file(path, optimized)
    print_stats(path, stats, optimized)


if __name__ == "__main__":
    main()
