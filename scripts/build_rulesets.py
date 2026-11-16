#!/usr/bin/env python3
import argparse
import ipaddress
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urljoin

SOURCE = "vnenapravo7-source/iplist-domains"
UPSTREAM_SOURCE = "splify2/splify2-lists"
UPSTREAM_NAME_PREFIX = "[Резерв - splify] "


def read_rules(path, rule_type):
    values = {}
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if rule_type == "domain_suffix" and line == "# DOMAIN_KEYWORD":
            rule_type = "domain_keyword"
        if line and not line.startswith("#"):
            if rule_type == "ip_cidr":
                value = str(ipaddress.ip_network(line, strict=False))
            elif rule_type == "domain_suffix":
                value = line.lower().removeprefix("*.").rstrip(".")
            else:
                value = line.lower()
            values.setdefault(rule_type, []).append(value)
    return [{kind: list(dict.fromkeys(items))} for kind, items in values.items()]


def local_entries(root, previous, section, paths, destination, compiler, rule_type):
    metadata = {
        entry["file"]: entry
        for entry in previous[section]
        if entry.get("source") == SOURCE
    }
    entries = []
    for path in sorted(paths):
        filename = path.relative_to(root).as_posix()
        binary = path.with_suffix(".srs").name
        binary_file = f"srs/{binary}"
        # Older catalogs used filenames that never matched the Discord lists.
        old_filename = "discord-" + filename[3:] if filename.startswith("ds-") else filename
        suffix = "-ip" if rule_type == "ip_cidr" else "-domains"
        identifier = path.stem.removesuffix(suffix)
        entry = dict(metadata.get(binary_file) or metadata.get(filename) or metadata.get(old_filename, {}))
        entry["id"] = entry.get("id", identifier).removeprefix("srs:")
        entry.setdefault("name_ru", "RU" if identifier == "ru" else identifier)
        entry.setdefault("default_on", False)
        if section == "domain_lists":
            entry["kind"] = "domains"
        entry.update(
            file=binary_file,
            format="srs",
            url=urljoin(previous["base_url"].rstrip("/") + "/", binary_file),
            source=SOURCE,
            source_name="iplist-domains",
        )
        entries.append(entry)

        source = destination / path.with_suffix(".json").name
        source.write_text(
            json.dumps({"version": 4, "rules": read_rules(path, rule_type)}),
            encoding="utf-8",
        )
        subprocess.run(
            [compiler, "rule-set", "compile", "--output", str(destination / binary), str(source)],
            check=True,
        )
    return entries


def merge_entries(local, upstream, section):
    base_url = upstream["base_url"].rstrip("/") + "/"
    combined = local + [
        dict(
            entry,
            name_ru=UPSTREAM_NAME_PREFIX + entry["name_ru"],
            url=entry.get("url") or urljoin(base_url, entry["file"]),
        )
        for entry in upstream[section]
    ]
    ids = [entry["id"] for entry in combined]
    if len(ids) != len(set(ids)):
        raise ValueError(f"Duplicate IDs in {section}")
    return combined


def build(root, upstream, compiler):
    catalog_path = root / "lists.json"
    previous = json.loads(catalog_path.read_text(encoding="utf-8"))
    catalog = dict(previous)
    sections = {
        "categories": ("ip_cidr", list(root.glob("*-ip.txt"))),
        "domain_lists": ("domain_suffix", [*root.glob("*-domains.txt"), *root.glob("ru/ru.txt")]),
    }
    catalog["upstream"] = {
        UPSTREAM_SOURCE: {key: value for key, value in upstream.items() if key not in sections}
    }

    with TemporaryDirectory(dir=root) as temp:
        staging = Path(temp)
        for section, (rule_type, paths) in sections.items():
            local = local_entries(root, previous, section, paths, staging, compiler, rule_type)
            catalog[section] = merge_entries(local, upstream, section)

        output = root / "srs"
        output.mkdir(exist_ok=True)
        binaries = {path.name: path for path in staging.glob("*.srs")}
        for path in output.glob("*.srs"):
            if path.name not in binaries:
                path.unlink()
        for name, path in binaries.items():
            path.replace(output / name)

        if catalog != previous:
            now = datetime.now(timezone.utc)
            catalog["version"] = now.strftime("%Y-%m-%d_%H-%M")
            catalog["generated_at"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
            staged_catalog = staging / "lists.json"
            staged_catalog.write_text(
                json.dumps(catalog, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
            staged_catalog.replace(catalog_path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("upstream", type=Path)
    parser.add_argument("--sing-box", default="sing-box")
    args = parser.parse_args()
    upstream = json.loads(args.upstream.read_text(encoding="utf-8-sig"))
    build(Path(__file__).resolve().parents[1], upstream, args.sing_box)


if __name__ == "__main__":
    main()
