#!/usr/bin/env python3
"""Extract the chronological fixture tracks, including incomplete attempts."""

import argparse
import json
from pathlib import Path


def read_tracks(log):
    wall, router = {}, {}
    if not log.is_file():
        return [], []
    with log.open(encoding="utf-8", errors="replace") as lines:
        for line in lines:
            for marker, tracks in (("DOMAIN_WALL_TRACE: ", wall),
                                   ("DOMAIN_ROUTER_OBSERVATION: ", router)):
                if marker in line:
                    raw = line.split(marker, 1)[1].strip()
                    tracks[raw] = json.loads(raw)
    return list(wall.values()), list(router.values())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("revision")
    parser.add_argument("scenario")
    options = parser.parse_args()
    directory = options.directory
    status = directory / "status.txt"
    wall, router = read_tracks(directory / "native.log")
    report = {
        "revision": options.revision,
        "scenario": options.scenario,
        "status": dict(line.split("=", 1) for line in status.read_text().splitlines())
        if status.is_file() else {},
        "wall_tracks": wall,
        "router_observations": router,
        "interpretation": "Consecutive marks within one wall track delimit disjoint intervals. "
        "Tracks and router observations can overlap. A missing mark means the boundary was not observed.",
    }
    (directory / "phases.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
