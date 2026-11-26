#!/usr/bin/env python3
"""Read-only provenance check for the disposable Ubuntu 26.04 native job.

No package installation, extraction, profile editing or version fallback.
Downloaded package bytes are pinned and bounded; ordinary production acquisition
still performs its own original path/ELF/dependency/source/namespace checks.
"""

import argparse
import hashlib
import io
import json
import os
import pathlib
import socket
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def read_pinned_archive(package):
    require(package["name"] in {"iptables", "libip4tc2", "libip6tc2", "libxtables12"},
            "closed package name required")
    url = package["url"]
    expected_url = ("https://snapshot.ubuntu.com/ubuntu/20261117T000000Z/pool/main/i/iptables/"
                    f"{package['name']}_{package['version']}_{package['architecture']}.deb")
    require(url == expected_url and
            0 < package["bytes"] < 1 << 20, "closed package provenance required")
    def download(source, hosts):
        with urllib.request.urlopen(source, timeout=30) as response:
            location = urllib.parse.urlsplit(response.url)
            require(location.scheme == "https" and location.hostname in hosts,
                    "unexpected official package location")
            return response.read(package["bytes"] + 1)

    try:
        body = download(url, {"snapshot.ubuntu.com"})
    except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
        if isinstance(error, urllib.error.HTTPError):
            transient = error.code in {408, 429, 500, 502, 503, 504}
        else:
            reason = getattr(error, "reason", error)
            transient = isinstance(reason, (TimeoutError, ConnectionError)) or (
                isinstance(reason, socket.gaierror) and reason.errno == socket.EAI_AGAIN)
        if not transient:
            raise
        if isinstance(error, urllib.error.HTTPError):
            error.close()
        filename = expected_url.rsplit("/", 1)[1]
        print("Retrying the same pinned archive via Ubuntu Launchpad:", filename, flush=True)
        body = download("https://launchpad.net/ubuntu/+archive/primary/+files/" + filename,
                        {"launchpad.net", "launchpadlibrarian.net"})
    require(len(body) == package["bytes"] and hashlib.sha256(body).hexdigest() == package["sha256"],
            "official package archive differs: " + package["name"])
    return body


def fetch_package(package, directory):
    body = read_pinned_archive(package)
    archive = directory / (package["name"] + ".deb")
    # No existing file/symlink may be followed or replaced by preparation.
    descriptor = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())
    return archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download-dir", type=pathlib.Path,
                        help="prepare four verified baseline .debs only; never install packages")
    args = parser.parse_args()
    require(os.geteuid() == 0, "root disposable native fixture required")
    release = dict(
        line.split("=", 1) for line in pathlib.Path("/etc/os-release").read_text().splitlines()
        if "=" in line
    )
    require(release.get("ID", "").strip('"') == "ubuntu" and
            release.get("VERSION_ID", "").strip('"') == "26.04" and
            os.uname().machine == "x86_64", "exact Ubuntu 26.04 amd64 fixture required")
    libc = os.confstr("CS_GNU_LIBC_VERSION")
    require(libc and libc.startswith("glibc ") and
            tuple(map(int, libc.split()[1].split("."))) >= (2, 42), "compatible native glibc required")
    manifest = json.loads((pathlib.Path(__file__).parent / "fixtures/classic-save-1.8.11.json").read_text())
    if args.download_dir is not None:
        directory = args.download_dir
        info = directory.lstat()
        require(directory.is_absolute() and directory.resolve(strict=True) == directory and
                not directory.is_symlink() and directory.is_dir() and
                info.st_uid == 0 and info.st_mode & 0o777 == 0o700 and not any(directory.iterdir()),
                "fresh absolute root-owned 0700 package directory required")
        archives = [str(fetch_package(package, directory)) for package in manifest["packages"]]
        print("ACTUAL_PINNED_CLASSIC_1_8_11_ARCHIVES " + json.dumps(archives))
        return
    observed = []
    with tempfile.TemporaryDirectory(prefix="razvilka-classic-provenance-") as temporary:
        for package in manifest["packages"]:
            version = subprocess.check_output(
                ["dpkg-query", "-W", "-f=${Version}\t${Architecture}\t${Architecture-Variant}", package["name"]], text=True
            )
            require(version == package["version"] + "\t" + package["architecture"] + "\t",
                    "installed baseline package/version/architecture/variant differs: " + package["name"] + " " + repr(version))
            archive = fetch_package(package, pathlib.Path(temporary))
            # The exact verified archive is inspected without running scripts.
            payload = subprocess.check_output(["dpkg-deb", "--fsys-tarfile", str(archive)], timeout=20)
            require(len(payload) <= 8 << 20, "bounded package payload required")
            verified = []
            with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as contents:
                for entry in contents:
                    relative = entry.name.removeprefix("./")
                    selected = relative == "usr/sbin/xtables-legacy-multi" or relative.startswith("usr/lib/x86_64-linux-gnu/")
                    if not selected or not entry.isfile():
                        continue
                    require(".." not in pathlib.PurePosixPath(relative).parts and not relative.startswith("/") and
                            0 < entry.size <= 2 << 20, "bounded library/extension member required")
                    expected = contents.extractfile(entry).read(entry.size + 1)
                    path = pathlib.Path("/") / relative
                    require(path.stat().st_size == entry.size, "installed package member size differs: " + relative)
                    with path.open("rb") as installed:
                        actual = installed.read(entry.size + 1)
                    require(len(expected) == entry.size and actual == expected,
                            "installed package member bytes differ: " + relative +
                            " expected=" + hashlib.sha256(expected).hexdigest() +
                            " actual=" + hashlib.sha256(actual).hexdigest())
                    verified.append({"path": str(path), "sha256": hashlib.sha256(actual).hexdigest()})
            require(verified, "no actual package library/image members checked")
            for pinned in package["files"]:
                require(any(v["path"] == pinned["path"] and v["sha256"] == pinned["sha256"] for v in verified),
                        "pinned production dependency missing")
            observed.append({"package": package["name"], "version": package["version"],
                             "archive_sha256": package["sha256"], "actual_members": verified})
    for alias, target in manifest["aliases"].items():
        require(pathlib.Path(alias).is_symlink() and str(pathlib.Path(alias).resolve(strict=True)) == target,
                "original legacy alias differs: " + alias)
        require(subprocess.check_output([alias, "--version"], text=True).strip() ==
                pathlib.Path(alias).name.removesuffix("-legacy") + " v1.8.11 (legacy)", "actual alias version differs")
    print("ACTUAL_PINNED_CLASSIC_1_8_11_PROVENANCE " + json.dumps({
        "runner": manifest["runner"], "profile": manifest["production_profile"],
        "glibc": libc, "packages": observed, "aliases": manifest["aliases"],
        "classification": "actual pinned bytes; public producer and native scenario checks still required",
    }, sort_keys=True))


if __name__ == "__main__":
    main()
