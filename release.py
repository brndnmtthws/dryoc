#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Cut a dryoc release: check that main is releasable, then tag and push it.

Pushing the `vX.Y.Z` tag starts `.github/workflows/publish.yml`, which
publishes the crate to crates.io and the Python package to PyPI.

    ./release.py [VERSION] [--dry-run] [--yes]
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parent
REPO = "brndnmtthws/dryoc"
USER_AGENT = f"dryoc release.py (https://github.com/{REPO})"
_ID = r"(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)"
SEMVER = re.compile(
    rf"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-({_ID}(?:\.{_ID})*))?"
)
# maturin passes the Cargo version to pep440_rs's `Version::from_str`, whose
# PEP 440 normalization maps these labels. Other labels are rejected: they
# either fail to parse (`-foo`) or change meaning (`-1` is a post-release,
# `-dev.1` sorts before `-alpha`).
PEP440_PRE = {"alpha": "a", "beta": "b", "rc": "rc"}

SemverKey = tuple[int, int, int, int, tuple[tuple[int, int, str], ...]]


class CheckError(Exception):
    """An expected failure, reported without a traceback."""


def execute(*cmd: str, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        raise CheckError(f"{cmd[0]} is not installed") from None


def run(*cmd: str, cwd: Path = ROOT) -> str:
    proc = execute(*cmd, cwd=cwd)
    if proc.returncode != 0:
        lines = (proc.stderr or proc.stdout).strip().splitlines()
        raise CheckError(
            f"`{' '.join(cmd)}` failed" + (f": {lines[-1]}" if lines else "")
        )
    return proc.stdout.strip()


def http_get(url: str) -> tuple[int, bytes]:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    try:
        with urllib.request.urlopen(
            urllib.request.Request(url, headers=headers), timeout=15
        ) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as err:
        return err.code, b""
    except (urllib.error.URLError, TimeoutError) as err:
        raise CheckError(f"GET {url} failed: {getattr(err, 'reason', err)}") from None


def semver_key(version: str) -> SemverKey:
    """Sort key implementing SemVer 2.0.0 precedence (build metadata ignored)."""
    match = SEMVER.fullmatch(version.split("+", 1)[0])
    if match is None:
        raise CheckError(
            f"{version!r} is not a SemVer version (MAJOR.MINOR.PATCH[-PRERELEASE])"
        )
    major, minor, patch, pre = match.groups()
    ids = (
        tuple((0, int(i), "") if i.isdigit() else (1, 0, i) for i in pre.split("."))
        if pre
        else ()
    )
    return int(major), int(minor), int(patch), 0 if pre else 1, ids


def pep440(version: str) -> str:
    """The version maturin puts on the wheels."""
    base, _, pre = version.partition("-")
    if not pre:
        return base
    match = re.fullmatch(r"(alpha|beta|rc)(?:\.(0|[1-9]\d*))?", pre)
    if match is None:
        raise CheckError(
            f"prerelease -{pre} has no clean PEP 440 form; use -alpha.N, -beta.N or -rc.N"
        )
    return f"{base}{PEP440_PRE[match[1]]}{match[2] or 0}"


def package_version(manifest: str) -> str:
    with (ROOT / manifest).open("rb") as f:
        return str(tomllib.load(f)["package"]["version"])


def check_tools() -> str:
    missing = [
        tool for tool in ("git", "cargo", "uv", "gh") if shutil.which(tool) is None
    ]
    if missing:
        raise CheckError(f"not on PATH: {', '.join(missing)}")
    return "git, cargo, uv, gh"


def check_git() -> str:
    problems = []
    branch = run("git", "branch", "--show-current")
    if branch != "main":
        problems.append(f"on branch {branch or '(detached HEAD)'}, not main")
    if run("git", "status", "--porcelain", "--untracked-files=all"):
        problems.append("working tree has uncommitted or untracked changes")
    run("git", "fetch", "--quiet", "origin", "main", "--tags")
    head, upstream = run("git", "rev-parse", "HEAD", "origin/main").split()
    if head != upstream:
        problems.append(f"HEAD {head[:12]} != origin/main {upstream[:12]}")
    if problems:
        raise CheckError("; ".join(problems))
    return f"main, clean, HEAD == origin/main ({head[:12]})"


def check_manifests(version: str) -> str:
    root, python = package_version("Cargo.toml"), package_version("python/Cargo.toml")
    if not root == python == version:
        raise CheckError(
            f"Cargo.toml {root}, python/Cargo.toml {python}, release {version}"
        )
    return f"Cargo.toml and python/Cargo.toml are {version}"


def check_newer(version: str) -> str:
    key, wheel = semver_key(version), pep440(version)
    status, body = http_get("https://crates.io/api/v1/crates/dryoc")
    if status == 404:
        return f"{version} (PyPI {wheel}); dryoc is not on crates.io yet"
    if status != 200:
        raise CheckError(f"crates.io returned HTTP {status}")
    published = [
        v["num"] for v in json.loads(body)["versions"] if SEMVER.match(v["num"])
    ]
    newest = max(published, key=semver_key, default="none")
    if newest != "none" and key <= semver_key(newest):
        raise CheckError(f"{version} is not greater than {newest} on crates.io")
    return f"{version} (PyPI {wheel}) > {newest} on crates.io"


def check_locks() -> str:
    problems = []
    manifest = ("--manifest-path", "python/Cargo.toml")
    if execute(
        "cargo", "metadata", "--locked", "--format-version", "1", *manifest
    ).returncode:
        problems.append(
            "python/Cargo.lock is stale: run `cargo update -p dryoc "
            "--manifest-path python/Cargo.toml`"
        )
    if execute("uv", "lock", "--check", cwd=ROOT / "python").returncode:
        problems.append("python/uv.lock is stale: run `uv lock` in python/")
    if problems:
        raise CheckError("; ".join(problems))
    return "python/Cargo.lock and python/uv.lock are up to date"


def check_tag(tag: str) -> str:
    if (
        execute("git", "rev-parse", "-q", "--verify", f"refs/tags/{tag}").returncode
        == 0
    ):
        raise CheckError(f"{tag} already exists locally")
    if run("git", "ls-remote", "--tags", "origin", f"refs/tags/{tag}"):
        raise CheckError(f"{tag} already exists on origin")
    return f"{tag} exists neither locally nor on origin"


def check_unpublished(version: str) -> str:
    semver_key(version)  # reject malformed versions before asking the registries
    wheel = pep440(version)
    status, _ = http_get(f"https://crates.io/api/v1/crates/dryoc/{version}")
    if status == 200:
        raise CheckError(f"dryoc {version} is already on crates.io")
    if status != 404:
        raise CheckError(f"crates.io returned HTTP {status} for dryoc {version}")
    status, body = http_get("https://pypi.org/pypi/dryoc/json")
    if status == 404:
        return (
            f"not on crates.io; PyPI project does not exist yet, so make sure the "
            f"pending trusted publisher ({REPO}, publish.yml, environment pypi) is configured"
        )
    if status != 200:
        raise CheckError(f"PyPI returned HTTP {status}")
    if wheel in json.loads(body)["releases"]:
        raise CheckError(f"dryoc {wheel} is already on PyPI")
    return f"dryoc {version} is on neither crates.io nor PyPI ({wheel})"


def check_ci() -> str:
    sha = run("git", "rev-parse", "HEAD")
    out = run(
        "gh",
        "run",
        "list",
        "--commit",
        sha,
        "--workflow",
        "build-and-test.yml",
        "--branch",
        "main",
        "--limit",
        "1",
        "--json",
        "conclusion,status,url",
    )
    runs: list[dict[str, str]] = json.loads(out)
    if not runs:
        raise CheckError(f"no Build & test run for {sha[:12]} on main")
    ci = runs[0]
    if ci["status"] != "completed":
        raise CheckError(f"Build & test is {ci['status']}; wait for CI: {ci['url']}")
    if ci["conclusion"] != "success":
        raise CheckError(f"Build & test concluded {ci['conclusion']}: {ci['url']}")
    return f"Build & test passed: {ci['url']}"


def publish_run_url(tag: str) -> str:
    for _ in range(10):
        time.sleep(3)
        proc = execute(
            "gh",
            "run",
            "list",
            "--workflow",
            "publish.yml",
            "--branch",
            tag,
            "--limit",
            "1",
            "--json",
            "url",
        )
        if proc.returncode == 0 and (runs := json.loads(proc.stdout)):
            return str(runs[0]["url"])
    return f"https://github.com/{REPO}/actions/workflows/publish.yml"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "version", nargs="?", help="default: the root Cargo.toml version"
    )
    parser.add_argument("--dry-run", action="store_true", help="run the checks only")
    parser.add_argument(
        "--yes", action="store_true", help="tag and push without asking"
    )
    args = parser.parse_args()
    try:
        version = (args.version or package_version("Cargo.toml")).removeprefix("v")
    except (OSError, tomllib.TOMLDecodeError, KeyError) as err:
        print(f"error: cannot read the version from Cargo.toml: {err}", file=sys.stderr)
        return 1
    tag = f"v{version}"

    checks: list[tuple[str, Callable[[], str]]] = [
        ("tools", check_tools),
        ("git state", check_git),
        ("manifest versions", lambda: check_manifests(version)),
        ("version", lambda: check_newer(version)),
        ("lockfiles", check_locks),
        ("tag", lambda: check_tag(tag)),
        ("not published", lambda: check_unpublished(version)),
        ("CI", check_ci),
    ]
    print(f"Checking release dryoc {version} ({tag})")
    failed = 0
    for name, check in checks:
        try:
            print(f"  ✓ {name}: {check()}")
        except (CheckError, OSError, KeyError, ValueError) as err:
            print(f"  ✗ {name}: {err}")
            failed += 1
    if failed:
        print(f"\n{failed} check(s) failed; not tagging.")
        return 1

    commit = run("git", "log", "-1", "--format=%h %s")
    prerelease = " (marked prerelease)" if "-" in version else ""
    print(
        f"\nRelease dryoc {version}\n  tag:    {tag} (annotated)\n  commit: {commit}\n"
        f"Pushing {tag} starts the Publish workflow: it validates the crate, builds and "
        f"verifies the wheels and sdist, publishes dryoc {version} to crates.io and "
        f"dryoc {pep440(version)} to PyPI, then drafts a GitHub release{prerelease}."
    )
    if args.dry_run:
        print("\nDry run: all checks passed; not tagging.")
        return 0
    if not args.yes:
        try:
            answer = input(f"\nCreate and push tag {tag}? [y/N] ")
        except EOFError:
            answer = ""
        if answer.strip().lower() not in ("y", "yes"):
            print("Aborted.")
            return 1

    run("git", "tag", "-a", tag, "-m", tag)
    try:
        run("git", "push", "origin", f"refs/tags/{tag}")
    except CheckError:
        print(
            f"Push failed; the local tag remains (delete it with `git tag -d {tag}`).",
            file=sys.stderr,
        )
        raise
    print(f"Pushed {tag}. Publish run: {publish_run_url(tag)}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except CheckError as err:
        print(f"error: {err}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
