#!/usr/bin/env python3
"""Assess an upstream workload upgrade for a rock and the charms that deploy it.

Given the version the rock builds today and the version it is moving to, this:

1. works out the upgrade path from upstream's tags (patch or series bump, skipped
   series),
2. compares the upstream files the rock's build depends on between the two tags
   (including manual CVE/dependency overrides in rockcraft.yaml),
3. collects the release notes of every release the upgrade absorbs,
4. asks an LLM to judge the risk and to plan what the charms must validate, and
5. renders a pull request comment and one issue body per charm.

Steps 1-3 are deterministic and always run. Step 4 is skipped when no API key is
configured, unless --require-llm is given.
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, replace
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, TypeVar

try:
    import yaml  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

# Default settings (used when no config file or rockcraft.yaml overrides them).
WORKLOAD = "authentik"
UPSTREAM_REPO = "goauthentik/authentik"
TAG_PREFIX = "version/"
SOURCE_SUBDIR = ""
RELEASE_NOTES_PATH: str | None = "website/docs/releases/{year}/v{year}.{minor}.mdx"
ROCK_IMAGE = "ghcr.io/canonical/authentik-server"
DEFAULT_CHARM_BRANCH = "main"
DEFAULT_CONFIG_PATH = Path(".github/upstream-upgrade.yaml")
ENFORCE_SEQUENTIAL_SERIES = True

# The workflow an engineer runs to open the charm issues, as its name: reads.
CHARM_ISSUES_WORKFLOW = "Upstream charm upgrade issues"

TEMPLATES = Path(__file__).resolve().parent / "templates"
if not TEMPLATES.is_dir():
    TEMPLATES = Path(__file__).resolve().parent.parent / "templates"
USER_AGENT = "canonical-rock-upstream-upgrade"

Series = tuple[int, int]
VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


@dataclass(frozen=True, order=True)
class Version:
    """An upstream release such as 2026.8.3 or 2.4.0; (major, minor) is its series."""

    major: int
    minor: int
    patch: int

    @property
    def year(self) -> int:
        return self.major

    @classmethod
    def parse(cls, text: str) -> Version:
        match = VERSION_RE.fullmatch(text.strip())
        if not match:
            raise ValueError(f"not a release version (expected X.Y.Z): {text!r}")
        return cls(*map(int, match.groups()))

    @property
    def series(self) -> Series:
        return (self.major, self.minor)

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


def series_name(series: Series) -> str:
    return f"{series[0]}.{series[1]}"


DEFAULT_IN_PLACE_UPGRADE = (
    "deploy the current `main` charm with `{{ FROM }}`, run a smoke flow, then "
    "`juju refresh {{ APP }} --resource {{ RESOURCE }}={{ IMAGE }}` "
    "and confirm existing data and relations survive."
)

AUTHENTIK_IN_PLACE_UPGRADE = (
    "deploy the current `main` charm with `{{ FROM }}` against PostgreSQL (and "
    "`authentik-worker`), create a test user/flow or OAuth client, then "
    "`juju refresh {{ APP }} --resource {{ RESOURCE }}={{ IMAGE }}` "
    "and confirm migrations succeed and existing data survives."
)


@dataclass(frozen=True)
class Charm:
    """A charm that deploys this rock and can be sent an upgrade issue."""

    key: str  # how the analysis refers to it in `applies_to`
    repo: str
    app: str = ""
    container: str = ""
    service: str = ""
    resource: str = "oci-image"
    description: str = ""  # what the LLM is told about it
    files: tuple[str, ...] = ("charmcraft.yaml",)  # where it decides how workload is configured
    in_place_upgrade: str = DEFAULT_IN_PLACE_UPGRADE


CHARMS: tuple[Charm, ...] = (
    Charm(
        key="server",
        repo="canonical/authentik-server-operator",
        app="authentik-server",
        container="authentik",
        service="authentik-server",
        resource="oci-image",
        description=(
            "Kubernetes charm running `/lifecycle/ak server` (HTTP 9000, HTTPS 9443, "
            "metrics 9300). It configures authentik only through AUTHENTIK_* environment "
            "variables in its Pebble layer, checks health on /-/health/live/ and "
            "/-/health/ready/, requires PostgreSQL (pg-database) and ingress "
            "(traefik-route), and optionally SMTP, logging and tracing. It calls the "
            "authentik REST API with a bootstrap token to manage OAuth2 providers for "
            "applications related over `oauth`, and shares the secret key and the "
            "database settings with the worker charm over `authentik-cluster`."
        ),
        files=(
            "charmcraft.yaml",
            "src/constants.py",
            "src/env_vars.py",
            "src/configs.py",
            "src/integrations.py",
            "src/services.py",
            "src/cli.py",
            "src/authentik_api.py",
        ),
        in_place_upgrade=AUTHENTIK_IN_PLACE_UPGRADE,
    ),
    Charm(
        key="worker",
        repo="canonical/authentik-worker-operator",
        app="authentik-worker",
        container="authentik",
        service="authentik-worker",
        resource="oci-image",
        description=(
            "Kubernetes charm running `/lifecycle/ak worker` (metrics 9300) from the same "
            "image. It receives AUTHENTIK_SECRET_KEY and the PostgreSQL settings from the "
            "server charm over `authentik-cluster` and sets AUTHENTIK_* environment "
            "variables in its Pebble layer."
        ),
        files=(
            "charmcraft.yaml",
            "src/constants.py",
            "src/env_vars.py",
            "src/configs.py",
            "src/integrations.py",
            "src/services.py",
        ),
        in_place_upgrade=AUTHENTIK_IN_PLACE_UPGRADE,
    ),
)


# Configuration & Auto-detection


def _load_yaml_text(text: str) -> dict[str, Any]:
    """Parse YAML text using PyYAML, JSON, or yq as a fallback."""
    if not text.strip():
        return {}
    if yaml is not None:
        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else {}
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else {}
    except ValueError:
        result = subprocess.run(
            ["yq", "-o=json"],
            input=text,
            check=True,
            capture_output=True,
            text=True,
        )
        data = json.loads(result.stdout)
        return data if isinstance(data, dict) else {}


@dataclass(frozen=True)
class RockMetadata:
    """Metadata inferred from a rock's rockcraft.yaml."""

    name: str
    version: Version | None
    rock_image: str
    workload: str
    upstream_repo: str
    tag_prefix: str
    source_subdir: str
    service: str


def inspect_rockcraft(rockcraft_text: str) -> RockMetadata:
    """Extract rock name, version, upstream GitHub repo, tag prefix, and service from rockcraft.yaml."""
    data = _load_yaml_text(rockcraft_text)
    name = str(data.get("name") or "")
    raw_version = str(data.get("version") or "")
    version: Version | None = None
    if raw_version:
        try:
            version = Version.parse(raw_version)
        except ValueError:
            version = None

    services = data.get("services")
    service = next(iter(services.keys()), name) if isinstance(services, dict) and services else name

    upstream_repo = ""
    tag_prefix = ""
    source_subdir = ""
    parts = data.get("parts")
    if isinstance(parts, dict):
        for part in parts.values():
            if not isinstance(part, dict):
                continue
            source = str(part.get("source") or "")
            gh_match = re.match(
                r"https?://github\.com/([^/\s]+/[^/\s]+?)(?:\.git)?/?$", source
            )
            if not gh_match:
                continue
            source_tag = str(part.get("source-tag") or "")
            if raw_version and source_tag.endswith(raw_version):
                upstream_repo = gh_match.group(1)
                tag_prefix = source_tag[: -len(raw_version)]
                source_subdir = str(part.get("source-subdir") or "").strip("/")
                break
            if not upstream_repo:
                upstream_repo = gh_match.group(1)
                if source_tag and VERSION_RE.search(source_tag):
                    ver_m = VERSION_RE.search(source_tag)
                    assert ver_m is not None
                    tag_prefix = source_tag[: ver_m.start()]
                source_subdir = str(part.get("source-subdir") or "").strip("/")

    workload = upstream_repo.split("/")[-1] if upstream_repo else name
    rock_image = f"ghcr.io/canonical/{name}" if name else ""
    return RockMetadata(
        name=name,
        version=version,
        rock_image=rock_image,
        workload=workload,
        upstream_repo=upstream_repo,
        tag_prefix=tag_prefix,
        source_subdir=source_subdir,
        service=service,
    )


def enrich_charm_from_charmcraft(
    charm: Charm, charmcraft_text: str, rock_image: str, default_service: str = ""
) -> Charm:
    """Fill in missing charm metadata (app, container, service, resource) from charmcraft.yaml."""
    data = _load_yaml_text(charmcraft_text)
    app = charm.app or str(data.get("name") or charm.repo.split("/")[-1])

    container = charm.container
    containers = data.get("containers")
    if not container and isinstance(containers, dict) and containers:
        container = str(next(iter(containers.keys())))

    resource = charm.resource or "oci-image"
    resources = data.get("resources")
    if isinstance(resources, dict):
        for res_name, res_data in resources.items():
            if not isinstance(res_data, dict):
                continue
            up_src = str(res_data.get("upstream-source") or "")
            if rock_image and up_src.startswith(f"{rock_image}:"):
                resource = str(res_name)
                break

    service = charm.service or default_service or container or app
    return replace(
        charm,
        app=app,
        container=container or app,
        service=service,
        resource=resource,
    )


def configure_from_files(
    config_path: Path | None, rockcraft_path: Path | None
) -> None:
    """Update module-level configuration from rockcraft.yaml and optional config YAML."""
    global WORKLOAD, UPSTREAM_REPO, TAG_PREFIX, SOURCE_SUBDIR, RELEASE_NOTES_PATH
    global ROCK_IMAGE, DIFFED_FILES, TRUSTED_LINK_HOSTS, CHARMS, ENFORCE_SEQUENTIAL_SERIES

    rock_meta: RockMetadata | None = None
    if rockcraft_path and rockcraft_path.exists():
        rock_meta = inspect_rockcraft(rockcraft_path.read_text(encoding="utf-8"))

    cfg: dict[str, Any] = {}
    if config_path and config_path.exists():
        cfg = _load_yaml_text(config_path.read_text(encoding="utf-8"))

    if not cfg and (rock_meta is None or not rock_meta.upstream_repo):
        return

    if rock_meta and rock_meta.upstream_repo:
        WORKLOAD = rock_meta.workload
        UPSTREAM_REPO = rock_meta.upstream_repo
        TAG_PREFIX = rock_meta.tag_prefix
        SOURCE_SUBDIR = rock_meta.source_subdir
        ROCK_IMAGE = rock_meta.rock_image
        if UPSTREAM_REPO != "goauthentik/authentik":
            RELEASE_NOTES_PATH = None
            DIFFED_FILES = ("Dockerfile",)
            TRUSTED_LINK_HOSTS = ()
            ENFORCE_SEQUENTIAL_SERIES = False

    if "workload" in cfg:
        WORKLOAD = str(cfg["workload"])
    if "upstream_repo" in cfg:
        UPSTREAM_REPO = str(cfg["upstream_repo"])
    if "tag_prefix" in cfg:
        TAG_PREFIX = str(cfg["tag_prefix"])
    if "source_subdir" in cfg:
        SOURCE_SUBDIR = str(cfg["source_subdir"]).strip("/")
    if "rock_image" in cfg:
        ROCK_IMAGE = str(cfg["rock_image"])
    if "release_notes_path" in cfg:
        val = cfg["release_notes_path"]
        RELEASE_NOTES_PATH = str(val) if val else None
    if "diffed_files" in cfg and isinstance(cfg["diffed_files"], list):
        DIFFED_FILES = tuple(str(f) for f in cfg["diffed_files"])
    if "trusted_link_hosts" in cfg and isinstance(cfg["trusted_link_hosts"], list):
        TRUSTED_LINK_HOSTS = tuple(str(h) for h in cfg["trusted_link_hosts"])
    if "enforce_sequential_series" in cfg:
        ENFORCE_SEQUENTIAL_SERIES = bool(cfg["enforce_sequential_series"])

    default_service = rock_meta.service if rock_meta else ""
    if "charms" in cfg and isinstance(cfg["charms"], list):
        parsed_charms: list[Charm] = []
        for entry in cfg["charms"]:
            if not isinstance(entry, dict):
                continue
            repo = str(entry["repo"])
            default_key = repo.split("/")[-1].removesuffix("-operator").removesuffix("-k8s")
            key = str(entry.get("key") or default_key)
            files_raw = entry.get("files") or ["charmcraft.yaml"]
            in_place = str(
                entry.get("in_place_upgrade")
                or cfg.get("in_place_upgrade")
                or DEFAULT_IN_PLACE_UPGRADE
            )
            parsed_charms.append(
                Charm(
                    key=key,
                    repo=repo,
                    app=str(entry.get("app") or ""),
                    container=str(entry.get("container") or ""),
                    service=str(entry.get("service") or default_service),
                    resource=str(entry.get("resource") or "oci-image"),
                    description=str(entry.get("description") or f"Charm in {repo}."),
                    files=tuple(str(f) for f in files_raw),
                    in_place_upgrade=in_place,
                )
            )
        if parsed_charms:
            CHARMS = tuple(parsed_charms)
    upstream_file.cache_clear()


# Network access

ATTEMPTS = 3
TRANSIENT_STATUSES = (408, 429, 500, 502, 503, 504)
T = TypeVar("T")


def is_transient(error: Exception) -> bool:
    """Whether a failed request or git call is worth trying again."""
    if isinstance(error, urllib.error.HTTPError):
        return error.code in TRANSIENT_STATUSES
    # Connection failures and timeouts, and git not reaching the remote.
    return isinstance(error, (OSError, subprocess.SubprocessError))


def retrying(call: Callable[[], T]) -> T:
    """Run a network call, waiting and trying again when it fails temporarily."""
    for attempt in range(1, ATTEMPTS):
        try:
            return call()
        except Exception as error:
            if not is_transient(error):
                raise
        time.sleep(5 * attempt)
    return call()


def read_url(request: urllib.request.Request, timeout: int) -> bytes:
    def read() -> bytes:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read()

    return retrying(read)


def http_get(url: str, headers: Mapping[str, str] | None = None) -> str | None:
    """Return the body at a URL, or None when it does not exist."""
    req_headers = {"User-Agent": USER_AGENT, **(headers or {})}
    request = urllib.request.Request(url, headers=req_headers)
    try:
        return read_url(request, timeout=30).decode("utf-8")
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


@lru_cache(maxsize=None)
def upstream_file(version: Version, path: str) -> str | None:
    """A file from upstream's source tree as it was at a release."""
    content = http_get(
        f"https://raw.githubusercontent.com/{UPSTREAM_REPO}/{TAG_PREFIX}{version}/{path}"
    )
    if content is None and SOURCE_SUBDIR and not path.startswith(f"{SOURCE_SUBDIR}/"):
        content = http_get(
            f"https://raw.githubusercontent.com/{UPSTREAM_REPO}/{TAG_PREFIX}{version}/{SOURCE_SUBDIR}/{path}"
        )
    return content


def charm_file(charm: Charm, path: str, branch: str = DEFAULT_CHARM_BRANCH) -> str | None:
    """A file from a charm's target branch."""
    return http_get(f"https://raw.githubusercontent.com/{charm.repo}/{branch}/{path}")


def charmcraft_version(text: str, image: str | None = None) -> Version:
    """The upstream rock version a charmcraft.yaml references in upstream-source."""
    target_image = image if image is not None else ROCK_IMAGE
    pattern = rf'upstream-source:\s*["\']?{re.escape(target_image)}:([^"\'\s]+)'
    match = re.search(pattern, text)
    if not match:
        raise ValueError(f"no upstream-source for {target_image} in charmcraft.yaml")
    return Version.parse(match.group(1))


def resolve_from_version(
    charms: Iterable[Charm],
    fetch: Callable[[Charm, str], str | None],
    image: str | None = None,
) -> Version:
    """Read the currently deployed rock version from the charms' charmcraft.yaml."""
    versions: dict[str, Version] = {}
    for charm in charms:
        text = fetch(charm, "charmcraft.yaml")
        if text is None:
            raise ValueError(f"{charm.repo} has no charmcraft.yaml")
        versions[charm.repo] = charmcraft_version(text, image=image)
    if not versions:
        raise ValueError("no charms configured to read version from")
    unique = set(versions.values())
    if len(unique) > 1:
        details = ", ".join(f"{repo}={ver}" for repo, ver in versions.items())
        print(f"::warning::Charms reference different versions ({details}); using the oldest.")
    return min(unique)


def read_charm_files(
    fetch: Callable[[Charm, str], str | None],
    charms: Iterable[Charm] | None = None,
) -> list[tuple[Charm, str, str]]:
    """The files of every charm that say how it configures and runs the workload."""
    found = []
    for charm in charms if charms is not None else CHARMS:
        for path in charm.files:
            text = fetch(charm, path)
            if text is None:
                print(f"::warning::{charm.repo} has no {path}; update charm files configuration")
            else:
                found.append((charm, path, text))
    return found


def notes_path(series: Series) -> str:
    if not RELEASE_NOTES_PATH:
        return ""
    return RELEASE_NOTES_PATH.format(
        year=series[0], major=series[0], minor=series[1]
    )


def release_notes(series: Series) -> str | None:
    """The release notes page of a series. Upstream keeps amending it on main."""
    if not RELEASE_NOTES_PATH:
        return None
    return http_get(
        f"https://raw.githubusercontent.com/{UPSTREAM_REPO}/main/{notes_path(series)}"
    )


def github_release_notes(
    frm: Version, to: Version, released: Iterable[Version]
) -> dict[Series, str]:
    """Fetch release notes from GitHub Releases for versions in (frm, to]."""
    absorbed = [v for v in sorted(released) if frm < v <= to]
    # Cap the number of individual release API calls to avoid rate limits.
    if len(absorbed) > 12:
        absorbed = absorbed[-12:]
    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if token := os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"

    by_series: dict[Series, list[str]] = {}
    for ver in absorbed:
        url = (
            f"https://api.github.com/repos/{UPSTREAM_REPO}/releases/tags/"
            f"{TAG_PREFIX}{ver}"
        )
        try:
            raw = http_get(url, headers=headers)
        except TypeError:
            raw = http_get(url)
        if not raw:
            continue
        try:
            payload = json.loads(raw)
        except ValueError:
            continue
        body = (payload.get("body") or "").strip()
        if body:
            by_series.setdefault(ver.series, []).append(f"## {ver}\n\n{body}")

    result: dict[Series, str] = {}
    for series in (*{v.series for v in absorbed}, to.series):
        chunks = by_series.get(series, [])
        result[series] = clip("\n\n".join(chunks), MAX_NOTES_CHARS)
    return result


def list_released_versions() -> list[Version]:
    """Every final release upstream has tagged."""
    command = [
        "git",
        "ls-remote",
        "--tags",
        "--refs",
        f"https://github.com/{UPSTREAM_REPO}",
        f"refs/tags/{TAG_PREFIX}*",
    ]
    output = retrying(
        lambda: subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)
    ).stdout
    versions = set()
    for line in output.splitlines():
        tag = line.rsplit(f"refs/tags/{TAG_PREFIX}", 1)[-1]
        if VERSION_RE.fullmatch(tag):  # skips release candidates
            versions.add(Version.parse(tag))
    return sorted(versions)


def rockcraft_version(path: Path) -> Version:
    """The upstream version a rockcraft.yaml builds."""
    match = re.search(
        r'^version:\s*["\']?([^"\'\s]+)', path.read_text(encoding="utf-8"), re.MULTILINE
    )
    if not match:
        raise ValueError(f"no version field in {path}")
    return Version.parse(match.group(1))


# Upgrade path


@dataclass(frozen=True)
class UpgradePath:
    frm: Version
    to: Version
    skipped: tuple[Series, ...]  # released series strictly between the two
    newer_patch: Version | None  # latest patch of the series being left, if not on it

    @property
    def kind(self) -> str:
        return "patch" if self.frm.series == self.to.series else "series"

    @property
    def absorbed_series(self) -> tuple[Series, ...]:
        """Series whose release notes describe changes this upgrade brings in."""
        return (*self.skipped, self.to.series)


def plan_upgrade(frm: Version, to: Version, released: Iterable[Version]) -> UpgradePath:
    """Place an upgrade among upstream's releases.

    Records skipped minor/series releases and whether a newer patch exists on the
    current series.
    """
    released = list(released)
    skipped = sorted({v.series for v in released if frm.series < v.series < to.series})
    newer_patch = None
    if frm.series != to.series:
        latest = max((v for v in released if v.series == frm.series), default=frm)
        newer_patch = latest if latest > frm else None
    return UpgradePath(frm, to, tuple(skipped), newer_patch)


# Release notes

FIXED_IN_RE = re.compile(r"Fixed in v?(\d+\.\d+\.\d+)", re.IGNORECASE)
# Long sections that say nothing about how the workload is built, configured or run.
IGNORED_SECTIONS = ("new integration guides", "new source guides", "api changes")
MAX_NOTES_CHARS = 80_000


def split_sections(doc: str) -> list[tuple[str, str]]:
    """Split a release notes page into its (heading, body) `## ` sections."""
    parts = re.split(r"^## +(.+?) *$", doc, flags=re.MULTILINE)
    return list(zip(parts[1::2], parts[2::2]))  # parts[0] is the front matter


def relevant_notes(doc: str, path: UpgradePath) -> str:
    """Keep the parts of a series' release notes that this upgrade absorbs.

    A patch bump only takes the "Fixed in" sections it crosses; the series-wide
    sections describe changes the rock already has. A series bump takes those too,
    minus the patches released after the target.
    """
    kept = []
    for heading, body in split_sections(doc):
        fixed = FIXED_IN_RE.fullmatch(heading)
        if fixed:
            keep = path.frm < Version.parse(fixed.group(1)) <= path.to
        else:
            keep = path.kind == "series" and heading.lower() not in IGNORED_SECTIONS
        if keep:
            kept.append(f"## {heading}\n\n{body.strip()}")
    return clip("\n\n".join(kept), MAX_NOTES_CHARS)


# Build inputs


@dataclass(frozen=True)
class Probe:
    """One fact about upstream's build that the rock's recipe has to match."""

    label: str
    path: str
    read: Callable[[str], str | None]


def _line(pattern: str) -> Callable[[str], str | None]:
    compiled = re.compile(pattern, re.MULTILINE)

    def read(text: str) -> str | None:
        match = compiled.search(text)
        return match.group(1) if match else None

    return read


def _node_engine(text: str) -> str | None:
    return json.loads(text).get("engines", {}).get("node")


def _web_package_manager(text: str) -> str | None:
    package = json.loads(text)
    if "packageManager" in package:
        return package["packageManager"].split("+", 1)[0]  # drop the integrity hash
    return ", ".join(sorted(set(package.get("engines", {})) - {"node"})) or None


PROBES = (
    Probe("Rust toolchain", "rust-toolchain.toml", _line(r'^channel\s*=\s*"([^"]+)"')),
    Probe("Go", "go.mod", _line(r"^go (\S+)")),
    Probe("Python", "pyproject.toml", _line(r'^requires-python\s*=\s*"([^"]+)"')),
    Probe("PyO3", "Cargo.toml", _line(r'^pyo3\s*=\s*"=?\s*([^"]+)"')),
    Probe("Node.js", "web/package.json", _node_engine),
    Probe("Web package manager", "web/package.json", _web_package_manager),
)
# Upstream's own image recipe and entrypoint, which rockcraft.yaml mirrors.
DIFFED_FILES: tuple[str, ...] = ("lifecycle/container/Dockerfile", "lifecycle/ak")

Fetch = Callable[[Version, str], "str | None"]


@dataclass(frozen=True)
class DependencyOverride:
    """A manual dependency bump in rockcraft.yaml and its upstream status."""

    ecosystem: str  # "go", "go-toolchain", "python", "rust"
    package: str
    spec: str  # the exact token/requirement in rockcraft.yaml
    min_version: str | None  # minimum version pinned in rockcraft.yaml, if any
    upstream_file: str  # go.mod, uv.lock, Cargo.lock
    before: str | None
    after: str | None
    status: str  # "satisfied", "removed", "bumped", "needed"


def parse_dep_version(version_str: str | None) -> tuple[int, ...] | None:
    """Parse a semantic/dotted version string into a tuple of ints for comparison."""
    if not version_str:
        return None
    cleaned = version_str.strip().lstrip("v")
    if re.search(r"-\d{14}-[0-9a-f]{12}$", cleaned):
        return None
    base = cleaned.split("-", 1)[0].split("+", 1)[0]
    parts = base.split(".")
    if not all(part.isdigit() for part in parts):
        return None
    return tuple(int(part) for part in parts)


def _normalize_py_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _go_mod_versions(text: str | None) -> dict[str, str]:
    """Map Go module paths (and 'go' for the toolchain) to their versions in go.mod."""
    if not text:
        return {}
    versions: dict[str, str] = {}
    if go_match := re.search(r"^go\s+(\S+)", text, re.MULTILINE):
        versions["go"] = go_match.group(1)
    for line in text.splitlines():
        line = line.split("//", 1)[0].strip()
        if line.startswith("require "):
            line = line.removeprefix("require ").strip()
        match = re.fullmatch(r"([a-zA-Z0-9._/-]+)\s+(v\S+)", line)
        if match:
            versions[match.group(1)] = match.group(2)
    return versions


def _uv_lock_versions(text: str | None) -> dict[str, str]:
    """Map normalized Python package names to their versions in uv.lock."""
    if not text:
        return {}
    versions: dict[str, str] = {}
    for block in text.split("[[package]]"):
        name_m = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
        ver_m = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
        if name_m and ver_m:
            versions[_normalize_py_name(name_m.group(1))] = ver_m.group(1)
    return versions


def _cargo_lock_versions(text: str | None) -> dict[str, str]:
    """Map Rust crate names to their versions in Cargo.lock."""
    if not text:
        return {}
    versions: dict[str, str] = {}
    for block in text.split("[[package]]"):
        name_m = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
        ver_m = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
        if name_m and ver_m:
            versions[name_m.group(1)] = ver_m.group(1)
    return versions


def extract_rockcraft_overrides(
    rockcraft_text: str,
) -> list[tuple[str, str, str, str | None, str]]:
    """Find manual CVE/dependency overrides in rockcraft.yaml.

    Returns (ecosystem, package, spec, min_version, upstream_file) tuples.
    """
    found: list[tuple[str, str, str, str | None, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(
        eco: str, pkg: str, spec: str, min_ver: str | None, up_file: str
    ) -> None:
        key = (eco, _normalize_py_name(pkg) if eco == "python" else pkg)
        if key not in seen:
            seen.add(key)
            found.append((eco, pkg, spec, min_ver, up_file))

    for match in re.finditer(r"go\s+mod\s+edit\s+-go=(\S+)", rockcraft_text):
        ver = match.group(1)
        add("go-toolchain", "go", match.group(0), ver, "go.mod")

    for match in re.finditer(
        r"go\s+mod\s+edit\s+-replace\s+([^\s=]+)=[^\s@]+@v?(\S+)", rockcraft_text
    ):
        pkg, ver = match.group(1), match.group(2)
        add("go", pkg, match.group(0), f"v{ver.lstrip('v')}", "go.mod")

    for match in re.finditer(r"go\s+get(?:\s+-\S+)*\s+([^\s\\#]+)", rockcraft_text):
        target = match.group(1).strip("\"'")
        if target in ("./...", "."):
            continue
        pkg, _, ver = target.partition("@")
        min_ver = f"v{ver.lstrip('v')}" if ver and ver != "latest" else None
        add("go", pkg, match.group(0), min_ver, "go.mod")

    pip_block_re = re.compile(r"(?:uv\s+)?pip\s+install\b((?:.*\\\n)*.*)")
    for block_match in pip_block_re.finditer(rockcraft_text):
        block = block_match.group(0)
        for req_match in re.finditer(
            r'"([A-Za-z0-9_.-]+)(?:>=|==)([^",<\s]+)(?:,[^"\s]*)?"'
            r"|'([A-Za-z0-9_.-]+)(?:>=|==)([^',<\s]+)(?:,[^'\s]*)?'",
            block,
        ):
            pkg = req_match.group(1) or req_match.group(3)
            ver = req_match.group(2) or req_match.group(4)
            add("python", pkg, req_match.group(0), ver, "uv.lock")

    for match in re.finditer(
        r"cargo\s+update\s+(?:-\S+\s+)*-p\s+(\S+)\s+--precise\s+(\S+)", rockcraft_text
    ):
        pkg, ver = match.group(1).strip("\"'"), match.group(2).strip("\"'")
        add("rust", pkg, match.group(0), ver, "Cargo.lock")

    return found


def compare_dependency_overrides(
    rockcraft_text: str,
    frm: Version,
    to: Version,
    fetch: Fetch,
    base_rockcraft_text: str | None = None,
) -> tuple[DependencyOverride, ...]:
    """Compare dependency overrides in rockcraft.yaml against upstream lockfiles."""
    raw = extract_rockcraft_overrides(rockcraft_text)
    already_removed: set[tuple[str, str]] = set()
    if base_rockcraft_text:
        current_keys = {
            (eco, _normalize_py_name(pkg) if eco == "python" else pkg)
            for eco, pkg, _, _, _ in raw
        }
        for item in extract_rockcraft_overrides(base_rockcraft_text):
            eco, pkg = item[0], item[1]
            key = (eco, _normalize_py_name(pkg) if eco == "python" else pkg)
            if key not in current_keys:
                raw.append(item)
                already_removed.add(key)
    if not raw:
        return ()

    go_before = _go_mod_versions(fetch(frm, "go.mod"))
    go_after = _go_mod_versions(fetch(to, "go.mod"))
    py_before = _uv_lock_versions(fetch(frm, "uv.lock"))
    py_after = _uv_lock_versions(fetch(to, "uv.lock"))
    rs_before = _cargo_lock_versions(fetch(frm, "Cargo.lock"))
    rs_after = _cargo_lock_versions(fetch(to, "Cargo.lock"))

    results: list[DependencyOverride] = []
    for eco, pkg, spec, min_ver, up_file in raw:
        if eco in ("go", "go-toolchain"):
            before = go_before.get(pkg)
            after = go_after.get(pkg)
        elif eco == "python":
            key = _normalize_py_name(pkg)
            before = py_before.get(key)
            after = py_after.get(key)
        else:
            before = rs_before.get(pkg)
            after = rs_after.get(pkg)

        after_t = parse_dep_version(after)
        before_t = parse_dep_version(before)
        min_t = parse_dep_version(min_ver)
        norm_key = (eco, _normalize_py_name(pkg) if eco == "python" else pkg)

        if min_t and after_t and after_t >= min_t:
            status = "removed" if norm_key in already_removed else "satisfied"
        elif norm_key in already_removed:
            continue
        elif not min_t and after_t and before_t and after_t > before_t:
            status = "bumped"
        else:
            status = "needed"

        results.append(
            DependencyOverride(
                ecosystem=eco,
                package=pkg,
                spec=spec,
                min_version=min_ver,
                upstream_file=up_file,
                before=before,
                after=after,
                status=status,
            )
        )
    return tuple(results)


def prune_rockcraft_overrides(
    rockcraft_text: str, overrides: Iterable[DependencyOverride]
) -> tuple[str, list[DependencyOverride]]:
    """Remove satisfied dependency overrides from rockcraft.yaml."""
    satisfied = [o for o in overrides if o.status == "satisfied"]
    if not satisfied:
        return rockcraft_text, []

    lines = rockcraft_text.splitlines()
    remove_indices: set[int] = set()
    pruned: list[DependencyOverride] = []

    single_line = [o for o in satisfied if o.ecosystem in ("go", "go-toolchain", "rust")]
    for ov in single_line:
        for idx, line in enumerate(lines):
            if idx not in remove_indices and ov.spec in line:
                remove_indices.add(idx)
                if ov not in pruned:
                    pruned.append(ov)

    py_satisfied = [o for o in satisfied if o.ecosystem == "python"]
    if py_satisfied:
        i = 0
        while i < len(lines):
            if re.search(r"(?:uv\s+)?pip\s+install\b", lines[i]):
                cmd_start = i
                env_start = cmd_start
                while env_start > 0 and re.match(
                    r"^\s*[A-Z_][A-Z0-9_]*=.*\\\s*$", lines[env_start - 1]
                ):
                    env_start -= 1
                comment_start = env_start
                while comment_start > 0 and re.match(
                    r"^\s*#.*(?:CVE|vulnerab|upgrade|bump)",
                    lines[comment_start - 1],
                    re.IGNORECASE,
                ):
                    comment_start -= 1

                cmd_end = cmd_start
                while cmd_end < len(lines) and lines[cmd_end].rstrip().endswith("\\"):
                    cmd_end += 1
                if cmd_end >= len(lines):
                    cmd_end = len(lines) - 1

                pkg_indices: list[int] = []
                matched_indices: list[int] = []
                for j in range(cmd_start, cmd_end + 1):
                    if j == cmd_start and lines[j].rstrip().endswith("\\"):
                        continue
                    pkg_indices.append(j)
                    for ov in py_satisfied:
                        if ov.spec in lines[j]:
                            matched_indices.append(j)
                            if ov not in pruned:
                                pruned.append(ov)
                            break

                if matched_indices:
                    if len(matched_indices) == len(pkg_indices) and pkg_indices:
                        for j in range(comment_start, cmd_end + 1):
                            remove_indices.add(j)
                    else:
                        for j in matched_indices:
                            remove_indices.add(j)
                        remaining = [j for j in pkg_indices if j not in remove_indices]
                        if remaining:
                            last_rem = remaining[-1]
                            lines[last_rem] = re.sub(r"\s*\\\s*$", "", lines[last_rem])
                i = cmd_end + 1
            else:
                i += 1

    if not remove_indices:
        return rockcraft_text, []

    if re.search(r"go\s+mod\s+tidy", rockcraft_text):
        remaining_go = any(
            idx not in remove_indices
            and re.search(r"go\s+(?:get|mod\s+edit)\b", line)
            for idx, line in enumerate(lines)
        )
        if not remaining_go:
            for idx, line in enumerate(lines):
                if re.match(r"^\s*go\s+mod\s+tidy\s*$", line):
                    remove_indices.add(idx)

    new_lines = [line for idx, line in enumerate(lines) if idx not in remove_indices]
    cleaned: list[str] = []
    for line in new_lines:
        if not line.strip() and cleaned and not cleaned[-1].strip():
            continue
        cleaned.append(line)

    trailing = "\n" if rockcraft_text.endswith("\n") else ""
    pruned_ordered = [ov for ov in satisfied if ov in pruned]
    return "\n".join(cleaned) + trailing, pruned_ordered


@dataclass(frozen=True)
class BuildInputs:
    facts: tuple[tuple[Probe, str | None, str | None], ...]  # probe, before, after
    diffs: tuple[tuple[str, str], ...]  # path and unified diff of each changed file
    files: tuple[tuple[str, str], ...]  # path and full text of each at the new version
    overrides: tuple[DependencyOverride, ...] = ()  # manual dependency bumps in rockcraft.yaml

    @property
    def changed(self) -> bool:
        return (
            bool(self.diffs)
            or any(old != new for _, old, new in self.facts)
            or any(
                o.before != o.after or o.status in ("satisfied", "removed")
                for o in self.overrides
            )
        )


def compare_build_inputs(
    frm: Version,
    to: Version,
    fetch: Fetch,
    rockcraft_text: str = "",
    base_rockcraft_text: str | None = None,
) -> BuildInputs:
    def read(probe: Probe, version: Version) -> str | None:
        text = fetch(version, probe.path)
        if text is None:
            return None
        try:
            return probe.read(text)
        except ValueError:  # the file is not what the probe expects, e.g. broken JSON
            return None

    facts = tuple((probe, read(probe, frm), read(probe, to)) for probe in PROBES)
    diffs, files = [], []
    for path in DIFFED_FILES:
        old, new = fetch(frm, path), fetch(to, path)
        if new is not None:
            files.append((path, new))
        if old != new:
            lines = difflib.unified_diff(
                (old or "").splitlines(),
                (new or "").splitlines(),
                f"{path} @ {frm}",
                f"{path} @ {to}",
                n=2,
                lineterm="",
            )
            diffs.append((path, "\n".join(lines)))
    overrides = (
        compare_dependency_overrides(
            rockcraft_text, frm, to, fetch, base_rockcraft_text
        )
        if rockcraft_text or base_rockcraft_text
        else ()
    )
    return BuildInputs(facts, tuple(diffs), tuple(files), overrides)


# Text handling

ZERO_WIDTH_SPACE = "​"
URL_RE = re.compile(r"https?://[^\s<>()\[\]\"'`]+")
TRUSTED_LINK_HOSTS: tuple[str, ...] = ("goauthentik.io", "docs.goauthentik.io")


def clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _vet_url(match: re.Match[str]) -> str:
    url = urllib.parse.urlsplit(match.group(0))
    if url.hostname in TRUSTED_LINK_HOSTS:
        return match.group(0)
    if url.hostname == "github.com" and url.path.startswith(f"/{UPSTREAM_REPO}/"):
        # GitHub's redirector links to upstream without adding a cross-reference
        # to their issues and pull requests.
        return match.group(0).replace("//github.com/", "//redirect.github.com/", 1)
    return "[link removed]"


def sanitize(text: object, limit: int = 600) -> str:
    """Make third-party or LLM-written text safe to embed in a comment or an issue.

    The result is one line that cannot open HTML (including comments, which hide
    text from human readers but not from agents), close a code fence, notify
    people, cross-reference issues, or link anywhere but upstream.
    """
    line = " ".join(str(text).split())
    line = URL_RE.sub(_vet_url, line)
    line = line.replace("```", "`")
    line = re.sub(r"<(?=[!/?A-Za-z])", "<" + ZERO_WIDTH_SPACE, line)
    # Only an @ at the start of a word is a mention; "pnpm@12" is left readable.
    line = re.sub(r"(?<!\w)@(?=\w)", "@" + ZERO_WIDTH_SPACE, line)
    line = re.sub(r"#(?=\d)", "#" + ZERO_WIDTH_SPACE, line)
    return clip(line, limit)


def code(text: object) -> str:
    """Render a short upstream value as an inline code span, where nothing is live."""
    line = " ".join(str(text).split()).replace("`", "'").replace("|", "\\|")
    return f"`{clip(line, 80)}`"


PLACEHOLDER_RE = re.compile(r"\{\{ *([A-Z_]+) *\}\}")


def render(template: str, values: Mapping[str, str]) -> str:
    """Fill a template's {{ NAME }} placeholders in one pass.

    Values are never rescanned, so text that happens to contain a placeholder is
    left alone, and a placeholder without a value is an error.
    """
    defaults = {"WORKLOAD": WORKLOAD, "RESOURCE": "oci-image"}
    merged = {**defaults, **values}
    text = (TEMPLATES / template).read_text(encoding="utf-8")
    filled = PLACEHOLDER_RE.sub(lambda match: merged[match.group(1)], text)
    return re.sub(r"\n{3,}", "\n\n", filled).strip() + "\n"


def render_inline(template_text: str, values: Mapping[str, str]) -> str:
    """Fill {{ NAME }} placeholders in an inline configuration string."""
    defaults = {"WORKLOAD": WORKLOAD, "RESOURCE": "oci-image"}
    merged = {**defaults, **values}
    return PLACEHOLDER_RE.sub(lambda match: merged[match.group(1)], template_text)


# LLM analysis

RISK_LEVELS = ("low", "medium", "high")
MAX_FILE_CHARS = 30_000  # per upstream or charm file shown to the model
# Bounds on what one analysis can add to a comment or an issue.
MAX_ITEMS = 10
MAX_FIELD_CHARS = 800


def _object(**properties: dict) -> dict:
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties),
        "additionalProperties": False,
    }


def _array(items: dict) -> dict:
    return {"type": "array", "items": items}


_TEXT = {"type": "string"}


def build_analysis_schema(charms: Iterable[Charm] | None = None) -> dict:
    charm_list = tuple(charms) if charms is not None else CHARMS
    keys = [*(charm.key for charm in charm_list), "both"]
    if len(charm_list) > 2 and "all" not in keys:
        keys.append("all")
    applies_to = {"type": "string", "enum": keys}
    return _object(
        risk=_object(
            level={"type": "string", "enum": list(RISK_LEVELS)},
            summary=_TEXT,
            drivers=_array(_object(title=_TEXT, detail=_TEXT, source=_TEXT)),
        ),
        rock=_object(
            summary=_TEXT,
            changes=_array(_object(title=_TEXT, detail=_TEXT)),
        ),
        charm=_object(
            summary=_TEXT,
            changes=_array(_object(applies_to=applies_to, title=_TEXT, detail=_TEXT)),
            validation=_array(
                _object(
                    applies_to=applies_to,
                    title=_TEXT,
                    why=_TEXT,
                    how=_TEXT,
                    expected=_TEXT,
                )
            ),
        ),
    )


ANALYSIS_SCHEMA = build_analysis_schema(CHARMS)


def schema_errors(value: Any, schema: dict, where: str = "$") -> list[str]:
    """Check a value against the subset of JSON Schema that ANALYSIS_SCHEMA uses."""
    if schema["type"] == "object":
        if not isinstance(value, dict):
            return [f"{where}: expected an object"]
        errors = []
        for key, subschema in schema["properties"].items():
            if key not in value:
                errors.append(f"{where}.{key}: missing")
            else:
                errors += schema_errors(value[key], subschema, f"{where}.{key}")
        return errors
    if schema["type"] == "array":
        if not isinstance(value, list):
            return [f"{where}: expected an array"]
        return [
            error
            for index, item in enumerate(value)
            for error in schema_errors(item, schema["items"], f"{where}[{index}]")
        ]
    if not isinstance(value, str):
        return [f"{where}: expected a string"]
    if "enum" in schema and value not in schema["enum"]:
        return [f"{where}: {value!r} is not one of {schema['enum']}"]
    return []


def tidy(value: Any, schema: dict | None = None) -> Any:
    """Sanitize every free-text field of a valid analysis and bound its lists."""
    active_schema = schema or build_analysis_schema()
    if active_schema["type"] == "object":
        return {
            key: tidy(value[key], sub)
            for key, sub in active_schema["properties"].items()
        }
    if active_schema["type"] == "array":
        return [tidy(item, active_schema["items"]) for item in value[:MAX_ITEMS]]
    return value if "enum" in active_schema else sanitize(value, MAX_FIELD_CHARS)


class LLMError(Exception):
    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class Provider:
    """An OpenAI-compatible chat completions endpoint."""

    name: str
    url: str
    key: str
    model: str


def providers_from_env(env: Mapping[str, str]) -> list[Provider]:
    """The configured providers, in the order they are tried."""
    known = (
        (
            "Gemini",
            "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
            "GEMINI_API_KEY",
            env.get("GEMINI_MODEL") or "gemini-3.8-flash",
        ),
        (
            "OpenRouter",
            "https://openrouter.ai/api/v1/chat/completions",
            "OPENROUTER_CI_KEY",
            env.get("OPENROUTER_MODEL") or "google/gemini-3.8-flash",
        ),
    )
    return [
        Provider(name, url, env[key], model) for name, url, key, model in known if env.get(key)
    ]


Post = Callable[[str, dict, dict], Any]


def http_post_json(url: str, payload: dict, headers: dict) -> Any:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT, **headers},
        method="POST",
    )
    try:
        return json.loads(read_url(request, timeout=180))
    except urllib.error.HTTPError as error:
        detail = " ".join(error.read().decode("utf-8", "replace")[:300].split())
        raise LLMError(f"HTTP {error.code}: {detail}", error.code) from error
    except (OSError, ValueError) as error:  # connection failures, timeouts, bad JSON
        raise LLMError(str(error)) from error


def ask(provider: Provider, system: str, user: str, post: Post) -> dict:
    """Get one analysis from a provider, validated and sanitized."""
    active_schema = build_analysis_schema()
    payload = {
        "model": provider.model,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    strict = {
        "type": "json_schema",
        "json_schema": {"name": "upgrade_analysis", "strict": True, "schema": active_schema},
    }
    # Not every provider and model accepts a schema here. The prompt spells the
    # schema out and the reply is validated below, so plain JSON mode is enough.
    for response_format in (strict, {"type": "json_object"}):
        try:
            reply = post(
                provider.url,
                {**payload, "response_format": response_format},
                {"Authorization": f"Bearer {provider.key}"},
            )
            break
        except LLMError as error:
            if error.status != 400 or response_format is not strict:
                raise
    try:
        content = reply["choices"][0]["message"]["content"]
        analysis = json.loads(re.sub(r"^```(?:json)?\s*|\s*```$", "", content.strip()))
    except (KeyError, IndexError, TypeError, AttributeError, ValueError) as error:
        raise LLMError(f"unusable reply: {error!r}") from error
    errors = schema_errors(analysis, active_schema)
    if errors:
        raise LLMError("reply does not match the schema: " + "; ".join(errors[:5]))
    return tidy(analysis, active_schema)


def analyse(
    providers: Iterable[Provider], system: str, user: str, post: Post
) -> tuple[dict | None, str, list[str]]:
    """Try each provider in turn. Returns the analysis, who wrote it, and failures."""
    failures = []
    for provider in providers:
        try:
            return ask(provider, system, user, post), f"{provider.name} {provider.model}", failures
        except LLMError as error:
            failures.append(f"{provider.name} ({provider.model}): {error}")
    return None, "", failures


def system_prompt() -> str:
    charms = "\n".join(
        f"- `{charm.key}`: {charm.repo}. {charm.description}" for charm in CHARMS
    )
    active_schema = build_analysis_schema()
    return render(
        "analysis_prompt.md.tmpl",
        {
            "WORKLOAD": WORKLOAD,
            "CHARMS": charms,
            "SCHEMA": json.dumps(active_schema, indent=2),
        },
    )


def user_prompt(
    path: UpgradePath,
    inputs: BuildInputs,
    notes: Mapping[Series, str],
    rockcraft: str,
    charm_files: Iterable[tuple[Charm, str, str]],
) -> str:
    """Everything the model may base its analysis on.

    Upstream text is wrapped in a tag with a random name, so nothing inside it can
    close the wrapper and pose as instructions.
    """
    tag = f"untrusted-{secrets.token_hex(8)}"

    def untrusted(source: str, text: str) -> str:
        return f'<{tag} source="{source}">\n{text}\n</{tag}>'

    facts = "\n".join(
        f"- {probe.label} ({probe.path}): {old or 'not found'} -> {new or 'not found'}"
        + ("" if old == new else "  [CHANGED]")
        for probe, old, new in inputs.facts
    )
    parts = [
        f"Third-party content is wrapped in <{tag}> tags. Only that exact tag closes it.",
        f"# Upgrade\n\n{WORKLOAD} {path.frm} -> {path.to} ({path.kind} bump)."
        + "".join(f"\n{line}" for line in path_facts(path)),
        f"# Build inputs\n\nRead from upstream's source at both tags.\n\n{facts}",
    ]
    if inputs.overrides:
        override_lines = []
        for ov in inputs.overrides:
            status_desc = {
                "satisfied": (
                    f"SATISFIED upstream ({ov.after} >= {ov.min_version}) — "
                    "can be removed from rockcraft.yaml"
                ),
                "removed": (
                    f"SATISFIED upstream ({ov.after} >= {ov.min_version}) — "
                    "already removed from rockcraft.yaml in this PR"
                ),
                "bumped": (
                    f"BUMPED upstream ({ov.before} -> {ov.after}) — "
                    "verify if override in rockcraft.yaml can be removed"
                ),
                "needed": (
                    f"STILL NEEDED (upstream is at {ov.after or 'not found'}, "
                    f"rockcraft.yaml pins {ov.min_version or 'latest'})"
                ),
            }[ov.status]
            override_lines.append(
                f"- {ov.package} ({ov.upstream_file}, `{ov.spec}`): "
                f"{ov.before or 'not found'} -> {ov.after or 'not found'} [{status_desc}]"
            )
        parts.append(
            "# Dependency overrides in rockcraft.yaml\n\n"
            "Manual CVE/dependency overrides found in rockcraft.yaml compared against "
            "upstream lockfiles:\n\n" + "\n".join(override_lines)
        )
    parts += [
        untrusted(f"diff of {name} between the tags", clip(diff, MAX_FILE_CHARS))
        for name, diff in inputs.diffs
    ]
    # A diff shows what moved, not what is still there, so the whole files go too.
    parts += [
        untrusted(f"{name} at {path.to}, complete", clip(text, MAX_FILE_CHARS))
        for name, text in inputs.files
    ]
    parts.append(f"# The rock's current rockcraft.yaml\n\n<rockcraft>\n{rockcraft}\n</rockcraft>")
    parts.append(
        f"# How the charms configure and run {WORKLOAD}\n\n"
        "Files from each charm's target branch."
    )
    parts += [
        f'<charm-file charm="{charm.key}" path="{name}">\n'
        f"{clip(text, MAX_FILE_CHARS)}\n</charm-file>"
        for charm, name, text in charm_files
    ]
    parts.append("# Upstream release notes absorbed by this upgrade")
    parts += [
        untrusted(f"{series_name(series)} release notes", text or "(none found)")
        for series, text in notes.items()
    ]
    return "\n\n".join(parts)


# Rendering


def path_facts(path: UpgradePath) -> list[str]:
    """Plain statements about where an upgrade sits among upstream's releases."""
    if not ENFORCE_SEQUENTIAL_SERIES:
        return []
    facts = []
    if path.skipped:
        names = ", ".join(series_name(series) for series in path.skipped)
        facts.append(
            f"This skips the {names} series. Upstream only supports upgrading one series "
            f"at a time, so deployments have to run a {names} release on the way."
        )
    if path.newer_patch:
        facts.append(
            f"The current series has a newer patch, {path.newer_patch}. Upstream asks for "
            "the latest patch of a series to be deployed before moving to the next one."
        )
    return facts


def apply_path_floor(analysis: dict, path: UpgradePath) -> dict:
    """Skipping a series is high risk when sequential series upgrades are required."""
    if not ENFORCE_SEQUENTIAL_SERIES or not path.skipped:
        return analysis
    names = ", ".join(series_name(series) for series in path.skipped)
    driver = {
        "title": f"Skips the {names} series",
        "detail": "Upstream only supports upgrading one release series at a time.",
        "source": "upstream tags",
    }
    risk = analysis["risk"]
    return {**analysis, "risk": {**risk, "level": "high", "drivers": [driver, *risk["drivers"]]}}


def upstream_links(path: UpgradePath) -> str:
    base = f"https://github.com/{UPSTREAM_REPO}"
    links = [f"[release {path.to}]({base}/releases/tag/{TAG_PREFIX}{path.to})"]
    if RELEASE_NOTES_PATH:
        links += [
            f"[{series_name(series)} release notes]({base}/blob/main/{notes_path(series)})"
            for series in path.absorbed_series
        ]
    links.append(f"[source diff]({base}/compare/{TAG_PREFIX}{path.frm}...{TAG_PREFIX}{path.to})")
    return ", ".join(links)


def _bullets(items: Iterable[dict], *, checkbox: bool = False) -> str:
    mark = "- [ ]" if checkbox else "-"
    return "\n".join(f"{mark} **{item['title']}**: {item['detail']}" for item in items)


def _for_charm(items: Iterable[dict], charm: Charm) -> list[dict]:
    return [item for item in items if item["applies_to"] in (charm.key, "both", "all")]


ALERTS = {"low": "NOTE", "medium": "WARNING", "high": "CAUTION"}


def render_pr_comment(
    path: UpgradePath,
    inputs: BuildInputs,
    analysis: dict | None,
    model: str,
    llm_note: str,
) -> str:
    if analysis:
        risk = analysis["risk"]
        risk_block = (
            f"> [!{ALERTS[risk['level']]}]\n"
            f"> **Upgrade risk: {risk['level']}** (AI). {risk['summary']}\n\n"
            + "\n".join(
                f"- **{d['title']}**: {d['detail']} _({d['source']})_" for d in risk["drivers"]
            )
        )
    else:
        risk_block = (
            "> [!WARNING]\n"
            f"> **Upgrade risk: not assessed.** {llm_note} The upgrade path and build "
            "inputs below are read from upstream's source and do not depend on it."
        )

    if path.kind == "patch":
        path_block = f"Patch bump within the {series_name(path.to.series)} series."
    else:
        path_block = (
            f"Series bump from {series_name(path.frm.series)} to {series_name(path.to.series)}."
        )
    path_block += "".join(f"\n\n> [!WARNING]\n> {fact}" for fact in path_facts(path))

    rows = [f"| Input | Upstream file | {path.frm} | {path.to} |", "|---|---|---|---|"]
    for probe, old, new in inputs.facts:
        label = probe.label if old == new else f"**{probe.label}**"
        rows.append(f"| {label} | `{probe.path}` | {code(old or '-')} | {code(new or '-')} |")
    build_block = (
        "The rock's recipe has to match these. Rows in bold changed.\n\n" + "\n".join(rows)
    )
    for name, diff in inputs.diffs:
        body = clip(diff, 8_000).replace("````", "` ` ` `")
        build_block += (
            f"\n\n<details><summary>Diff of <code>{name}</code></summary>\n\n"
            f"````diff\n{body}\n````\n\n</details>"
        )
    if inputs.overrides:
        ov_rows = [
            f"| Package | Upstream file | `rockcraft.yaml` override | {path.frm} | {path.to} | Status |",
            "|---|---|---|---|---|---|",
        ]
        status_labels = {
            "satisfied": "**Satisfied upstream (can remove)**",
            "removed": "**Satisfied upstream (removed)**",
            "bumped": "**Bumped upstream (check if removable)**",
            "needed": "Still needed",
        }
        for ov in inputs.overrides:
            pkg_cell = (
                f"**{code(ov.package)}**" if ov.status != "needed" else code(ov.package)
            )
            ov_rows.append(
                f"| {pkg_cell} | `{ov.upstream_file}` | {code(ov.spec)} "
                f"| {code(ov.before or '-')} | {code(ov.after or '-')} "
                f"| {status_labels[ov.status]} |"
            )
        build_block += (
            "\n\n### Dependency overrides in `rockcraft.yaml`\n\n"
            "Manual CVE/dependency overrides compared against upstream lockfiles.\n\n"
            + "\n".join(ov_rows)
        )
    if not inputs.changed:
        build_block += "\n\nNone of them changed."

    rock_block = charm_block = ""
    footer = f"Sources: {upstream_links(path)}."
    if analysis:
        rock = analysis["rock"]
        rock_block = "### Changes needed in `rockcraft.yaml` (AI)\n\n" + rock["summary"]
        if rock["changes"]:
            rock_block += "\n\n" + _bullets(rock["changes"])

        repos = " and ".join(f"[{c.repo}](https://github.com/{c.repo})" for c in CHARMS)
        follow_up = (
            "Nothing is filed on the charms automatically. When they are ready to move, "
            f"run the `{CHARM_ISSUES_WORKFLOW}` workflow to open an upgrade issue on "
            f"{repos} for the versions involved."
        )
        charm_block = f"### Charm impact (AI)\n\n{analysis['charm']['summary']}\n\n{follow_up}"
        for charm in CHARMS:
            checks = _for_charm(analysis["charm"]["validation"], charm)
            if checks:
                titles = "\n".join(f"- {check['title']}" for check in checks)
                charm_block += (
                    f"\n\n<details><summary>Validation needed on {charm.app or charm.key} "
                    f"({len(checks)})</summary>\n\n{titles}\n\n</details>"
                )
        footer += (
            f" Sections marked AI were written by {model} from those sources and the "
            "build inputs above; check them against the sources before relying on them."
        )

    return render(
        "pr_comment.md.tmpl",
        {
            "WORKLOAD": WORKLOAD,
            "FROM": str(path.frm),
            "TO": str(path.to),
            "RISK": risk_block,
            "UPGRADE_PATH": path_block,
            "BUILD_INPUTS": build_block,
            "ROCK": rock_block,
            "CHARMS": charm_block,
            "FOOTER": footer,
        },
    )


def charm_issue_title(path: UpgradePath) -> str:
    return f"Upgrade to {WORKLOAD} {path.to}"


def render_charm_issue(
    charm: Charm, path: UpgradePath, analysis: dict, model: str, image: str
) -> str:
    risk = analysis["risk"]
    changes = _for_charm(analysis["charm"]["changes"], charm)
    checks = _for_charm(analysis["charm"]["validation"], charm)
    validation = "\n\n".join(
        f"### {number}. {check['title']}\n\n"
        f"- **Why**: {check['why']}\n"
        f"- **How**: {check['how']}\n"
        f"- **Expected**: {check['expected']}\n"
        "- [ ] Validated"
        for number, check in enumerate(checks, 1)
    )
    in_place_values = {
        "WORKLOAD": WORKLOAD,
        "FROM": str(path.frm),
        "TO": str(path.to),
        "APP": charm.app,
        "CONTAINER": charm.container,
        "SERVICE": charm.service,
        "RESOURCE": charm.resource,
        "IMAGE": image,
    }
    in_place_text = render_inline(
        charm.in_place_upgrade or DEFAULT_IN_PLACE_UPGRADE, in_place_values
    )
    return render(
        "charm_issue.md.tmpl",
        {
            **in_place_values,
            "MODEL": model,
            "WORKFLOW": CHARM_ISSUES_WORKFLOW,
            "SOURCES": upstream_links(path),
            "RISK_LEVEL": risk["level"],
            "RISK_SUMMARY": risk["summary"],
            "RISK_DRIVERS": "\n".join(
                f"- **{d['title']}**: {d['detail']} _({d['source']})_" for d in risk["drivers"]
            ),
            "UPGRADE_PATH": "".join(f"> [!WARNING]\n> {fact}\n\n" for fact in path_facts(path)),
            "CHARM_SUMMARY": analysis["charm"]["summary"],
            "CHARM_CHANGES": _bullets(changes, checkbox=True),
            "VALIDATION": validation
            or "The analysis found nothing specific to this charm beyond the baseline below.",
            "IN_PLACE_UPGRADE": in_place_text,
        },
    )


# Command line


def write_outputs(values: Mapping[str, str]) -> None:
    """Expose results to later workflow steps."""
    for name, value in values.items():
        print(f"{name}={value}")
    if output_file := os.environ.get("GITHUB_OUTPUT"):
        with open(output_file, "a", encoding="utf-8") as handle:
            handle.writelines(f"{name}={value}\n" for name, value in values.items())


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help=f"per-repository configuration file (default: {DEFAULT_CONFIG_PATH})",
    )
    source = parser.add_mutually_exclusive_group(required=False)
    source.add_argument(
        "--from",
        dest="frm",
        help="version the rock builds today (default: read from charmcraft.yaml on --target-branch)",
    )
    source.add_argument(
        "--from-rockcraft", type=Path, help="rockcraft.yaml to read that version from"
    )
    parser.add_argument("--to", help="version the rock moves to (default: --rockcraft's)")
    parser.add_argument(
        "--target-branch",
        default=DEFAULT_CHARM_BRANCH,
        help=f"branch in the charm repositories to read charm files from (default: {DEFAULT_CHARM_BRANCH})",
    )
    parser.add_argument(
        "--rockcraft",
        type=Path,
        default=Path("rockcraft.yaml"),
        help="the rock's recipe, shown to the LLM (default: rockcraft.yaml)",
    )
    parser.add_argument(
        "--prune-overrides",
        action="store_true",
        help="remove satisfied dependency overrides from --rockcraft in place",
    )
    parser.add_argument("--image", help="published image (default: <rock_image>:<to>)")
    parser.add_argument("--out-dir", type=Path, default=Path(".artifacts"))
    parser.add_argument(
        "--require-llm", action="store_true", help="fail when the LLM analysis is unavailable"
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    global CHARMS
    args = parse_args(argv)
    configure_from_files(args.config, args.rockcraft)

    def fetch_charm(charm: Charm, path: str) -> str | None:
        return charm_file(charm, path, branch=args.target_branch)

    # Enrich charms from their charmcraft.yaml when app/container/resource are not explicitly set.
    enriched_charms: list[Charm] = []
    for charm in CHARMS:
        if not charm.app or not charm.container:
            cc_text = fetch_charm(charm, "charmcraft.yaml")
            if cc_text:
                charm = enrich_charm_from_charmcraft(charm, cc_text, ROCK_IMAGE)
        enriched_charms.append(charm)
    CHARMS = tuple(enriched_charms)

    if args.frm:
        frm = Version.parse(args.frm)
    elif args.from_rockcraft:
        frm = rockcraft_version(args.from_rockcraft)
    else:
        try:
            frm = resolve_from_version(CHARMS, fetch_charm, image=ROCK_IMAGE)
        except ValueError as error:
            print(f"error: {error}", file=sys.stderr)
            return 1

    to = Version.parse(args.to) if args.to else rockcraft_version(args.rockcraft)
    if to <= frm:
        print(f"Nothing to assess: {frm} -> {to} is not an upgrade.")
        write_outputs({"changed": "false"})
        return 0

    released = list_released_versions()
    for version in (frm, to):
        if version not in released:
            print(f"error: {version} is not a release of {UPSTREAM_REPO}", file=sys.stderr)
            return 1
    path = plan_upgrade(frm, to, released)
    rockcraft_text = (
        args.rockcraft.read_text(encoding="utf-8") if args.rockcraft.exists() else ""
    )
    base_rockcraft_text = (
        args.from_rockcraft.read_text(encoding="utf-8")
        if args.from_rockcraft and args.from_rockcraft.exists()
        else None
    )
    inputs = compare_build_inputs(
        frm, to, upstream_file, rockcraft_text, base_rockcraft_text
    )

    pruned_list: list[DependencyOverride] = []
    if args.prune_overrides and rockcraft_text:
        rockcraft_text, pruned_list = prune_rockcraft_overrides(
            rockcraft_text, inputs.overrides
        )
        if pruned_list:
            args.rockcraft.write_text(rockcraft_text, encoding="utf-8")
            pruned_set = set(pruned_list)
            updated_overrides = tuple(
                DependencyOverride(
                    ecosystem=ov.ecosystem,
                    package=ov.package,
                    spec=ov.spec,
                    min_version=ov.min_version,
                    upstream_file=ov.upstream_file,
                    before=ov.before,
                    after=ov.after,
                    status="removed" if ov in pruned_set else ov.status,
                )
                for ov in inputs.overrides
            )
            inputs = BuildInputs(
                inputs.facts, inputs.diffs, inputs.files, updated_overrides
            )

    if RELEASE_NOTES_PATH:
        notes = {
            series: relevant_notes(release_notes(series) or "", path)
            for series in path.absorbed_series
        }
    else:
        notes = github_release_notes(frm, to, released)

    providers = providers_from_env(os.environ)
    analysis, model, failures = None, "", []
    if providers:
        prompt = user_prompt(
            path,
            inputs,
            notes,
            rockcraft_text,
            read_charm_files(fetch_charm, CHARMS),
        )
        analysis, model, failures = analyse(providers, system_prompt(), prompt, http_post_json)
    for failure in failures:
        print(f"::warning::LLM analysis failed with {failure}")
    if analysis:
        analysis = apply_path_floor(analysis, path)
        llm_note = ""
    elif not providers:
        llm_note = "No LLM API key is configured."
    else:
        llm_note = "The LLM analysis failed; see the workflow log."
    if not analysis and args.require_llm:
        print(f"error: {llm_note}", file=sys.stderr)
        return 1

    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "pr_comment.md").write_text(
        render_pr_comment(path, inputs, analysis, model, llm_note), encoding="utf-8"
    )
    issues = []
    if analysis:
        (args.out_dir / "analysis.json").write_text(
            json.dumps(analysis, indent=2) + "\n", encoding="utf-8"
        )
        image = args.image or f"{ROCK_IMAGE}:{to}"
        for charm in CHARMS:
            body_file = args.out_dir / f"charm_issue_{charm.key}.md"
            body_file.write_text(
                render_charm_issue(charm, path, analysis, model, image), encoding="utf-8"
            )
            issues.append(
                {"repo": charm.repo, "title": charm_issue_title(path), "body_file": str(body_file)}
            )
    (args.out_dir / "charm_issues.json").write_text(
        json.dumps(issues, indent=2) + "\n", encoding="utf-8"
    )

    write_outputs(
        {
            "changed": "true",
            "from": str(frm),
            "to": str(to),
            "kind": path.kind,
            "risk": analysis["risk"]["level"] if analysis else "",
            "pruned": "true" if pruned_list else "false",
        }
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
