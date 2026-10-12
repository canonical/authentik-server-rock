#!/usr/bin/env python3
"""Assess an upstream authentik upgrade for this rock and the charms that run it.

Given the version the rock builds today and the version it is moving to, this:

1. works out the upgrade path from upstream's tags (patch or series bump, skipped
   series),
2. compares the upstream files the rock's build depends on between the two tags,
3. collects the release notes of every release the upgrade absorbs,
4. asks an LLM to judge the risk and to plan what the charms must validate, and
5. renders a pull request comment and one issue body per charm.

Steps 1-3 are deterministic and always run. Step 4 is skipped when no API key is
configured, unless --require-llm is given. Only the standard library is used, so the
workflows need no install step.
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
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

# What this rock tracks. These are the parts to turn into inputs when the tooling
# moves to a shared workflow.

UPSTREAM_REPO = "goauthentik/authentik"
TAG_PREFIX = "version/"
RELEASE_NOTES_PATH = "website/docs/releases/{year}/v{year}.{minor}.mdx"
ROCK_IMAGE = "ghcr.io/canonical/authentik-server"

TEMPLATES = Path(__file__).resolve().parent.parent / "templates"
USER_AGENT = "authentik-server-rock-upstream-upgrade"

Series = tuple[int, int]
VERSION_RE = re.compile(r"(\d{4})\.(\d{1,2})\.(\d+)")


@dataclass(frozen=True, order=True)
class Version:
    """An upstream release such as 2026.8.3; 2026.8 is its release series."""

    year: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, text: str) -> Version:
        match = VERSION_RE.fullmatch(text.strip())
        if not match:
            raise ValueError(f"not an authentik release version: {text!r}")
        return cls(*map(int, match.groups()))

    @property
    def series(self) -> Series:
        return (self.year, self.minor)

    def __str__(self) -> str:
        return f"{self.year}.{self.minor}.{self.patch}"


def series_name(series: Series) -> str:
    return f"{series[0]}.{series[1]}"


@dataclass(frozen=True)
class Charm:
    """A charm that deploys this rock and gets an issue when the rock moves."""

    key: str  # how the analysis refers to it in `applies_to`
    repo: str
    app: str
    container: str
    service: str
    description: str  # what the LLM is told about it


CHARMS = (
    Charm(
        key="server",
        repo="canonical/authentik-server-operator",
        app="authentik-server",
        container="authentik",
        service="authentik-server",
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
    ),
    Charm(
        key="worker",
        repo="canonical/authentik-worker-operator",
        app="authentik-worker",
        container="authentik",
        service="authentik-worker",
        description=(
            "Kubernetes charm running `/lifecycle/ak worker` (metrics 9300) from the same "
            "image. It receives AUTHENTIK_SECRET_KEY and the PostgreSQL settings from the "
            "server charm over `authentik-cluster` and sets AUTHENTIK_* environment "
            "variables in its Pebble layer."
        ),
    ),
)


# Upstream access


def http_get(url: str) -> str | None:
    """Return the body at a URL, or None when it does not exist."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


@lru_cache(maxsize=None)
def upstream_file(version: Version, path: str) -> str | None:
    """A file from upstream's source tree as it was at a release."""
    return http_get(
        f"https://raw.githubusercontent.com/{UPSTREAM_REPO}/{TAG_PREFIX}{version}/{path}"
    )


def notes_path(series: Series) -> str:
    return RELEASE_NOTES_PATH.format(year=series[0], minor=series[1])


def release_notes(series: Series) -> str | None:
    """The release notes page of a series. Upstream keeps amending it on main."""
    return http_get(
        f"https://raw.githubusercontent.com/{UPSTREAM_REPO}/main/{notes_path(series)}"
    )


def list_released_versions() -> list[Version]:
    """Every final release upstream has tagged."""
    output = subprocess.run(
        [
            "git",
            "ls-remote",
            "--tags",
            "--refs",
            f"https://github.com/{UPSTREAM_REPO}",
            f"refs/tags/{TAG_PREFIX}*",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
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

    Upstream supports moving one series at a time, from the latest patch of the
    current series, so both deviations are recorded.
    """
    released = list(released)
    skipped = sorted({v.series for v in released if frm.series < v.series < to.series})
    newer_patch = None
    if frm.series != to.series:
        latest = max((v for v in released if v.series == frm.series), default=frm)
        newer_patch = latest if latest > frm else None
    return UpgradePath(frm, to, tuple(skipped), newer_patch)


# Release notes

FIXED_IN_RE = re.compile(r"Fixed in (\d{4}\.\d{1,2}\.\d+)", re.IGNORECASE)
# Long sections that say nothing about how authentik is built, configured or run.
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
DIFFED_FILES = ("lifecycle/container/Dockerfile", "lifecycle/ak")

Fetch = Callable[[Version, str], "str | None"]


@dataclass(frozen=True)
class BuildInputs:
    facts: tuple[tuple[Probe, str | None, str | None], ...]  # probe, before, after
    diffs: tuple[tuple[str, str], ...]  # path and unified diff of each changed file

    @property
    def changed(self) -> bool:
        return bool(self.diffs) or any(old != new for _, old, new in self.facts)


def compare_build_inputs(frm: Version, to: Version, fetch: Fetch) -> BuildInputs:
    def read(probe: Probe, version: Version) -> str | None:
        text = fetch(version, probe.path)
        if text is None:
            return None
        try:
            return probe.read(text)
        except ValueError:  # the file is not what the probe expects, e.g. broken JSON
            return None

    facts = tuple((probe, read(probe, frm), read(probe, to)) for probe in PROBES)
    diffs = []
    for path in DIFFED_FILES:
        old, new = fetch(frm, path), fetch(to, path)
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
    return BuildInputs(facts, tuple(diffs))


# Text handling

ZERO_WIDTH_SPACE = "​"
URL_RE = re.compile(r"https?://[^\s<>()\[\]\"'`]+")
TRUSTED_LINK_HOSTS = ("goauthentik.io", "docs.goauthentik.io")


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
    line = re.sub(r"@(?=\w)", "@" + ZERO_WIDTH_SPACE, line)
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
    text = (TEMPLATES / template).read_text(encoding="utf-8")
    filled = PLACEHOLDER_RE.sub(lambda match: values[match.group(1)], text)
    return re.sub(r"\n{3,}", "\n\n", filled).strip() + "\n"


# LLM analysis

RISK_LEVELS = ("low", "medium", "high")
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
_APPLIES_TO = {"type": "string", "enum": [*(charm.key for charm in CHARMS), "both"]}

ANALYSIS_SCHEMA = _object(
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
        changes=_array(_object(applies_to=_APPLIES_TO, title=_TEXT, detail=_TEXT)),
        validation=_array(
            _object(applies_to=_APPLIES_TO, title=_TEXT, why=_TEXT, how=_TEXT, expected=_TEXT)
        ),
    ),
)


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


def tidy(value: Any, schema: dict = ANALYSIS_SCHEMA) -> Any:
    """Sanitize every free-text field of a valid analysis and bound its lists."""
    if schema["type"] == "object":
        return {key: tidy(value[key], sub) for key, sub in schema["properties"].items()}
    if schema["type"] == "array":
        return [tidy(item, schema["items"]) for item in value[:MAX_ITEMS]]
    return value if "enum" in schema else sanitize(value, MAX_FIELD_CHARS)


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
            "OPENROUTER_API_KEY",
            env.get("OPENROUTER_MODEL") or "google/gemini-3.8-flash",
        ),
    )
    return [
        Provider(name, url, env[key], model) for name, url, key, model in known if env.get(key)
    ]


TRANSIENT_STATUSES = (408, 429, 500, 502, 503, 504)
Post = Callable[[str, dict, dict], Any]


def http_post_json(url: str, payload: dict, headers: dict, attempts: int = 3) -> Any:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT, **headers},
        method="POST",
    )
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(request, timeout=180) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as error:
            detail = " ".join(error.read().decode("utf-8", "replace")[:300].split())
            failure = LLMError(f"HTTP {error.code}: {detail}", error.code)
            if error.code not in TRANSIENT_STATUSES:
                break
        except (OSError, ValueError) as error:  # connection failures, timeouts, bad JSON
            failure = LLMError(str(error))
        if attempt < attempts:
            time.sleep(5 * attempt)
    raise failure


def ask(provider: Provider, system: str, user: str, post: Post) -> dict:
    """Get one analysis from a provider, validated and sanitized."""
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
        "json_schema": {"name": "upgrade_analysis", "strict": True, "schema": ANALYSIS_SCHEMA},
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
    errors = schema_errors(analysis, ANALYSIS_SCHEMA)
    if errors:
        raise LLMError("reply does not match the schema: " + "; ".join(errors[:5]))
    return tidy(analysis)


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
    return render(
        "analysis_prompt.md.tmpl",
        {"CHARMS": charms, "SCHEMA": json.dumps(ANALYSIS_SCHEMA, indent=2)},
    )


def user_prompt(
    path: UpgradePath, inputs: BuildInputs, notes: Mapping[Series, str], rockcraft: str
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
        f"# Upgrade\n\nauthentik {path.frm} -> {path.to} ({path.kind} bump)."
        + "".join(f"\n{line}" for line in path_facts(path)),
        f"# Build inputs\n\nRead from upstream's source at both tags.\n\n{facts}",
    ]
    parts += [
        untrusted(f"diff of {name} between the tags", clip(diff, 30_000))
        for name, diff in inputs.diffs
    ]
    parts.append(f"# The rock's current rockcraft.yaml\n\n<rockcraft>\n{rockcraft}\n</rockcraft>")
    parts.append("# Upstream release notes absorbed by this upgrade")
    parts += [
        untrusted(f"{series_name(series)} release notes", text or "(none found)")
        for series, text in notes.items()
    ]
    return "\n\n".join(parts)


# Rendering


def path_facts(path: UpgradePath) -> list[str]:
    """Plain statements about where an upgrade sits among upstream's releases."""
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
    """Skipping a series is high risk whatever the model made of the notes."""
    if not path.skipped:
        return analysis
    names = ", ".join(series_name(series) for series in path.skipped)
    driver = {
        "title": f"Skips the {names} series",
        "detail": "Upstream only supports upgrading one release series at a time.",
        "source": "upstream tags",
    }
    risk = analysis["risk"]
    return {**analysis, "risk": {**risk, "level": "high", "drivers": [driver, *risk["drivers"]]}}


def opens_charm_issues(path: UpgradePath, analysis: dict) -> bool:
    """A series bump always needs charm work; a patch bump only when it is risky."""
    return path.kind == "series" or analysis["risk"]["level"] != "low"


def upstream_links(path: UpgradePath) -> str:
    base = f"https://github.com/{UPSTREAM_REPO}"
    links = [f"[release {path.to}]({base}/releases/tag/{TAG_PREFIX}{path.to})"]
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
    return [item for item in items if item["applies_to"] in (charm.key, "both")]


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
        if opens_charm_issues(path, analysis):
            follow_up = (
                f"Upgrade issues are opened on {repos} once this is merged and the "
                "image is published."
            )
        else:
            follow_up = "No charm issues are opened for a low-risk patch bump."
        charm_block = f"### Charm impact (AI)\n\n{analysis['charm']['summary']}\n\n{follow_up}"
        for charm in CHARMS:
            checks = _for_charm(analysis["charm"]["validation"], charm)
            if checks:
                titles = "\n".join(f"- {check['title']}" for check in checks)
                charm_block += (
                    f"\n\n<details><summary>Validation planned for {charm.app} "
                    f"({len(checks)})</summary>\n\n{titles}\n\n</details>"
                )
        footer += (
            f" Sections marked AI were written by {model} from those sources and the "
            "build inputs above; check them against the sources before relying on them."
        )

    return render(
        "pr_comment.md.tmpl",
        {
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
    return f"Upgrade to authentik {path.to}"


def render_charm_issue(
    charm: Charm, path: UpgradePath, analysis: dict, model: str, image: str, rock_change: str
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
    return render(
        "charm_issue.md.tmpl",
        {
            "FROM": str(path.frm),
            "TO": str(path.to),
            "APP": charm.app,
            "CONTAINER": charm.container,
            "SERVICE": charm.service,
            "IMAGE": image,
            "MODEL": model,
            "ROCK_CHANGE": rock_change or "not recorded",
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
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--from", dest="frm", help="version the rock builds today")
    source.add_argument(
        "--from-rockcraft", type=Path, help="rockcraft.yaml to read that version from"
    )
    parser.add_argument("--to", help="version the rock moves to (default: --rockcraft's)")
    parser.add_argument(
        "--rockcraft",
        type=Path,
        default=Path("rockcraft.yaml"),
        help="the rock's recipe, shown to the LLM (default: rockcraft.yaml)",
    )
    parser.add_argument("--image", help=f"published image (default: {ROCK_IMAGE}:<to>)")
    parser.add_argument("--rock-change", default="", help="URL of the change that bumped the rock")
    parser.add_argument("--out-dir", type=Path, default=Path(".artifacts"))
    parser.add_argument(
        "--require-llm", action="store_true", help="fail when the LLM analysis is unavailable"
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    frm = Version.parse(args.frm) if args.frm else rockcraft_version(args.from_rockcraft)
    to = Version.parse(args.to) if args.to else rockcraft_version(args.rockcraft)
    if to <= frm:
        print(f"Nothing to assess: {frm} -> {to} is not an upgrade.")
        write_outputs({"changed": "false", "open_charm_issues": "false"})
        return 0

    released = list_released_versions()
    for version in (frm, to):
        if version not in released:
            print(f"error: {version} is not a release of {UPSTREAM_REPO}", file=sys.stderr)
            return 1
    path = plan_upgrade(frm, to, released)
    inputs = compare_build_inputs(frm, to, upstream_file)
    notes = {
        series: relevant_notes(release_notes(series) or "", path)
        for series in path.absorbed_series
    }

    providers = providers_from_env(os.environ)
    analysis, model, failures = analyse(
        providers,
        system_prompt(),
        user_prompt(path, inputs, notes, args.rockcraft.read_text(encoding="utf-8")),
        http_post_json,
    )
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
                render_charm_issue(charm, path, analysis, model, image, args.rock_change),
                encoding="utf-8",
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
            "open_charm_issues": str(bool(analysis) and opens_charm_issues(path, analysis)).lower(),
        }
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
