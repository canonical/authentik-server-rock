#!/usr/bin/env python3
"""Check upstream Authentik releases, analyze breaking changes with Gemini,
update rockcraft.yaml, and generate agent-ready issue specifications for charms.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

UPSTREAM_REPO = "goauthentik/authentik"
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.8-flash")
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
GEMINI_OPENAI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai/"
OPENROUTER_MODEL = os.environ.get("OPENROUTER_MODEL", "google/gemini-3.8-flash")
OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"

GEMINI_RESPONSE_SCHEMA: Dict[str, Any] = {
    "type": "OBJECT",
    "properties": {
        "has_breaking_changes": {"type": "BOOLEAN"},
        "severity": {"type": "STRING", "enum": ["none", "low", "medium", "high"]},
        "breaking_changes_summary": {"type": "STRING"},
        "highlights": {
            "type": "ARRAY",
            "items": {"type": "STRING"}
        },
        "rock_impact": {
            "type": "OBJECT",
            "properties": {
                "summary": {"type": "STRING"},
                "action_items": {
                    "type": "ARRAY",
                    "items": {"type": "STRING"}
                }
            },
            "required": ["summary", "action_items"]
        },
        "charm_impact": {
            "type": "OBJECT",
            "properties": {
                "summary": {"type": "STRING"},
                "affected_components": {
                    "type": "ARRAY",
                    "items": {"type": "STRING"}
                },
                "action_items": {
                    "type": "ARRAY",
                    "items": {"type": "STRING"}
                }
            },
            "required": ["summary", "affected_components", "action_items"]
        },
        "testing_and_verification_matrix": {
            "type": "OBJECT",
            "properties": {
                "automated_tests": {
                    "type": "ARRAY",
                    "items": {"type": "STRING"}
                },
                "in_cluster_checks": {
                    "type": "ARRAY",
                    "items": {"type": "STRING"}
                },
                "regression_probes": {
                    "type": "ARRAY",
                    "items": {"type": "STRING"}
                }
            },
            "required": ["automated_tests", "in_cluster_checks", "regression_probes"]
        },
        "definition_of_done": {
            "type": "ARRAY",
            "items": {"type": "STRING"}
        }
    },
    "required": [
        "has_breaking_changes",
        "severity",
        "breaking_changes_summary",
        "highlights",
        "rock_impact",
        "charm_impact",
        "testing_and_verification_matrix",
        "definition_of_done"
    ]
}


def parse_version_tuple(version_str: str) -> Tuple[int, ...]:
    """Parse version string like '2026.8.3' or 'version/2026.8.3' into a tuple of ints."""
    clean = re.sub(r"^(version/|v)", "", version_str.strip())
    parts = []
    for part in clean.split("."):
        match = re.match(r"^(\d+)", part)
        if match:
            parts.append(int(match.group(1)))
        else:
            parts.append(0)
    return tuple(parts)


def is_multi_minor_jump(
    current_ver: str,
    new_ver: str,
    releases: Optional[List[Dict[str, Any]]] = None,
) -> bool:
    """Return True if jumping more than one minor release (e.g. 2026.5 to 2026.8+).
    
    Authentik uses CalVer (YEAR.MINOR.PATCH, e.g. 2026.5.3). Upstream documentation
    mandates sequential upgrades across minor versions to execute database migrations.
    """
    c_parts = parse_version_tuple(current_ver)
    n_parts = parse_version_tuple(new_ver)
    if len(c_parts) < 2 or len(n_parts) < 2:
        return False

    c_m = (c_parts[0], c_parts[1])
    n_m = (n_parts[0], n_parts[1])
    if n_m <= c_m:
        return False

    if releases:
        known_minors = set()
        for r in releases:
            tag = r.get("tag_name", "")
            clean = re.sub(r"^(version/|v)", "", tag)
            t = parse_version_tuple(clean)
            if len(t) >= 2:
                known_minors.add((t[0], t[1]))
        intermediate = [m for m in known_minors if c_m < m < n_m]
        return len(intermediate) > 0

    c_year, c_minor = c_parts[0], c_parts[1]
    n_year, n_minor = n_parts[0], n_parts[1]
    if n_year > c_year:
        return True
    if n_year == c_year and (n_minor - c_minor) > 1:
        return True
    return False


def read_current_version(rockcraft_path: Path) -> str:
    """Read the current version from rockcraft.yaml."""
    content = rockcraft_path.read_text(encoding="utf-8")
    match = re.search(r'^version:\s*["\']?([^"\'\s]+)["\']?', content, flags=re.MULTILINE)
    if not match:
        raise ValueError(f"Could not find 'version:' field in {rockcraft_path}")
    return match.group(1)


def fetch_json(url: str, token: Optional[str] = None) -> Any:
    """Fetch JSON from a URL with optional Bearer/Token auth."""
    headers = {
        "User-Agent": "authentik-rock-upstream-checker",
        "Accept": "application/vnd.github+json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_text(url: str) -> Optional[str]:
    """Fetch plain text / markdown from a URL, returning None if 404."""
    req = urllib.request.Request(url, headers={"User-Agent": "authentik-rock-upstream-checker"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def get_latest_upstream_release(token: Optional[str] = None) -> Dict[str, Any]:
    """Get the latest non-prerelease from goauthentik/authentik."""
    url = f"https://api.github.com/repos/{UPSTREAM_REPO}/releases/latest"
    return fetch_json(url, token=token)


def fetch_all_upstream_releases(token: Optional[str] = None) -> List[Dict[str, Any]]:
    """Fetch releases from upstream repository, excluding drafts and prereleases."""
    url = f"https://api.github.com/repos/{UPSTREAM_REPO}/releases?per_page=100"
    try:
        releases = fetch_json(url, token=token)
        if isinstance(releases, list):
            return [r for r in releases if not r.get("prerelease") and not r.get("draft")]
    except Exception as e:
        print(f"Warning: Failed to fetch release list from upstream: {e}")
    return []


def select_target_release(
    current_ver: str,
    releases: List[Dict[str, Any]],
    strategy: str = "next-minor"
) -> Optional[Dict[str, Any]]:
    """Select the target release based on strategy ('next-minor' or 'latest').
    
    - 'next-minor' (default):
      1. If newer patch releases exist in the current minor series (e.g. 2026.5.3 -> 2026.5.7),
         picks the latest patch of the current minor.
      2. If already on the latest patch of the current minor series, picks the latest patch
         of the immediate next minor series (e.g. 2026.5.7 -> 2026.8.3).
      This prevents skipping minor versions, ensuring safe sequential PostgreSQL schema migrations.
    - 'latest':
      Picks the absolute latest release.
    """
    current_tuple = parse_version_tuple(current_ver)
    
    parsed_releases = []
    for r in releases:
        tag = r.get("tag_name", "")
        clean_tag = re.sub(r"^(version/|v)", "", tag)
        t = parse_version_tuple(clean_tag)
        if len(t) >= 2:
            parsed_releases.append((t, r))
            
    parsed_releases.sort(key=lambda x: x[0])
    newer = [pr for pr in parsed_releases if pr[0] > current_tuple]
    if not newer:
        return None
        
    if strategy == "latest":
        return newer[-1][1]
        
    # 'next-minor': check for newer patches in the same minor series first
    same_minor = [
        pr for pr in newer
        if len(pr[0]) >= 2 and len(current_tuple) >= 2
        and pr[0][0] == current_tuple[0] and pr[0][1] == current_tuple[1]
    ]
    if same_minor:
        return same_minor[-1][1]
        
    # Advance to the earliest next minor series and select its highest patch
    next_minor_key = min((pr[0][0], pr[0][1]) for pr in newer)
    next_minor_releases = [pr for pr in newer if (pr[0][0], pr[0][1]) == next_minor_key]
    return next_minor_releases[-1][1]


def get_upstream_release_by_tag(tag: str, token: Optional[str] = None) -> Dict[str, Any]:
    """Get release data for a specific tag."""
    url = f"https://api.github.com/repos/{UPSTREAM_REPO}/releases/tags/{tag}"
    return fetch_json(url, token=token)


def check_existing_pr(
    repo: str = "canonical/authentik-server-rock",
    branch: str = "",
    token: Optional[str] = None
) -> Optional[str]:
    """Check if a PR already exists for the given branch on GitHub (open, merged, or closed)."""
    if not branch or not repo:
        return None
    owner = repo.split("/")[0] if "/" in repo else "canonical"
    url = f"https://api.github.com/repos/{repo}/pulls?head={owner}:{branch}&state=all"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "authentik-rock-release-checker"
    }
    req = urllib.request.Request(url, headers=headers)
    if token:
        req.add_header("Authorization", f"token {token}")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if isinstance(data, list) and len(data) > 0:
                return data[0].get("html_url")
    except Exception:
        pass
    try:
        import subprocess
        cmd = ["gh", "pr", "list", "--repo", repo, "--head", branch, "--state", "all", "--json", "url", "-q", ".[0].url"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        url_out = res.stdout.strip()
        if url_out:
            return url_out
    except Exception:
        pass
    return None


def fetch_upstream_docs_release_notes(version_clean: str) -> Optional[str]:
    """Fetch raw documentation markdown (.mdx) for this release series."""
    parts = version_clean.split(".")
    if len(parts) >= 2:
        year = parts[0]
        minor = parts[1]
        url = f"https://raw.githubusercontent.com/{UPSTREAM_REPO}/main/website/docs/releases/{year}/v{year}.{minor}.mdx"
        return fetch_text(url)
    return None


def extract_key_sections_from_docs(docs_md: str, version_clean: str) -> str:
    """Extract high-priority sections (Breaking changes, Highlights, Upgrading, Deprecations, Fixed in X.Y.Z) from docs markdown."""
    extracted = []
    # 1. Highlights
    m_high = re.search(r"(##\s+(?i:Highlights)[\s\S]*?)(?=\n##\s+|\Z)", docs_md)
    if m_high:
        extracted.append(m_high.group(1).strip())

    # 2. Breaking changes
    m_break = re.search(r"(##\s+(?i:Breaking\s+[Cc]hanges)[\s\S]*?)(?=\n##\s+|\Z)", docs_md)
    if m_break:
        extracted.append(m_break.group(1).strip())

    # 3. Upgrading / Migration
    m_upg = re.search(r"(##\s+(?i:Upgrading|Migration)[\s\S]*?)(?=\n##\s+|\Z)", docs_md)
    if m_upg:
        extracted.append(m_upg.group(1).strip())

    # 4. Deprecations
    m_dep = re.search(r"(##\s+(?i:Deprecations)[\s\S]*?)(?=\n##\s+|\Z)", docs_md)
    if m_dep:
        extracted.append(m_dep.group(1).strip())

    # 5. Patch-specific section, e.g. '## Fixed in 2026.8.3'
    m_patch = re.search(r"(##\s+(?i:Fixed\s+in\s+)" + re.escape(version_clean) + r"[\s\S]*?)(?=\n##\s+|\Z)", docs_md)
    if m_patch:
        extracted.append(m_patch.group(1).strip())

    if extracted:
        return "\n\n".join(extracted)
    return docs_md[:80000]


def extract_json_from_text(text: str) -> Dict[str, Any]:
    """Extract and parse JSON object from raw LLM text output."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned)
        cleaned = cleaned.strip()
    
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        match = re.search(r"(\{[\s\S]*\})", cleaned)
        if match:
            return json.loads(match.group(1))
        raise


def render_template(
    template_name: str,
    substitutions: Dict[str, Any],
    template_dir: Optional[Path] = None,
    fallback_content: Optional[str] = None
) -> str:
    """Load a template file and substitute {{ KEY }} placeholders.
    Falls back to fallback_content if the file is not found.
    """
    dir_path = template_dir or DEFAULT_TEMPLATES_DIR
    template_file = dir_path / template_name
    if template_file.is_file():
        content = template_file.read_text(encoding="utf-8")
    elif fallback_content is not None:
        content = fallback_content
    else:
        raise FileNotFoundError(f"Template not found at {template_file} and no fallback content provided.")

    for key, val in substitutions.items():
        content = content.replace(f"{{{{ {key} }}}}", str(val))
        content = content.replace(f"{{{{{key}}}}}", str(val))
    return content


def call_gemini_sdk(
    prompt: str,
    api_key: str,
    model: str = GEMINI_MODEL,
    timeout: int = 60
) -> Dict[str, Any]:
    """Call Google Gemini using the OpenAI-compatible SDK endpoint with automatic retries."""
    if not OPENAI_AVAILABLE:
        raise RuntimeError("openai package is not installed")
    client = OpenAI(
        api_key=api_key,
        base_url=GEMINI_OPENAI_BASE_URL,
        timeout=timeout,
        max_retries=3,
    )
    completion = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
        response_format={"type": "json_object"},
    )
    content = completion.choices[0].message.content or "{}"
    return extract_json_from_text(content)


def call_openrouter_sdk(
    prompt: str,
    api_key: str,
    model: str = OPENROUTER_MODEL,
    timeout: int = 60
) -> Dict[str, Any]:
    """Call OpenRouter using the official OpenAI SDK with automatic retries."""
    if not OPENAI_AVAILABLE:
        raise RuntimeError("openai package is not installed")
    client = OpenAI(
        api_key=api_key,
        base_url=OPENROUTER_BASE_URL,
        default_headers={
            "HTTP-Referer": "https://github.com/canonical/authentik-server-rock",
            "X-Title": "authentik-server-rock upstream checker",
        },
        timeout=timeout,
        max_retries=3,
    )
    completion = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
        response_format={"type": "json_object"},
    )
    content = completion.choices[0].message.content or "{}"
    return extract_json_from_text(content)


def call_gemini_rest(prompt: str, api_key: str, model: str = GEMINI_MODEL, timeout: int = 60) -> Dict[str, Any]:
    """Call the Gemini API with header auth and structured schema via REST urllib."""
    url = GEMINI_API_URL.format(model=model)
    
    payload = {
        "contents": [
            {
                "parts": [
                    {"text": prompt}
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.1,
            "responseMimeType": "application/json",
            "responseSchema": GEMINI_RESPONSE_SCHEMA,
        }
    }
    
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": api_key,
        },
        method="POST"
    )
    
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        res = json.loads(resp.read().decode("utf-8"))
        
    candidates = res.get("candidates", [])
    if not candidates:
        raise ValueError(f"No response candidates from Gemini: {res}")
    
    content_text = candidates[0]["content"]["parts"][0]["text"]
    return extract_json_from_text(content_text)


def call_openrouter_rest(
    prompt: str,
    api_key: str,
    model: str = OPENROUTER_MODEL,
    timeout: int = 60
) -> Dict[str, Any]:
    """Call OpenRouter API using chat completions endpoint via REST urllib."""
    url = OPENROUTER_API_URL
    payload = {
        "model": model,
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ],
        "temperature": 0.1,
        "response_format": {"type": "json_object"}
    }
    
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "HTTP-Referer": "https://github.com/canonical/authentik-server-rock",
            "X-Title": "authentik-server-rock upstream checker",
        },
        method="POST"
    )
    
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        res = json.loads(resp.read().decode("utf-8"))
        
    choices = res.get("choices", [])
    if not choices:
        raise ValueError(f"No response choices from OpenRouter: {res}")
    
    content_text = choices[0]["message"]["content"]
    return extract_json_from_text(content_text)


def call_gemini(
    prompt: str,
    api_key: str,
    model: str = GEMINI_MODEL,
    timeout: int = 60,
    prefer_sdk: bool = True
) -> Dict[str, Any]:
    """Call Gemini API preferring OpenAI SDK with automatic retries, falling back to REST urllib."""
    if prefer_sdk and OPENAI_AVAILABLE:
        try:
            return call_gemini_sdk(prompt, api_key, model=model, timeout=timeout)
        except Exception as e:
            print(f"Notice: Gemini SDK call failed ({e}), falling back to direct REST request...")
    return call_gemini_rest(prompt, api_key, model=model, timeout=timeout)


def call_openrouter(
    prompt: str,
    api_key: str,
    model: str = OPENROUTER_MODEL,
    timeout: int = 60,
    prefer_sdk: bool = True
) -> Dict[str, Any]:
    """Call OpenRouter API preferring OpenAI SDK with automatic retries, falling back to REST urllib."""
    if prefer_sdk and OPENAI_AVAILABLE:
        try:
            return call_openrouter_sdk(prompt, api_key, model=model, timeout=timeout)
        except Exception as e:
            print(f"Notice: OpenRouter SDK call failed ({e}), falling back to direct REST request...")
    return call_openrouter_rest(prompt, api_key, model=model, timeout=timeout)


def analyze_with_llm(
    prompt: str,
    gemini_key: Optional[str] = None,
    openrouter_key: Optional[str] = None,
    gemini_model: str = GEMINI_MODEL,
    openrouter_model: str = OPENROUTER_MODEL
) -> Optional[Dict[str, Any]]:
    """Dispatch LLM analysis to Gemini or OpenRouter depending on configured keys."""
    if gemini_key:
        try:
            print(f"Analyzing changes with Gemini API (model: {gemini_model})...")
            return call_gemini(prompt, gemini_key, model=gemini_model)
        except Exception as e:
            print(f"Warning: Gemini API call failed: {e}")
            if not openrouter_key:
                return None
            print("Falling back to OpenRouter API...")

    if openrouter_key:
        try:
            print(f"Analyzing changes with OpenRouter API (model: {openrouter_model})...")
            return call_openrouter(prompt, openrouter_key, model=openrouter_model)
        except Exception as e:
            print(f"Warning: OpenRouter API call failed: {e}")
            return None

    return None


def generate_analysis_prompt(
    current_ver: str,
    new_ver: str,
    gh_release_body: str,
    docs_markdown: Optional[str],
    template_dir: Optional[Path] = None
) -> str:
    """Build the prompt for the LLM using analysis_prompt.txt template with prompt injection isolation."""
    context_text = f"### GitHub Release Body:\n<untrusted_upstream_release_notes>\n{gh_release_body}\n</untrusted_upstream_release_notes>\n\n"
    if docs_markdown:
        key_sections = extract_key_sections_from_docs(docs_markdown, new_ver)
        context_text += f"### Upstream Documentation & Release Notes:\n<untrusted_upstream_documentation>\n{key_sections}\n</untrusted_upstream_documentation>\n"

    fallback_prompt = """You are an expert Canonical / Ubuntu software engineer specializing in Rockcraft OCI rocks and Juju Charms.
You are evaluating an upstream release of the Authentik identity provider.

Current version in rockcraft: {{ CURRENT_VER }}
New upstream release version: {{ NEW_VER }}

Upstream Data:
{{ CONTEXT_TEXT }}

Analyze the changes thoroughly and output a JSON object adhering strictly to the requested schema."""

    substitutions = {
        "CURRENT_VER": current_ver,
        "NEW_VER": new_ver,
        "CONTEXT_TEXT": context_text
    }
    return render_template(
        "analysis_prompt.txt",
        substitutions,
        template_dir=template_dir,
        fallback_content=fallback_prompt
    )


def generate_fallback_analysis(current_ver: str, new_ver: str, gh_release_body: str) -> Dict[str, Any]:
    """Fallback when GEMINI_API_KEY is not available (e.g. offline dry run) or API call fails."""
    has_breaking = "breaking" in gh_release_body.lower()
    return {
        "is_fallback": True,
        "has_breaking_changes": has_breaking,
        "severity": "medium" if has_breaking else "low",
        "breaking_changes_summary": "Automated fallback: Review upstream release notes for details.",
        "highlights": [f"Upgraded from {current_ver} to {new_ver}"],
        "rock_impact": {
            "summary": "Rockcraft container updated to target new release tag.",
            "action_items": ["Verify rockcraft pack succeeds in CI."]
        },
        "charm_impact": {
            "summary": "Verify charm compatibility with new image.",
            "affected_components": ["pebble_service", "environment_variables"],
            "action_items": ["Check charm pebble service layers and environment variables."]
        },
        "testing_and_verification_matrix": {
            "automated_tests": [
                "tox -e lint",
                "tox -e unit",
                "tox -e integration"
            ],
            "in_cluster_checks": [
                "juju exec --unit authentik-server/0 -- pebble services",
                "juju exec --unit authentik-server/0 -- pebble logs server",
                "juju exec --unit authentik-worker/0 -- pebble services",
                "juju exec --unit authentik-worker/0 -- pebble logs worker"
            ],
            "regression_probes": [
                "Verify database migration completes on startup",
                "Verify user login and admin dashboard loading"
            ]
        },
        "definition_of_done": [
            f"Updated charm image resource to {new_ver}",
            "Verified unit tests pass",
            "Verified integration tests pass",
            "Verified cluster smoke tests"
        ]
    }


def format_rockcraft_pr_body(
    current_ver: str,
    new_ver: str,
    analysis: Dict[str, Any],
    upstream_release_url: str,
    template_dir: Optional[Path] = None,
    releases: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """Format PR description for authentik-server-rock using rockcraft_pr_body.md template."""
    breaking = analysis.get("has_breaking_changes", False)
    breaking_badge = "⚠️ **YES (Breaking Changes Detected)**" if breaking else "✅ **No Breaking Changes Detected**"
    
    highlights_list = analysis.get("highlights", [])
    highlights_md = "\n".join(f"- {h}" for h in highlights_list) if highlights_list else "- See upstream release notes"
    
    rock_actions_list = analysis.get("rock_impact", {}).get("action_items", [])
    rock_actions_md = "\n".join(f"- {a}" for a in rock_actions_list) if rock_actions_list else ""
    
    charm_actions_list = analysis.get("charm_impact", {}).get("action_items", [])
    charm_actions_md = "\n".join(f"- {a}" for a in charm_actions_list) if charm_actions_list else ""
    
    banners = []
    if analysis.get("is_fallback", False):
        banners.append(
            "> [!CAUTION]\n"
            "> **Automated Fallback Analysis (LLM Unavailable)**\n"
            "> AI-assisted analysis was not executed or failed. The assessment below contains generic template items. Maintainers MUST manually inspect upstream release notes."
        )

    if is_multi_minor_jump(current_ver, new_ver, releases=releases):
        banners.append(
            "> [!WARNING]\n"
            f"> **Multi-Minor Version Jump Detected (`v{current_ver}` → `v{new_ver}`)**\n"
            "> Upstream Authentik requires sequential database schema migrations across minor releases. Migrations cannot skip minor versions directly in production."
        )

    banner_block = ("\n\n".join(banners) + "\n\n---\n\n") if banners else ""

    substitutions = {
        "CURRENT_VER": current_ver,
        "NEW_VER": new_ver,
        "UPSTREAM_RELEASE_URL": upstream_release_url,
        "BREAKING_BADGE": breaking_badge,
        "SEVERITY": analysis.get("severity", "unknown"),
        "HIGHLIGHTS": highlights_md,
        "BREAKING_CHANGES_SUMMARY": analysis.get("breaking_changes_summary", "None reported"),
        "ROCK_IMPACT_SUMMARY": analysis.get("rock_impact", {}).get("summary", "Standard version bump"),
        "ROCK_ACTION_ITEMS": rock_actions_md,
        "CHARM_IMPACT_SUMMARY": analysis.get("charm_impact", {}).get("summary", "Review required"),
        "CHARM_ACTION_ITEMS": charm_actions_md,
        "BANNERS": banner_block,
    }

    fallback_content = """## 🤖 Automated Upstream Release Update

Updates `authentik-server-rock` from **`{{ CURRENT_VER }}`** to **`{{ NEW_VER }}`**.

{{ BANNERS }}- **Upstream Release**: [{{ NEW_VER }}]({{ UPSTREAM_RELEASE_URL }})
- **Breaking Changes**: {{ BREAKING_BADGE }}
- **Severity**: `{{ SEVERITY }}`

---

### Upstream Highlights
{{ HIGHLIGHTS }}

### Breaking Changes & Migration Notes
{{ BREAKING_CHANGES_SUMMARY }}

### Impact on Rock Build
{{ ROCK_IMPACT_SUMMARY }}
{{ ROCK_ACTION_ITEMS }}

### Impact on Charms (`authentik-server-operator` & `authentik-worker-operator`)
{{ CHARM_IMPACT_SUMMARY }}
{{ CHARM_ACTION_ITEMS }}

---
*An automated issue with testing and execution instructions has also been created on the charm operator repositories.*
"""

    return render_template(
        "rockcraft_pr_body.md",
        substitutions,
        template_dir=template_dir,
        fallback_content=fallback_content
    )


def format_charm_issue_body(
    current_ver: str,
    new_ver: str,
    analysis: Dict[str, Any],
    upstream_release_url: str,
    rockcraft_pr_url: Optional[str] = None,
    template_dir: Optional[Path] = None,
    releases: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """Format an agent-ready GitHub Issue body for the charm operators using charm_issue_body.md template."""
    breaking = analysis.get("has_breaking_changes", False)
    breaking_badge = "⚠️ **YES (Breaking Changes Detected)**" if breaking else "✅ **No Known Breaking Changes**"
    
    components = ", ".join(analysis.get("charm_impact", {}).get("affected_components", []))
    charm_actions_list = analysis.get("charm_impact", {}).get("action_items", [])
    charm_actions = "\n".join(f"- {a}" for a in charm_actions_list) if charm_actions_list else "- Update image resource to new tag/digest."
    
    auto_tests_list = analysis.get("testing_and_verification_matrix", {}).get("automated_tests", [])
    auto_tests = "\n".join(auto_tests_list) if auto_tests_list else "tox -e lint\ntox -e unit\ntox -e integration"
    
    cluster_checks_list = analysis.get("testing_and_verification_matrix", {}).get("in_cluster_checks", [])
    cluster_checks = "\n".join(cluster_checks_list) if cluster_checks_list else "juju exec --unit authentik-server/0 -- pebble services\njuju exec --unit authentik-server/0 -- pebble logs server"
    
    probes_list = analysis.get("testing_and_verification_matrix", {}).get("regression_probes", [])
    probes = "\n".join(f"- {p}" for p in probes_list) if probes_list else "- Confirm user login and admin dashboard functionality"
    
    dod_list = analysis.get("definition_of_done", [])
    dod = "\n".join(f"- [ ] {item}" for item in dod_list) if dod_list else f"- [ ] Updated charm image resource to {new_ver}\n- [ ] Verified tests pass"

    rock_pr_line = (
        f"- **Associated Rockcraft PR**: [{rockcraft_pr_url}]({rockcraft_pr_url}) *(Wait for this rock build to merge and publish before rolling out to production)*"
        if rockcraft_pr_url
        else "- **Associated Rockcraft PR**: Pending Rockcraft PR *(Wait for rock image build to succeed and publish before charm upgrade)*"
    )

    banners = []
    if analysis.get("is_fallback", False):
        banners.append(
            "> [!CAUTION]\n"
            "> **Automated Fallback Analysis (LLM Unavailable)**\n"
            "> AI-assisted analysis was not executed or failed. The action items and test matrix below are generic templates. Maintainers MUST manually inspect upstream release notes."
        )

    if is_multi_minor_jump(current_ver, new_ver, releases=releases):
        banners.append(
            "> [!WARNING]\n"
            f"> **Multi-Minor Version Jump Detected (`v{current_ver}` → `v{new_ver}`)**\n"
            "> Upstream Authentik does NOT support skipping minor releases during database migrations. Upgrades MUST be applied sequentially through each intermediate minor release (e.g. 2026.6, 2026.7) before upgrading directly in production models!"
        )

    banner_block = ("\n\n".join(banners) + "\n\n---\n\n") if banners else ""

    substitutions = {
        "CURRENT_VER": current_ver,
        "NEW_VER": new_ver,
        "UPSTREAM_RELEASE_URL": upstream_release_url,
        "ROCK_PR_LINE": rock_pr_line,
        "BREAKING_BADGE": breaking_badge,
        "SEVERITY": analysis.get("severity", "unknown"),
        "AFFECTED_COMPONENTS": components or "Standard image bump",
        "BREAKING_CHANGES_SUMMARY": analysis.get("breaking_changes_summary", "None reported"),
        "CHARM_IMPACT_SUMMARY": analysis.get("charm_impact", {}).get("summary", ""),
        "CHARM_ACTION_ITEMS": charm_actions,
        "AUTOMATED_TESTS": auto_tests,
        "IN_CLUSTER_CHECKS": cluster_checks,
        "REGRESSION_PROBES": probes,
        "DEFINITION_OF_DONE": dod,
        "BANNERS": banner_block,
    }

    fallback_content = """## 🚀 Upstream Authentik Upgrade Specification: v{{ CURRENT_VER }} → v{{ NEW_VER }}

> **For Engineers & AI Coding Agents:** This issue contains a complete specification to update the charm for Authentik `v{{ NEW_VER }}`.
> You can feed this issue directly to an agent (e.g. Antigravity) with:
> `Read this issue and implement all required charm changes, then run unit and integration tests to confirm.`

---

{{ BANNERS }}### 1. Upstream Summary & Impact Assessment
- **Upstream Version**: [{{ NEW_VER }}]({{ UPSTREAM_RELEASE_URL }}) (Previous: `{{ CURRENT_VER }}`)
{{ ROCK_PR_LINE }}
- **Breaking Changes**: {{ BREAKING_BADGE }}
- **Severity**: `{{ SEVERITY }}`
- **Affected Components**: `{{ AFFECTED_COMPONENTS }}`

**Summary of Upstream Changes:**
{{ BREAKING_CHANGES_SUMMARY }}

---

### 2. Action Items for the Charm
{{ CHARM_IMPACT_SUMMARY }}

{{ CHARM_ACTION_ITEMS }}

---

### 3. Testing & Verification Matrix (MUST BE CONFIRMED)

#### A. Automated Test Suite
Run local checks:
```bash
{{ AUTOMATED_TESTS }}
```

#### B. In-Cluster Service Health Checks
Once deployed or upgraded on a test model:
```bash
{{ IN_CLUSTER_CHECKS }}
```

#### C. Specific Regression Probes
{{ REGRESSION_PROBES }}

---

### 4. Definition of Done
{{ DEFINITION_OF_DONE }}
"""

    return render_template(
        "charm_issue_body.md",
        substitutions,
        template_dir=template_dir,
        fallback_content=fallback_content
    )


def update_rockcraft_yaml(rockcraft_path: Path, current_ver: str, new_ver: str) -> bool:
    """Update version and source-tag references in rockcraft.yaml."""
    content = rockcraft_path.read_text(encoding="utf-8")
    
    # 1. version: "..."
    new_content, count1 = re.subn(
        r'^(version:\s*["\']?)' + re.escape(current_ver) + r'(["\']?)',
        r'\g<1>' + new_ver + r'\g<2>',
        content,
        flags=re.MULTILINE
    )
    
    # 2. source-tag: version/...
    new_content, count2 = re.subn(
        r'(source-tag:\s*version/)' + re.escape(current_ver),
        r'\g<1>' + new_ver,
        new_content
    )
    
    # 3. main.Version=...
    new_content, count3 = re.subn(
        r'(main\.Version=)' + re.escape(current_ver),
        r'\g<1>' + new_ver,
        new_content
    )
    
    total_replacements = count1 + count2 + count3
    if total_replacements == 0:
        print(f"Warning: No occurrences of version {current_ver} found to replace in {rockcraft_path}")
        return False
        
    rockcraft_path.write_text(new_content, encoding="utf-8")
    print(f"Successfully updated {rockcraft_path}: {total_replacements} replacements made.")
    return True


def write_github_output(name: str, value: str) -> None:
    """Append output variable to GITHUB_OUTPUT environment file."""
    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path:
        with open(output_path, "a", encoding="utf-8") as f:
            f.write(f"{name}={value}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Check upstream Authentik releases and generate update specs.")
    parser.add_argument("--rockcraft-file", default="rockcraft.yaml", help="Path to rockcraft.yaml")
    parser.add_argument("--current-version", default=None, help="Override current version")
    parser.add_argument("--target-version", default=None, help="Target upstream version (e.g. 2026.8.3)")
    parser.add_argument("--dry-run", action="store_true", help="Do not write files or modify git")
    parser.add_argument("--update-rockcraft", action="store_true", help="Update rockcraft.yaml on disk")
    parser.add_argument("--out-dir", default=".", help="Directory to save generated markdown artifacts")
    parser.add_argument("--gemini-api-key", default=None, help="Gemini API Key (or env GEMINI_API_KEY)")
    parser.add_argument("--openrouter-api-key", default=None, help="OpenRouter API Key (or env OPENROUTER_API_KEY)")
    parser.add_argument("--gemini-model", default=GEMINI_MODEL, help="Gemini model name")
    parser.add_argument("--openrouter-model", default=OPENROUTER_MODEL, help="OpenRouter model name")
    parser.add_argument("--template-dir", default=None, help="Directory containing template files")
    parser.add_argument("--github-token", default=None, help="GitHub Token (or env GITHUB_TOKEN)")
    parser.add_argument("--rockcraft-pr-url", default=None, help="Associated Rockcraft PR URL")
    parser.add_argument("--repo", default=None, help="Target GitHub repository (default: canonical/authentik-server-rock or GITHUB_REPOSITORY)")
    parser.add_argument("--force", action="store_true", help="Force re-running analysis even if a PR already exists")
    parser.add_argument(
        "--strategy",
        choices=["next-minor", "latest"],
        default="next-minor",
        help="Target release strategy: 'next-minor' (default: safe sequential upgrade) or 'latest'"
    )
    
    args = parser.parse_args()
    
    template_dir = Path(args.template_dir) if args.template_dir else DEFAULT_TEMPLATES_DIR
    rockcraft_path = Path(args.rockcraft_file)
    if not rockcraft_path.is_file():
        print(f"Error: {rockcraft_path} does not exist.")
        return 1
        
    current_ver = args.current_version or read_current_version(rockcraft_path)
    current_tuple = parse_version_tuple(current_ver)
    print(f"Current rockcraft version: {current_ver} (parsed: {current_tuple})")
    
    gh_token = args.github_token or os.environ.get("GITHUB_TOKEN") or os.environ.get("PAT_TOKEN")
    rock_pr_url = args.rockcraft_pr_url or os.environ.get("ROCKCRAFT_PR_URL")
    target_repo = args.repo or os.environ.get("GITHUB_REPOSITORY", "canonical/authentik-server-rock")
    
    upstream_releases: List[Dict[str, Any]] = []
    if args.target_version:
        target_ver_clean = re.sub(r"^(version/|v)", "", args.target_version)
        print(f"Target version manually set to: {target_ver_clean}")
        try:
            rel_data = get_upstream_release_by_tag(f"version/{target_ver_clean}", token=gh_token)
        except Exception:
            rel_data = {
                "tag_name": f"version/{target_ver_clean}",
                "html_url": f"https://github.com/{UPSTREAM_REPO}/releases/tag/version/{target_ver_clean}",
                "body": f"Release notes for {target_ver_clean}"
            }
    else:
        print(f"Fetching upstream releases from GitHub (strategy: {args.strategy})...")
        upstream_releases = fetch_all_upstream_releases(token=gh_token)
        rel_data = None
        if upstream_releases:
            rel_data = select_target_release(current_ver, upstream_releases, strategy=args.strategy)
            
        if not rel_data:
            if not upstream_releases:
                print("Falling back to latest upstream release endpoint...")
                rel_data = get_latest_upstream_release(token=gh_token)
            else:
                print(f"No update needed. Current version ({current_ver}) is up-to-date with upstream.")
                write_github_output("has_new_release", "false")
                return 0
        
    raw_tag = rel_data.get("tag_name", "")
    new_ver = re.sub(r"^(version/|v)", "", raw_tag)
    new_tuple = parse_version_tuple(new_ver)
    upstream_url = rel_data.get("html_url", f"https://github.com/{UPSTREAM_REPO}/releases/tag/{raw_tag}")
    release_body = rel_data.get("body", "")
    
    print(f"Selected upstream release: {new_ver} (tag: {raw_tag}, parsed: {new_tuple})")
    
    has_update = new_tuple > current_tuple
    if not has_update and not args.target_version:
        print(f"No update needed. Current version ({current_ver}) is up-to-date with upstream ({new_ver}).")
        write_github_output("has_new_release", "false")
        return 0
        
    print(f"New release detected! {current_ver} -> {new_ver}")
    pr_branch = f"auto-update-authentik-{new_ver}"

    if not args.force:
        existing_pr = check_existing_pr(target_repo, pr_branch, token=gh_token)
        if existing_pr:
            print(f"Pull request for version {new_ver} already exists on {target_repo}: {existing_pr}")
            print("Skipping LLM analysis, rockcraft update, and PR/issue creation.")
            write_github_output("has_new_release", "false")
            write_github_output("existing_pr_url", existing_pr)
            return 0

    write_github_output("has_new_release", "true")
    write_github_output("current_version", current_ver)
    write_github_output("new_version", new_ver)
    write_github_output("pr_branch", pr_branch)
    
    print("Fetching documentation release notes...")
    docs_text = fetch_upstream_docs_release_notes(new_ver)
    if docs_text:
        print(f"Fetched {len(docs_text)} characters of documentation notes.")
    else:
        print("No matching documentation page found; using GitHub release body.")
        
    gemini_key = args.gemini_api_key or os.environ.get("GEMINI_API_KEY")
    openrouter_key = args.openrouter_api_key or os.environ.get("OPENROUTER_API_KEY")

    prompt = generate_analysis_prompt(
        current_ver,
        new_ver,
        release_body,
        docs_text,
        template_dir=template_dir
    )

    if gemini_key or openrouter_key:
        analysis = analyze_with_llm(
            prompt,
            gemini_key=gemini_key,
            openrouter_key=openrouter_key,
            gemini_model=args.gemini_model,
            openrouter_model=args.openrouter_model,
        )
        if analysis:
            analysis["is_fallback"] = False
            print("LLM analysis completed successfully.")
        else:
            print("Warning: LLM analysis failed. Falling back to template analysis.")
            analysis = generate_fallback_analysis(current_ver, new_ver, release_body)
    else:
        print("Neither GEMINI_API_KEY nor OPENROUTER_API_KEY provided. Generating template fallback analysis.")
        analysis = generate_fallback_analysis(current_ver, new_ver, release_body)
        
    has_breaking = analysis.get("has_breaking_changes", False)
    write_github_output("has_breaking_changes", "true" if has_breaking else "false")
    
    pr_body = format_rockcraft_pr_body(
        current_ver,
        new_ver,
        analysis,
        upstream_url,
        template_dir=template_dir,
        releases=upstream_releases,
    )
    charm_issue_body = format_charm_issue_body(
        current_ver,
        new_ver,
        analysis,
        upstream_url,
        rockcraft_pr_url=rock_pr_url,
        template_dir=template_dir,
        releases=upstream_releases,
    )
    
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    
    pr_file = out_dir / "rockcraft_pr_body.md"
    issue_file = out_dir / "charm_issue_body.md"
    analysis_file = out_dir / "analysis.json"
    
    pr_file.write_text(pr_body, encoding="utf-8")
    issue_file.write_text(charm_issue_body, encoding="utf-8")
    analysis_file.write_text(json.dumps(analysis, indent=2), encoding="utf-8")
    
    print(f"Generated artifacts:\n - {pr_file}\n - {issue_file}\n - {analysis_file}")
    
    if args.update_rockcraft and not args.dry_run:
        update_rockcraft_yaml(rockcraft_path, current_ver, new_ver)
        
    return 0


if __name__ == "__main__":
    sys.exit(main())
