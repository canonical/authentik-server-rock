import io
import json
import unittest
from pathlib import Path
import tempfile
import sys
from unittest.mock import MagicMock, patch

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from check_upstream_release import (
    parse_version_tuple,
    is_multi_minor_jump,
    read_current_version,
    update_rockcraft_yaml,
    extract_key_sections_from_docs,
    format_charm_issue_body,
    format_rockcraft_pr_body,
    generate_fallback_analysis,
    call_gemini,
    call_openrouter,
    call_gemini_rest,
    call_openrouter_rest,
    call_gemini_sdk,
    call_openrouter_sdk,
    check_existing_pr,
    analyze_with_llm,
    select_target_release,
    fetch_all_upstream_releases,
    render_template,
    extract_json_from_text,
    GEMINI_RESPONSE_SCHEMA,
    OPENROUTER_MODEL,
    OPENROUTER_API_URL,
    GEMINI_OPENAI_BASE_URL,
    OPENROUTER_BASE_URL,
)


class TestCheckUpstreamRelease(unittest.TestCase):
    def test_parse_version_tuple(self):
        self.assertEqual(parse_version_tuple("2026.8.3"), (2026, 8, 3))
        self.assertEqual(parse_version_tuple("version/2026.8.3"), (2026, 8, 3))
        self.assertEqual(parse_version_tuple("v2026.5.0"), (2026, 5, 0))
        self.assertTrue(parse_version_tuple("2026.8.3") > parse_version_tuple("2026.5.3"))
        self.assertTrue(parse_version_tuple("2026.5.7") > parse_version_tuple("2026.5.3"))
        self.assertFalse(parse_version_tuple("2026.5.3") > parse_version_tuple("2026.5.3"))

    def test_is_multi_minor_jump(self):
        # Heuristic fallback (no releases provided)
        self.assertFalse(is_multi_minor_jump("2026.5.3", "2026.5.4"))
        self.assertFalse(is_multi_minor_jump("2026.5.3", "2026.6.0"))
        self.assertTrue(is_multi_minor_jump("2026.5.3", "2026.7.0"))
        self.assertTrue(is_multi_minor_jump("2026.5.3", "2026.8.3"))
        self.assertTrue(is_multi_minor_jump("2025.12.1", "2026.1.0"))

        # With upstream releases list
        sample_releases = [
            {"tag_name": "version/2025.10.4"},
            {"tag_name": "version/2025.12.6"},
            {"tag_name": "version/2026.2.7"},
            {"tag_name": "version/2026.5.3"},
            {"tag_name": "version/2026.5.7"},
            {"tag_name": "version/2026.8.3"},
        ]
        # Same minor patch bump: False
        self.assertFalse(is_multi_minor_jump("2026.5.3", "2026.5.7", releases=sample_releases))
        # Immediate consecutive minor bump (2026.5 -> 2026.8): False
        self.assertFalse(is_multi_minor_jump("2026.5.7", "2026.8.3", releases=sample_releases))
        # Skipping intermediate minors (2025.10 -> 2026.8 skips 2025.12, 2026.2, 2026.5): True
        self.assertTrue(is_multi_minor_jump("2025.10.4", "2026.8.3", releases=sample_releases))

    def test_select_target_release(self):
        sample_releases = [
            {"tag_name": "version/2025.10.1"},
            {"tag_name": "version/2025.10.4"},
            {"tag_name": "version/2025.12.0"},
            {"tag_name": "version/2025.12.6"},
            {"tag_name": "version/2026.5.3"},
            {"tag_name": "version/2026.5.7"},
            {"tag_name": "version/2026.8.0"},
            {"tag_name": "version/2026.8.3"},
        ]
        # 1. On 2026.5.3, next-minor strategy picks latest patch of current minor (2026.5.7)
        target = select_target_release("2026.5.3", sample_releases, strategy="next-minor")
        self.assertIsNotNone(target)
        self.assertEqual(target["tag_name"], "version/2026.5.7")

        # 2. On 2026.5.7, next-minor strategy advances to immediate next minor's latest patch (2026.8.3)
        target = select_target_release("2026.5.7", sample_releases, strategy="next-minor")
        self.assertIsNotNone(target)
        self.assertEqual(target["tag_name"], "version/2026.8.3")

        # 3. On 2025.10.4, next-minor strategy advances to 2025.12.6 (NOT jumping directly to 2026.8.3)
        target = select_target_release("2025.10.4", sample_releases, strategy="next-minor")
        self.assertIsNotNone(target)
        self.assertEqual(target["tag_name"], "version/2025.12.6")

        # 4. On 2026.8.3, already on latest -> returns None
        target = select_target_release("2026.8.3", sample_releases, strategy="next-minor")
        self.assertIsNone(target)

        # 5. On 2026.5.3 with 'latest' strategy -> jumps straight to 2026.8.3
        target = select_target_release("2026.5.3", sample_releases, strategy="latest")
        self.assertIsNotNone(target)
        self.assertEqual(target["tag_name"], "version/2026.8.3")

    def test_read_current_version(self):
        sample = 'name: authentik-server\nbase: bare\nversion: "2026.5.3"\nsummary: test\n'
        with tempfile.NamedTemporaryFile("w+", delete=False) as f:
            f.write(sample)
            tmp_path = Path(f.name)
        try:
            self.assertEqual(read_current_version(tmp_path), "2026.5.3")
        finally:
            tmp_path.unlink()

    def test_update_rockcraft_yaml(self):
        sample = """name: authentik-server
version: "2026.5.3"
parts:
  web-ui:
    source-tag: version/2026.5.3
  go-server:
    source-tag: version/2026.5.3
    override-build: |
      go build -ldflags="-s -w -X 'main.Version=2026.5.3'" -o server
  # CVE comment: CVE-2026-32597
"""
        with tempfile.NamedTemporaryFile("w+", delete=False) as f:
            f.write(sample)
            tmp_path = Path(f.name)
        try:
            res = update_rockcraft_yaml(tmp_path, "2026.5.3", "2026.8.3")
            self.assertTrue(res)
            updated = tmp_path.read_text()
            self.assertIn('version: "2026.8.3"', updated)
            self.assertIn("source-tag: version/2026.8.3", updated)
            self.assertIn("main.Version=2026.8.3", updated)
            self.assertIn("# CVE comment: CVE-2026-32597", updated)
            self.assertNotIn("2026.5.3", updated)
        finally:
            tmp_path.unlink()

    def test_extract_key_sections_from_docs(self):
        docs_md = """---
title: Release 2026.8
---

## Highlights
- Exciting new features in 2026.8

## Breaking changes
- Header restrictions on reverse proxy

## New features and improvements
- Detailed feature descriptions...

## Fixed in 2026.8.3
- Fix minor bug
"""
        extracted = extract_key_sections_from_docs(docs_md, "2026.8.3")
        self.assertIn("## Highlights", extracted)
        self.assertIn("## Breaking changes", extracted)
        self.assertIn("## Fixed in 2026.8.3", extracted)
        self.assertNotIn("## New features and improvements", extracted)

    def test_extract_json_from_text(self):
        # Plain JSON
        plain = '{"key": "value"}'
        self.assertEqual(extract_json_from_text(plain), {"key": "value"})

        # Markdown fenced JSON
        fenced = '```json\n{"key": "fenced"}\n```'
        self.assertEqual(extract_json_from_text(fenced), {"key": "fenced"})

        # Fenced without language tag
        fenced_no_lang = '```\n{"key": "no_lang"}\n```'
        self.assertEqual(extract_json_from_text(fenced_no_lang), {"key": "no_lang"})

        # Surrounding commentary
        surrounded = 'Here is the JSON:\n{"key": "surrounded"}\nHope this helps!'
        self.assertEqual(extract_json_from_text(surrounded), {"key": "surrounded"})

    def test_render_template(self):
        # Rendering from actual templates directory
        substitutions = {
            "CURRENT_VER": "2026.5.3",
            "NEW_VER": "2026.8.3",
            "CONTEXT_TEXT": "Sample context"
        }
        prompt_rendered = render_template("analysis_prompt.txt", substitutions)
        self.assertIn("Current version in rockcraft: 2026.5.3", prompt_rendered)
        self.assertIn("New upstream release version: 2026.8.3", prompt_rendered)
        self.assertIn("Sample context", prompt_rendered)

        # Fallback content when template file does not exist
        fallback = "Version {{ CURRENT_VER }} to {{ NEW_VER }}"
        res = render_template("non_existent.txt", substitutions, fallback_content=fallback)
        self.assertEqual(res, "Version 2026.5.3 to 2026.8.3")

    def test_format_bodies(self):
        analysis = generate_fallback_analysis("2026.5.3", "2026.8.3", "Breaking changes included")
        pr_body = format_rockcraft_pr_body("2026.5.3", "2026.8.3", analysis, "https://github.com/example")
        self.assertIn("2026.5.3", pr_body)
        self.assertIn("2026.8.3", pr_body)
        self.assertIn("YES (Breaking Changes Detected)", pr_body)
        self.assertIn("Multi-Minor Version Jump Detected", pr_body)
        self.assertIn("Automated Fallback Analysis", pr_body)

        issue_body = format_charm_issue_body(
            "2026.5.3",
            "2026.8.3",
            analysis,
            "https://github.com/example",
            rockcraft_pr_url="https://github.com/canonical/authentik-server-rock/pull/123"
        )
        self.assertIn("Testing & Verification Matrix", issue_body)
        self.assertIn("tox -e unit", issue_body)
        self.assertIn("juju exec --unit authentik-server/0 -- pebble services", issue_body)
        self.assertIn("Definition of Done", issue_body)
        self.assertIn("https://github.com/canonical/authentik-server-rock/pull/123", issue_body)
        self.assertIn("Multi-Minor Version Jump Detected", issue_body)
        self.assertIn("Automated Fallback Analysis", issue_body)

    @patch("urllib.request.urlopen")
    def test_call_gemini_security_and_schema(self, mock_urlopen):
        fake_response_content = {
            "has_breaking_changes": False,
            "severity": "none",
            "breaking_changes_summary": "None",
            "highlights": ["test highlight"],
            "rock_impact": {"summary": "none", "action_items": []},
            "charm_impact": {"summary": "none", "affected_components": [], "action_items": []},
            "testing_and_verification_matrix": {
                "automated_tests": ["tox -e unit"],
                "in_cluster_checks": ["pebble services"],
                "regression_probes": ["smoke test"]
            },
            "definition_of_done": ["done"]
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {"text": json.dumps(fake_response_content)}
                        ]
                    }
                }
            ]
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        fake_api_key = "secret-gemini-key-12345"
        res = call_gemini_rest("test prompt", fake_api_key)

        self.assertFalse(res["has_breaking_changes"])
        self.assertEqual(res["severity"], "none")

        called_req = mock_urlopen.call_args[0][0]
        self.assertNotIn(fake_api_key, called_req.full_url)
        self.assertEqual(called_req.headers.get("X-goog-api-key"), fake_api_key)
        payload = json.loads(called_req.data.decode("utf-8"))
        self.assertEqual(
            payload["generationConfig"]["responseSchema"],
            GEMINI_RESPONSE_SCHEMA
        )

    @patch("urllib.request.urlopen")
    def test_call_openrouter(self, mock_urlopen):
        fake_payload = {
            "choices": [
                {
                    "message": {
                        "content": '{"has_breaking_changes": true, "severity": "medium", "breaking_changes_summary": "Schema change"}'
                    }
                }
            ]
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(fake_payload).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        api_key = "sk-or-v1-secret-test-token"
        res = call_openrouter_rest("Test prompt", api_key=api_key)

        self.assertTrue(res["has_breaking_changes"])
        self.assertEqual(res["severity"], "medium")

        called_req = mock_urlopen.call_args[0][0]
        self.assertEqual(called_req.full_url, OPENROUTER_API_URL)
        self.assertEqual(called_req.headers.get("Authorization"), f"Bearer {api_key}")
        data = json.loads(called_req.data.decode("utf-8"))
        self.assertEqual(data["model"], OPENROUTER_MODEL)
        self.assertEqual(data["response_format"], {"type": "json_object"})

    @patch("check_upstream_release.OpenAI")
    def test_call_gemini_sdk(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_completion = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = '{"has_breaking_changes": false, "severity": "none"}'
        mock_completion.choices = [mock_choice]
        mock_client.chat.completions.create.return_value = mock_completion

        res = call_gemini_sdk("test prompt", "test-key")
        self.assertFalse(res["has_breaking_changes"])
        mock_openai_cls.assert_called_once_with(
            api_key="test-key",
            base_url=GEMINI_OPENAI_BASE_URL,
            timeout=60,
            max_retries=3
        )

    @patch("check_upstream_release.OpenAI")
    def test_call_openrouter_sdk(self, mock_openai_cls):
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_completion = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = '{"has_breaking_changes": true, "severity": "high"}'
        mock_completion.choices = [mock_choice]
        mock_client.chat.completions.create.return_value = mock_completion

        res = call_openrouter_sdk("test prompt", "test-or-key")
        self.assertTrue(res["has_breaking_changes"])
        mock_openai_cls.assert_called_once_with(
            api_key="test-or-key",
            base_url=OPENROUTER_BASE_URL,
            default_headers={
                "HTTP-Referer": "https://github.com/canonical/authentik-server-rock",
                "X-Title": "authentik-server-rock upstream checker",
            },
            timeout=60,
            max_retries=3
        )

    @patch("urllib.request.urlopen")
    def test_check_existing_pr(self, mock_urlopen):
        # Case 1: PR exists in GitHub API
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps([
            {"html_url": "https://github.com/canonical/authentik-server-rock/pull/36"}
        ]).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        pr_url = check_existing_pr("canonical/authentik-server-rock", "feat/auto-upstream-update")
        self.assertEqual(pr_url, "https://github.com/canonical/authentik-server-rock/pull/36")

        # Case 2: PR does not exist
        mock_resp2 = MagicMock()
        mock_resp2.read.return_value = json.dumps([]).encode("utf-8")
        mock_resp2.__enter__.return_value = mock_resp2
        mock_urlopen.return_value = mock_resp2

        pr_url2 = check_existing_pr("canonical/authentik-server-rock", "auto-update-authentik-9999.0")
        self.assertIsNone(pr_url2)

    @patch("check_upstream_release.call_gemini")
    @patch("check_upstream_release.call_openrouter")
    def test_analyze_with_llm_dispatch(self, mock_openrouter, mock_gemini):
        mock_gemini.return_value = {"has_breaking_changes": False, "provider": "gemini"}
        mock_openrouter.return_value = {"has_breaking_changes": False, "provider": "openrouter"}

        # Case 1: Gemini key provided
        res = analyze_with_llm("prompt", gemini_key="gem-key")
        self.assertEqual(res["provider"], "gemini")
        mock_gemini.assert_called_once()
        mock_openrouter.assert_not_called()

        # Case 2: Only OpenRouter key provided
        mock_gemini.reset_mock()
        mock_openrouter.reset_mock()
        res = analyze_with_llm("prompt", openrouter_key="or-key")
        self.assertEqual(res["provider"], "openrouter")
        mock_gemini.assert_not_called()
        mock_openrouter.assert_called_once()

        # Case 3: Both provided, but Gemini fails -> Fallback to OpenRouter
        mock_gemini.reset_mock()
        mock_openrouter.reset_mock()
        mock_gemini.side_effect = Exception("Gemini rate limit")
        res = analyze_with_llm("prompt", gemini_key="gem-key", openrouter_key="or-key")
        self.assertEqual(res["provider"], "openrouter")
        mock_gemini.assert_called_once()
        mock_openrouter.assert_called_once()

        # Case 4: Neither provided
        mock_gemini.reset_mock()
        mock_openrouter.reset_mock()
        res = analyze_with_llm("prompt")
        self.assertIsNone(res)

    @patch("check_upstream_release.check_existing_pr")
    @patch("check_upstream_release.fetch_all_upstream_releases")
    @patch("check_upstream_release.read_current_version")
    @patch("check_upstream_release.analyze_with_llm")
    @patch("check_upstream_release.write_github_output")
    def test_existing_pr_skips_analysis(
        self,
        mock_write_output,
        mock_analyze_llm,
        mock_read_ver,
        mock_fetch_releases,
        mock_check_pr,
    ):
        mock_read_ver.return_value = "2026.5.3"
        mock_fetch_releases.return_value = [
            {
                "tag_name": "version/2026.5.7",
                "html_url": "https://github.com/goauthentik/authentik/releases/tag/version/2026.5.7",
                "body": "Release notes"
            }
        ]
        mock_check_pr.return_value = "https://github.com/canonical/authentik-server-rock/pull/99"

        with patch("sys.argv", ["check_upstream_release.py", "--rockcraft-file", "rockcraft.yaml"]):
            from check_upstream_release import main
            ret = main()
            self.assertEqual(ret, 0)
            mock_analyze_llm.assert_not_called()
            mock_write_output.assert_any_call("has_new_release", "false")
            mock_write_output.assert_any_call("existing_pr_url", "https://github.com/canonical/authentik-server-rock/pull/99")

    @patch("check_upstream_release.call_gemini_sdk")
    def test_call_gemini_custom_model(self, mock_sdk):
        mock_sdk.return_value = {"has_breaking_changes": False}
        res = call_gemini("prompt", "key", model="gemini-3.7-flash")
        mock_sdk.assert_called_once_with("prompt", "key", model="gemini-3.7-flash", timeout=60)

    @patch("check_upstream_release.call_openrouter_sdk")
    def test_call_openrouter_custom_model(self, mock_sdk):
        mock_sdk.return_value = {"has_breaking_changes": False}
        res = call_openrouter("prompt", "key", model="google/gemini-3.6-flash")
        mock_sdk.assert_called_once_with("prompt", "key", model="google/gemini-3.6-flash", timeout=60)


if __name__ == "__main__":
    unittest.main()


