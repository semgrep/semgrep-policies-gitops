"""Offline tests for the reconciler, with the API mocked.

These exercise the client's etag handling and error mapping without a live
deployment. The recorded responses mirror the live API shapes verified
against a real Semgrep deployment.
"""

from __future__ import annotations

import pytest
import responses

from reconciler import bundles
from reconciler import cli
from reconciler.client import PoliciesApiError
from reconciler.client import PoliciesClient

_BASE = "https://example.test"
_DEPLOYMENT = 524
_PREFIX = f"{_BASE}/api/policies/v2/deployments/{_DEPLOYMENT}"

_EMPTY_DIFF = {"creates": [], "updates": [], "deletes": []}
_PENDING_DIFF = {
    "creates": [{"kind": "RemediationPolicy", "key": {"slug": "new-policy"}}],
    "updates": [],
    "deletes": [],
}


def _client() -> PoliciesClient:
    return PoliciesClient(_DEPLOYMENT, token="fake-token", base_url=_BASE)


@responses.activate
def test_get_detection_policy_returns_bundle_and_etag():
    responses.get(
        f"{_PREFIX}/detection-policy/code",
        json={"bundle": {"rulesets": ["p/default"]}, "state_version": "abc123"},
    )

    bundle = _client().get_detection_policy("code")

    assert bundle.data["rulesets"] == ["p/default"]
    assert bundle.state_version == "abc123"


@responses.activate
def test_apply_sends_if_match_header():
    responses.put(
        f"{_PREFIX}/remediation-policies",
        json={"bundle": {"policies": []}, "state_version": "def456"},
    )

    _client().apply_remediation_policies({"policies": []}, "abc123")

    assert responses.calls[0].request.headers["If-Match"] == "abc123"


@responses.activate
def test_state_version_mismatch_raises_with_code_and_current_version():
    responses.put(
        f"{_PREFIX}/remediation-policies",
        status=409,
        json={
            "error": "The bundle changed since the state_version in If-Match was read.",
            "code": "STATE_VERSION_MISMATCH",
            "current_state_version": "newsv",
        },
    )

    with pytest.raises(PoliciesApiError) as exc_info:
        _client().apply_remediation_policies({"policies": []}, "stale")

    assert exc_info.value.status == 409
    assert exc_info.value.code == "STATE_VERSION_MISMATCH"
    assert exc_info.value.details["current_state_version"] == "newsv"


@responses.activate
def test_missing_dependent_action_surfaces_companion():
    responses.put(
        f"{_PREFIX}/remediation-policies",
        status=400,
        json={
            "error": "block requires pr_comment",
            "code": "MISSING_DEPENDENT_ACTION",
            "missing_companion": "pr_comment",
        },
    )

    with pytest.raises(PoliciesApiError) as exc_info:
        _client().apply_remediation_policies({"policies": []}, "abc")

    assert exc_info.value.code == "MISSING_DEPENDENT_ACTION"
    assert exc_info.value.details["missing_companion"] == "pr_comment"


def test_missing_token_is_a_clear_error(monkeypatch):
    monkeypatch.delenv("SEMGREP_API_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="SEMGREP_API_TOKEN"):
        PoliciesClient(_DEPLOYMENT, base_url=_BASE)


def _stub_plan_responses(remediation_diff):
    """Stub the three dry-runs cmd_plan issues against the demo policies."""
    responses.post(f"{_PREFIX}/detection-policy/code:dryRun", json=_EMPTY_DIFF)
    responses.post(
        f"{_PREFIX}/detection-policy/secrets:dryRun",
        status=404,
        json={"code": "PRODUCT_NOT_ENABLED"},
    )
    responses.post(
        f"{_PREFIX}/remediation-policies:dryRun", json=remediation_diff
    )


@responses.activate
def test_plan_passes_on_clean_state():
    _stub_plan_responses(_EMPTY_DIFF)
    assert cli.cmd_plan(_client()) == 0


@responses.activate
def test_plan_with_pending_diff_passes_by_default():
    # On a PR, a pending diff is the change under review, not a failure.
    _stub_plan_responses(_PENDING_DIFF)
    assert cli.cmd_plan(_client()) == 0


@responses.activate
def test_plan_with_pending_diff_fails_when_gating_on_drift():
    # The nightly drift check passes --fail-on-diff.
    _stub_plan_responses(_PENDING_DIFF)
    assert cli.cmd_plan(_client(), fail_on_diff=True) == 1


def test_validate_accepts_the_shipped_policies():
    # The policy files in this repo must always pass offline validation.
    assert cli.cmd_validate() == 0


def test_read_yaml_rejects_malformed_yaml(tmp_path):
    bad = tmp_path / "remediation.yaml"
    bad.write_text("policies:\n  - name: x\n   actions: oops\n")  # bad indent
    with pytest.raises(bundles.BundleError, match="not valid YAML"):
        bundles.read_yaml(bad)


def test_read_yaml_rejects_non_utf8(tmp_path):
    bad = tmp_path / "remediation.yaml"
    bad.write_bytes(b"\xff\xfe policies: []")
    with pytest.raises(bundles.BundleError, match="UTF-8"):
        bundles.read_yaml(bad)


def test_read_yaml_rejects_oversize_file(tmp_path):
    big = tmp_path / "remediation.yaml"
    big.write_text("policies: []\n" + "# pad\n" * 200_000)
    with pytest.raises(bundles.BundleError, match="over the"):
        bundles.read_yaml(big)


def test_read_yaml_rejects_non_mapping(tmp_path):
    bad = tmp_path / "remediation.yaml"
    bad.write_text("- just\n- a\n- list\n")
    with pytest.raises(bundles.BundleError, match="must be a YAML mapping"):
        bundles.read_yaml(bad)


def test_validate_remediation_rejects_actionless_policy(tmp_path):
    path = tmp_path / "remediation.yaml"
    raw = {"policies": [{"name": "x", "filters": {"mode": "all"}, "actions": []}]}
    with pytest.raises(bundles.BundleError, match="at least one action"):
        bundles.validate_remediation(path, raw)


def test_validate_detection_rejects_exception_with_both_scopes(tmp_path):
    path = tmp_path / "detection-code.yaml"
    raw = {
        "exceptions": [
            {"project": "a", "project_tag_name": "b", "rule": "x", "rule_type": "rule"}
        ]
    }
    with pytest.raises(bundles.BundleError, match="exactly one"):
        bundles.validate_detection(path, raw)


@responses.activate
def test_plan_main_returns_2_on_invalid_bundle(monkeypatch):
    monkeypatch.setenv("SEMGREP_API_TOKEN", "fake-token")
    responses.post(f"{_PREFIX}/detection-policy/code:dryRun", json=_EMPTY_DIFF)
    responses.post(
        f"{_PREFIX}/detection-policy/secrets:dryRun",
        status=404,
        json={"code": "PRODUCT_NOT_ENABLED"},
    )
    responses.post(
        f"{_PREFIX}/remediation-policies:dryRun",
        status=400,
        json={"code": "MISSING_DEPENDENT_ACTION", "missing_companion": "pr_comment"},
    )
    exit_code = cli.main(
        ["plan", "--deployment-id", str(_DEPLOYMENT), "--base-url", _BASE]
    )
    assert exit_code == 2
