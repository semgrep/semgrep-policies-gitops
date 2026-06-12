"""Translate between the YAML files in this repo and API bundle payloads.

The on-disk YAML is the desired state; these helpers strip the output-only
fields the API returns on reads (``deployment_slug``, ``product``) so a
file written by ``export`` round-trips cleanly through ``apply``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

POLICIES_DIR = Path(__file__).resolve().parent.parent / "policies"

DETECTION_CODE_FILE = POLICIES_DIR / "detection-code.yaml"
DETECTION_SECRETS_FILE = POLICIES_DIR / "detection-secrets.yaml"
REMEDIATION_FILE = POLICIES_DIR / "remediation.yaml"

# Fields the API returns on reads but ignores in request bodies. Dropping
# them keeps the YAML free of values a customer should not hand-edit.
_DETECTION_OUTPUT_ONLY = ("deployment_slug", "product")
_REMEDIATION_OUTPUT_ONLY = ("deployment_slug",)


# Policy files are tiny (a few KB). The cap is basic hygiene — it bounds
# the input we hand to the YAML parser and rejects an obviously wrong file
# before parsing. It is not a defense against a hand-crafted YAML
# alias-expansion bomb; this repo relies on PR review for that, since every
# change to policies/ is reviewed before it can run.
_MAX_POLICY_FILE_BYTES = 256 * 1024


class BundleError(ValueError):
    """A policy file is malformed or structurally wrong.

    Raised before any API call, so honest mistakes — a YAML syntax error, a
    wrong-shaped policy — are caught locally and on fork PRs (which have no
    API token), with a clear message instead of a stack trace.
    """


def detection_to_bundle(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "rulesets": raw.get("rulesets", []),
        "rules": raw.get("rules", []),
        "disabled": raw.get("disabled", []),
        "exceptions": raw.get("exceptions", []),
    }


def remediation_to_bundle(raw: dict[str, Any]) -> dict[str, Any]:
    return {"policies": raw.get("policies", [])}


def write_yaml(path: Path, bundle: dict[str, Any], drop: tuple[str, ...]) -> None:
    cleaned = {key: value for key, value in bundle.items() if key not in drop}
    path.write_text(
        yaml.safe_dump(cleaned, sort_keys=False, default_flow_style=False)
    )


def write_detection_yaml(path: Path, bundle: dict[str, Any]) -> None:
    write_yaml(path, bundle, _DETECTION_OUTPUT_ONLY)


def write_remediation_yaml(path: Path, bundle: dict[str, Any]) -> None:
    write_yaml(path, bundle, _REMEDIATION_OUTPUT_ONLY)


def read_yaml(path: Path) -> dict[str, Any]:
    """Parse a policy file, turning a YAML syntax error into a clear message.

    A missing file is an empty document (that bundle is simply not managed
    from this repo). Anything that parses to a non-mapping is rejected.
    """
    if not path.exists():
        return {}
    size = path.stat().st_size
    if size > _MAX_POLICY_FILE_BYTES:
        raise BundleError(
            f"{path.name} is {size} bytes, over the "
            f"{_MAX_POLICY_FILE_BYTES}-byte limit for a policy file"
        )
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError) as err:
        raise BundleError(f"{path.name} could not be read as UTF-8 text: {err}") from err
    try:
        loaded = yaml.safe_load(text)
    except yaml.YAMLError as err:
        raise BundleError(f"{path.name} is not valid YAML: {err}") from err
    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise BundleError(
            f"{path.name} must be a YAML mapping, got {type(loaded).__name__}"
        )
    return loaded


def validate_detection(path: Path, raw: dict[str, Any]) -> None:
    """Structural checks for a detection file (offline, no API)."""
    for field in ("rulesets", "rules", "disabled"):
        value = raw.get(field, [])
        if not isinstance(value, list):
            raise BundleError(f"{path.name}: `{field}` must be a list")
        if not all(isinstance(item, str) for item in value):
            raise BundleError(f"{path.name}: every `{field}` entry must be a string")
    exceptions = raw.get("exceptions", [])
    if not isinstance(exceptions, list):
        raise BundleError(f"{path.name}: `exceptions` must be a list")
    for index, exception in enumerate(exceptions):
        if not isinstance(exception, dict):
            raise BundleError(f"{path.name}: exception #{index + 1} must be a mapping")
        has_project = "project" in exception
        has_tag = "project_tag_name" in exception
        if has_project == has_tag:
            raise BundleError(
                f"{path.name}: exception #{index + 1} must set exactly one of "
                "`project` or `project_tag_name`"
            )


def validate_remediation(path: Path, raw: dict[str, Any]) -> None:
    """Structural checks for the remediation file (offline, no API)."""
    policies = raw.get("policies", [])
    if not isinstance(policies, list):
        raise BundleError(f"{path.name}: `policies` must be a list")
    for index, policy in enumerate(policies):
        where = f"{path.name}: policy #{index + 1}"
        if not isinstance(policy, dict):
            raise BundleError(f"{where} must be a mapping")
        if not policy.get("name"):
            raise BundleError(f"{where} is missing a `name`")
        actions = policy.get("actions", [])
        if not isinstance(actions, list) or not actions:
            raise BundleError(f"{where} ({policy.get('name')}) needs at least one action")
        filters = policy.get("filters", {})
        if not isinstance(filters, dict):
            raise BundleError(f"{where} ({policy['name']}): `filters` must be a mapping")
