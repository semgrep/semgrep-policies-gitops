"""GitOps reconciler CLI for Semgrep policies.

Four verbs model the GitOps loop:

  validate  parse and structurally check the YAML files offline (no token,
            no network) — catches malformed YAML and wrong shapes fast
  export    pull the live state into the YAML files (bootstrap or drift repair)
  plan      dry-run every bundle and print the diff; the API validates values
            and references, so a bad value fails here
  apply     strictly apply every YAML file, using the etag from a fresh read
            as If-Match so a concurrent UI change is caught as a conflict

`validate` runs offline; `export`, `plan`, and `apply` take
`--deployment-id <id>` and read the token from the SEMGREP_API_TOKEN
environment variable.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from reconciler import bundles
from reconciler.client import Bundle
from reconciler.client import PoliciesApiError
from reconciler.client import PoliciesClient

# (file, product) for each detection bundle. Secrets is optional: a
# deployment without Semgrep Secrets returns 404 PRODUCT_NOT_ENABLED, which
# is treated as "skip", not "fail".
_DETECTION_TARGETS = [
    (bundles.DETECTION_CODE_FILE, "code"),
    (bundles.DETECTION_SECRETS_FILE, "secrets"),
]


def cmd_validate() -> int:
    """Offline structural validation of the policy files.

    Catches malformed YAML and wrong shapes without a token or network, so
    contributors (and fork PRs) get fast, local feedback before the API
    round-trip in `plan`.
    """
    checked = 0
    for path, _ in _DETECTION_TARGETS:
        raw = bundles.read_yaml(path)
        if not raw:
            continue
        bundles.validate_detection(path, raw)
        checked += 1

    remediation_raw = bundles.read_yaml(bundles.REMEDIATION_FILE)
    if remediation_raw:
        bundles.validate_remediation(bundles.REMEDIATION_FILE, remediation_raw)
        checked += 1

    print(f"validate: {checked} policy file(s) are well-formed")
    return 0


def _print_detection_diff(product: str, diff: dict[str, Any]) -> bool:
    changed = False
    for verb in ("creates", "updates", "deletes"):
        for entry in diff.get(verb, []):
            changed = True
            key = entry["key"]
            label = key.get("product") or key.get("scope_target") or key.get("rule")
            print(f"  detection/{product}: {verb[:-1]} {entry['kind']} {label}")
    return changed


def _print_remediation_diff(diff: dict[str, Any]) -> bool:
    changed = False
    for verb in ("creates", "updates", "deletes"):
        for entry in diff.get(verb, []):
            changed = True
            print(f"  remediation: {verb[:-1]} {entry['key']['slug']}")
    return changed


def _print_validation_errors(label: str, diff: dict[str, Any]) -> bool:
    """Print any validation errors a dry run reported in-band.

    A dry run returns 200 with `validation_errors` (and an empty diff) when the
    candidate is invalid, so every problem is reported at once. Returns True if
    any were present.
    """
    errors = diff.get("validation_errors") or []
    for error in errors:
        context = error.get("context") or {}
        detail = ", ".join(f"{key}={value}" for key, value in sorted(context.items()))
        slug = error.get("policy_slug")
        scope = f" [{slug}]" if slug else ""
        suffix = f" ({detail})" if detail else ""
        print(f"  {label}: {error.get('code')}{scope} {error.get('message', '')}{suffix}")
    return bool(errors)


def cmd_export(client: PoliciesClient) -> int:
    code = client.get_detection_policy("code")
    bundles.write_detection_yaml(bundles.DETECTION_CODE_FILE, code.data)
    print(f"wrote {bundles.DETECTION_CODE_FILE.name}")

    try:
        secrets = client.get_detection_policy("secrets")
        bundles.write_detection_yaml(bundles.DETECTION_SECRETS_FILE, secrets.data)
        print(f"wrote {bundles.DETECTION_SECRETS_FILE.name}")
    except PoliciesApiError as err:
        if err.code != "PRODUCT_NOT_ENABLED":
            raise
        print("skipped detection-secrets.yaml (Semgrep Secrets not enabled)")

    remediation = client.get_remediation_policies()
    bundles.write_remediation_yaml(bundles.REMEDIATION_FILE, remediation.data)
    print(f"wrote {bundles.REMEDIATION_FILE.name}")
    return 0


def cmd_plan(client: PoliciesClient, *, fail_on_diff: bool = False) -> int:
    changed = False
    invalid = False
    for path, product in _DETECTION_TARGETS:
        raw = bundles.read_yaml(path)
        if not raw:
            continue
        try:
            diff = client.dry_run_detection_policy(
                product, bundles.detection_to_bundle(raw)
            )
        except PoliciesApiError as err:
            if err.code == "PRODUCT_NOT_ENABLED":
                print(f"  detection/{product}: product not enabled, skipping")
                continue
            raise
        if _print_validation_errors(f"detection/{product}", diff):
            invalid = True
            continue
        changed |= _print_detection_diff(product, diff)

    remediation_raw = bundles.read_yaml(bundles.REMEDIATION_FILE)
    if remediation_raw:
        diff = client.dry_run_remediation_policies(
            bundles.remediation_to_bundle(remediation_raw)
        )
        if _print_validation_errors("remediation", diff):
            invalid = True
        else:
            changed |= _print_remediation_diff(diff)

    # A dry run reports an invalid candidate in-band (200 with
    # validation_errors); treat that as a hard failure, the same as a
    # structural error from `validate`.
    if invalid:
        print("\nplan: bundle is invalid; fix the errors above and retry")
        return 2

    if not changed:
        print("plan: live state matches this repo")
        return 0

    # A pending diff is normal on a PR — it is exactly what the reviewer is
    # there to approve. Only fail when asked to gate on drift (the nightly
    # drift check), so that a valid PR is not red just for proposing a change.
    print("\nplan: changes pending")
    return 1 if fail_on_diff else 0


def cmd_apply(client: PoliciesClient) -> int:
    for path, product in _DETECTION_TARGETS:
        raw = bundles.read_yaml(path)
        if not raw:
            continue
        try:
            current = client.get_detection_policy(product)
        except PoliciesApiError as err:
            if err.code == "PRODUCT_NOT_ENABLED":
                print(f"  detection/{product}: product not enabled, skipping")
                continue
            raise
        result = client.apply_detection_policy(
            product, bundles.detection_to_bundle(raw), current.state_version
        )
        print(f"applied detection/{product} (state_version {result.state_version})")

    remediation_raw = bundles.read_yaml(bundles.REMEDIATION_FILE)
    if remediation_raw:
        current_remediation: Bundle = client.get_remediation_policies()
        result = client.apply_remediation_policies(
            bundles.remediation_to_bundle(remediation_raw),
            current_remediation.state_version,
        )
        print(f"applied remediation (state_version {result.state_version})")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=["validate", "export", "plan", "apply"],
        help="the reconciler verb",
    )
    parser.add_argument(
        "--deployment-id",
        type=int,
        default=None,
        help="numeric Semgrep deployment id (required except for validate)",
    )
    parser.add_argument(
        "--base-url",
        default=None,
        help="API base URL (defaults to SEMGREP_APP_URL or https://semgrep.dev)",
    )
    parser.add_argument(
        "--fail-on-diff",
        action="store_true",
        help=(
            "make `plan` exit non-zero when the live state differs from this "
            "repo. Use for drift detection; leave off for PR review, where a "
            "pending diff is expected."
        ),
    )
    args = parser.parse_args(argv)

    try:
        # validate is fully offline: no token, no deployment id.
        if args.command == "validate":
            return cmd_validate()

        if args.deployment_id is None:
            parser.error(f"{args.command} requires --deployment-id")
        client = PoliciesClient(args.deployment_id, base_url=args.base_url)
        if args.command == "export":
            return cmd_export(client)
        if args.command == "plan":
            # Structural validation first, so malformed YAML fails fast and
            # locally rather than as an opaque API error.
            cmd_validate()
            return cmd_plan(client, fail_on_diff=args.fail_on_diff)
        cmd_validate()
        return cmd_apply(client)
    except bundles.BundleError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    except PoliciesApiError as err:
        print(f"error: {err}", file=sys.stderr)
        if err.code == "STATE_VERSION_MISMATCH":
            print(
                "  the live state changed since this repo was read; re-run "
                "`export`, reconcile, and retry.",
                file=sys.stderr,
            )
        elif err.details.get("missing_references"):
            for ref in err.details["missing_references"]:
                print(f"  missing {ref['kind']}: {ref['value']}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
