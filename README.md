# Semgrep policies as code — GitOps reference

A worked example of managing [Semgrep](https://semgrep.dev) detection and
remediation policies with GitOps, using the **Policies V2 API**. Your policy
state lives in this repo as YAML; a reconciler reads it, previews the diff,
and strictly applies it to your deployment. Pull requests are gated on the
diff, a merge to `main` applies immediately, and a nightly read-only check
flags changes made out of band in the UI.

This is a reference implementation — fork it, point it at your deployment,
and adapt the policy files. It has no dependency on Semgrep internals; it
only calls the public, documented API.

## Why GitOps for policies

The API is built for a Kubernetes-style apply loop:

1. **Read** the current state (`GET`), which returns a bundle plus a
   `state_version` etag.
2. **Plan** by dry-running your desired bundle (`POST .../:dryRun`), which
   returns the exact creates / updates / deletes an apply would make,
   without changing anything.
3. **Apply** strictly (`PUT` with `If-Match: <state_version>`): the
   submitted bundle replaces the live state, items you removed are deleted,
   and a concurrent UI edit is caught as a `409` instead of being silently
   clobbered.

The server owns the diff, slug handling, and concurrency control, so the
client in this repo stays thin.

## Layout

```
policies/
  detection-code.yaml      which Semgrep Code rules run, and per-project carve-outs
  detection-secrets.yaml   same for Semgrep Secrets (optional; omit if not enabled)
  remediation.yaml         what happens when a finding matches (block, comment, ...)
reconciler/                the GitOps client + CLI (export / plan / apply)
.github/workflows/         plan on PRs, apply on merge + nightly
```

## Quick start

```bash
uv sync
export SEMGREP_API_TOKEN="<your web API token>"   # never commit this

# Bootstrap the YAML from your live deployment:
uv run python -m reconciler.cli export --deployment-id <id>

# Edit policies/*.yaml, then check them offline (no token needed):
uv run python -m reconciler.cli validate

# Preview what an apply would change against the live deployment:
uv run python -m reconciler.cli plan --deployment-id <id>

# Apply (this is what CI runs on merge):
uv run python -m reconciler.cli apply --deployment-id <id>
```

`validate` is offline and structural; `plan` adds the server-side semantic
check and prints the diff. On the nightly drift check, `plan --fail-on-diff`
exits non-zero when the live state has drifted from this repo.

## The policy files

### Detection (`detection-code.yaml`, `detection-secrets.yaml`)

One bundle per product. `rulesets` are registry ruleset paths (`p/...`),
`rules` are individual registry rule paths, `disabled` turns off rules from
the selected rulesets, and `exceptions` are per-project or per-tag
include/exclude carve-outs. Secrets bundles do not accept `rulesets`.

### Remediation (`remediation.yaml`)

A list of policies, each a filter (conditions over finding attributes) plus
actions. `slug` is the stable identity — omit it on a new policy and it is
derived from the name; renaming a policy keeps its slug. Some actions
require a companion: `block` must be paired with `pr_comment` in the same
policy.

The accepted condition types, action types, and value enums are published
by the API itself:

```bash
curl -H "Authorization: Bearer $SEMGREP_API_TOKEN" \
  "$SEMGREP_APP_URL/api/policies/v2/deployments/<id>/vocab?product=remediation"
```

Validate your YAML against that vocabulary in CI to catch typos before an
apply.

## CI setup

The workflows expect two repository settings:

- **Secret** `SEMGREP_API_TOKEN` — a Semgrep web API token. Store it as an
  Actions secret; it is never read from the repo.
- **Variable** `SEMGREP_DEPLOYMENT_ID` — your numeric deployment id.

The PR checks are layered, cheapest first:

- `validate.yml` runs on PRs that touch `policies/` (and needs no token, so
  it works on PRs from forks): it parses the YAML and checks its shape
  offline. Malformed YAML or a wrong-shaped policy fails here, fast, before
  any network call.
- `plan.yml` dry-runs the PR's policies against the live deployment and
  prints the diff. A pending diff is the change under review, so it passes;
  the API's semantic validation fails it on a bad **value** or reference
  (an unknown rule, a typo'd severity, `block` without `pr_comment`).
- `test.yml` runs the reconciler's unit tests; it is scoped to PRs that
  touch `reconciler/`, `tests/`, or the dependencies, so a policy-only PR
  is gated purely on its policy files.
- `apply.yml` runs on every merge to `main` (and on demand): a merge writes
  to the deployment immediately. This is the only path that writes.
- `drift.yml` runs nightly (and on demand), read-only: it runs
  `plan --fail-on-diff`, so it fails if the live state has been changed in
  the UI out of band — but it never writes.

So `validate` catches structural mistakes locally and offline, while `plan`
catches semantic ones (values, references, action dependencies) that only
the server can judge. Every action is pinned to a full commit SHA.

## Requirements

- The deployment must be on Semgrep's Unified Policies model. The API
  returns `403 DEPLOYMENT_NOT_MIGRATED` otherwise.
- The token must be a web API token (not a browser session).

## Error codes worth handling

The API returns stable, machine-readable error codes. The reconciler maps
the common ones to actionable messages:

| Code | Meaning |
| --- | --- |
| `STATE_VERSION_MISMATCH` (409) | the live state changed since you read it — re-export and retry |
| `IF_MATCH_REQUIRED` (428) | an apply was sent without the `If-Match` etag |
| `UNKNOWN_REFERENCE` (400) | a referenced project, tag, rule, or ruleset does not exist |
| `MISSING_DEPENDENT_ACTION` (400) | an action is missing a required companion (e.g. `block` without `pr_comment`) |
| `RESERVED_SLUG` (409) | a policy slug collides with a system-managed policy |
| `PRODUCT_NOT_ENABLED` (404) | the product (e.g. Secrets) is not enabled for the deployment |
