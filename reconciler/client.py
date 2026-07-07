"""Minimal HTTP client for the Semgrep Policies V2 API.

The client is intentionally thin: it knows the endpoint shapes and how to
carry the ``state_version`` etag through the ``If-Match`` header, and it
surfaces the API's structured error codes as exceptions. Everything else
(diffing, slug derivation, concurrency) lives on the server.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import requests

DEFAULT_BASE_URL = "https://semgrep.dev"
_TOKEN_ENV_VAR = "SEMGREP_API_TOKEN"


class PoliciesApiError(RuntimeError):
    """An error response from the API.

    ``code`` is the stable machine-readable error code from the response
    body (for example ``STATE_VERSION_MISMATCH``); ``details`` is the full
    parsed body, so callers can read fields like ``current_state_version``
    or ``missing_references`` without reparsing.
    """

    def __init__(self, status: int, body: dict[str, Any]) -> None:
        self.status = status
        self.code = body.get("code", "")
        self.details = body
        message = body.get("error") or f"HTTP {status}"
        super().__init__(f"[{status} {self.code or 'error'}] {message}")


@dataclass(frozen=True)
class Bundle:
    """A bundle paired with the etag it was read at."""

    data: dict[str, Any]
    state_version: str


class PoliciesClient:
    def __init__(
        self,
        deployment_id: int,
        *,
        token: str | None = None,
        base_url: str | None = None,
    ) -> None:
        resolved_token = token or os.environ.get(_TOKEN_ENV_VAR)
        if not resolved_token:
            raise RuntimeError(
                f"No API token. Set the {_TOKEN_ENV_VAR} environment variable "
                "to a Semgrep web API token."
            )
        self._deployment_id = deployment_id
        self._base = (base_url or os.environ.get("SEMGREP_APP_URL") or DEFAULT_BASE_URL).rstrip(
            "/"
        )
        self._session = requests.Session()
        self._session.headers["Authorization"] = f"Bearer {resolved_token}"

    # -- Detection policies ------------------------------------------------

    def get_detection_policy(self, product: str) -> Bundle:
        body = self._request("GET", f"detection-policy/{product}")
        return Bundle(data=body["bundle"], state_version=body["state_version"])

    def dry_run_detection_policy(
        self, product: str, bundle: dict[str, Any]
    ) -> dict[str, Any]:
        return self._request(
            "POST", f"detection-policy/{product}:dryRun", json={"bundle": bundle}
        )

    def apply_detection_policy(
        self, product: str, bundle: dict[str, Any], state_version: str
    ) -> Bundle:
        body = self._request(
            "PUT",
            f"detection-policy/{product}",
            json={"bundle": bundle},
            if_match=state_version,
        )
        return Bundle(data=body["bundle"], state_version=body["state_version"])

    # -- Remediation policies ----------------------------------------------

    def get_remediation_policies(self) -> Bundle:
        body = self._request("GET", "remediation-policies")
        return Bundle(data=body["bundle"], state_version=body["state_version"])

    def dry_run_remediation_policies(self, bundle: dict[str, Any]) -> dict[str, Any]:
        return self._request(
            "POST", "remediation-policies:dryRun", json={"bundle": bundle}
        )

    def apply_remediation_policies(
        self, bundle: dict[str, Any], state_version: str
    ) -> Bundle:
        body = self._request(
            "PUT",
            "remediation-policies",
            json={"bundle": bundle},
            if_match=state_version,
        )
        return Bundle(data=body["bundle"], state_version=body["state_version"])

    # -- Vocabulary --------------------------------------------------------

    def get_vocab(self, product: str | None = None) -> dict[str, Any]:
        params = {"product": product} if product else None
        return self._request("GET", "vocab", params=params)

    # -- Internals ---------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
        if_match: str | None = None,
    ) -> dict[str, Any]:
        url = (
            f"{self._base}/api/policies/v2/deployments/"
            f"{self._deployment_id}/{path}"
        )
        headers = {"If-Match": if_match} if if_match else None
        response = self._session.request(
            method, url, json=json, params=params, headers=headers, timeout=30
        )
        if not response.ok:
            try:
                body = response.json()
            except ValueError:
                body = {"error": response.text}
            raise PoliciesApiError(response.status_code, body)
        return response.json()
