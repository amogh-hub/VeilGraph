from __future__ import annotations

import ipaddress
import secrets
from dataclasses import dataclass
from typing import Mapping, Sequence


@dataclass(frozen=True)
class DeploymentDecision:
    allowed: bool
    status_code: int
    detail: str


def is_loopback_host(host: str) -> bool:
    if host.lower() in {"localhost", "testclient"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _parse_proxy_networks(networks: Sequence[str]) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    parsed: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for raw in networks:
        value = str(raw).strip()
        if not value:
            continue
        network = ipaddress.ip_network(value, strict=False)
        if network.prefixlen == 0:
            raise ValueError("Trusted proxy networks may not include a universal /0 network")
        parsed.append(network)
    return tuple(parsed)


def is_trusted_proxy_host(host: str, networks: Sequence[str]) -> bool:
    try:
        address = ipaddress.ip_address(host)
        parsed = _parse_proxy_networks(networks)
    except ValueError:
        return False
    return any(address.version == network.version and address in network for network in parsed)


def validate_online_configuration(
    *,
    offline_mode: bool,
    api_token: str | None,
    require_https: bool,
    trust_proxy_headers: bool = False,
    trusted_proxy_networks: Sequence[str] = (),
) -> None:
    if offline_mode:
        return
    token = (api_token or "").strip()
    if len(token) < 32:
        raise RuntimeError("Secure-online mode requires VEILGRAPH_ONLINE_API_TOKEN with at least 32 characters")
    if not require_https:
        raise RuntimeError("Secure-online mode refuses to start with HTTPS enforcement disabled")
    if trust_proxy_headers:
        try:
            parsed = _parse_proxy_networks(trusted_proxy_networks)
        except ValueError as exc:
            raise RuntimeError(f"Invalid VEILGRAPH_TRUSTED_PROXY_NETWORKS: {exc}") from exc
        if not parsed:
            raise RuntimeError(
                "VEILGRAPH_TRUST_PROXY_HEADERS=true requires at least one explicit trusted proxy network"
            )


def authorize_request(
    *,
    offline_mode: bool,
    client_host: str,
    headers: Mapping[str, str],
    url_scheme: str,
    configured_token: str | None,
    require_https: bool,
    trust_proxy_headers: bool = False,
    trusted_proxy_networks: Sequence[str] = (),
) -> DeploymentDecision:
    if offline_mode:
        if is_loopback_host(client_host):
            return DeploymentDecision(True, 200, "local offline client")
        return DeploymentDecision(False, 403, "Offline mode accepts localhost clients only")

    if require_https:
        direct_https = url_scheme.lower() == "https"
        forwarded_https = False
        if trust_proxy_headers and is_trusted_proxy_host(client_host, trusted_proxy_networks):
            forwarded = headers.get("x-forwarded-proto", "").split(",", 1)[0].strip().lower()
            forwarded_https = forwarded == "https"
        if not (direct_https or forwarded_https):
            return DeploymentDecision(False, 426, "Secure-online mode requires HTTPS")

    expected = (configured_token or "").strip()
    authorization = headers.get("authorization", "")
    supplied = authorization[7:] if authorization.lower().startswith("bearer ") else ""
    if not expected or not supplied or not secrets.compare_digest(supplied, expected):
        return DeploymentDecision(False, 401, "Secure-online mode requires a valid bearer token")
    return DeploymentDecision(True, 200, "authenticated secure-online client")
