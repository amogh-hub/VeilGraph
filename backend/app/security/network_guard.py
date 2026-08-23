"""Application-process egress guard for competition offline mode.

The guard is deliberately fail-closed for Python socket connections and DNS
resolution. It is not presented as an operating-system firewall; competition
packaging still runs on localhost and should additionally rely on host/network
controls where available.
"""
from __future__ import annotations

import ipaddress
import socket
import sys
from collections.abc import Callable
from typing import Any

_original_create_connection: Callable = socket.create_connection
_installed = False
_guard_enabled = False
_audit_hook_installed = False


def _is_loopback_literal(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        # Never resolve arbitrary hostnames merely to decide whether they are
        # allowed; DNS itself would be an egress channel.
        return False


def _host_from_address(address: Any) -> str:
    if isinstance(address, tuple) and address:
        return str(address[0])
    return str(address)


def _audit_hook(event: str, args: tuple[Any, ...]) -> None:
    if not _guard_enabled:
        return
    if event == "socket.getaddrinfo":
        host = str(args[0]) if args else ""
        if not _is_loopback_literal(host):
            raise OSError(f"VeilGraph offline mode blocked DNS resolution for {host}")
    elif event == "socket.connect":
        address = args[1] if len(args) > 1 else ""
        host = _host_from_address(address)
        if not _is_loopback_literal(host):
            raise OSError(f"VeilGraph offline mode blocked external connection to {host}")


def install_egress_guard() -> None:
    global _installed, _guard_enabled, _audit_hook_installed
    _guard_enabled = True
    if not _audit_hook_installed:
        sys.addaudithook(_audit_hook)
        _audit_hook_installed = True
    if _installed:
        return

    def guarded_create_connection(address, *args, **kwargs):
        host = _host_from_address(address)
        if not _is_loopback_literal(host):
            raise OSError(f"VeilGraph offline mode blocked external connection to {host}")
        return _original_create_connection(address, *args, **kwargs)

    socket.create_connection = guarded_create_connection
    _installed = True


def disable_egress_guard_for_tests() -> None:
    """Disable enforcement without trying to remove Python's permanent audit hook."""
    global _guard_enabled
    _guard_enabled = False


def egress_guard_status() -> dict[str, bool]:
    return {
        "installed": _installed,
        "audit_hook_installed": _audit_hook_installed,
        "enforcement_enabled": _guard_enabled,
        "dns_fail_closed": True,
    }
