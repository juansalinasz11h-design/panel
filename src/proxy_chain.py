"""Multi-egress proxy router: supports Cloudflare WARP, Tor Network, and Custom SOCKS5/HTTP."""

from __future__ import annotations

import json
import os
import socket
from typing import Literal

from ouc_common import LANE_DIR, ensure_dirs
from tor_manager import (
    get_active_tor_target,
    open_socks5_tunnel,
    start_portable_tor,
)

import sys

EgressType = Literal["warp", "tor", "custom", "clean"]
EGRESS_CONFIG_FILE = LANE_DIR / "egress_mode.json"


def get_default_warp_scope() -> str:
    return "tun" if sys.platform == "win32" else "isolated"


def get_egress_config() -> dict:
    """Read the active egress routing configuration."""
    default_scope = get_default_warp_scope()
    if EGRESS_CONFIG_FILE.is_file():
        try:
            cfg = json.loads(EGRESS_CONFIG_FILE.read_text(encoding="utf-8"))
            if "warp_scope" not in cfg:
                cfg["warp_scope"] = default_scope
            return cfg
        except Exception:
            pass
    return {
        "mode": "warp",
        "warp_scope": default_scope,
        "custom_proxy": "127.0.0.1:10808",
        "custom_type": "socks5",
    }


def set_egress_config(
    mode: EgressType,
    custom_proxy: str = "127.0.0.1:10808",
    custom_type: str = "socks5",
    warp_scope: str | None = None,
) -> dict:
    """Save the active egress configuration."""
    ensure_dirs()
    if warp_scope is None or not warp_scope.strip():
        chosen_scope = get_default_warp_scope()
    else:
        chosen_scope = "tun" if warp_scope.lower().strip() == "tun" else "isolated"
    cfg = {
        "mode": mode,
        "warp_scope": chosen_scope,
        "custom_proxy": custom_proxy.strip(),
        "custom_type": custom_type.lower().strip(),
    }
    EGRESS_CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    try:
        (LANE_DIR / "custom_proxy_index.txt").write_text("0", encoding="utf-8")
    except Exception:
        pass
    return cfg


PROXY_INDEX_FILE = LANE_DIR / "custom_proxy_index.txt"


def _parse_proxy_entry(raw: str, default_type: str = "socks5") -> dict | None:
    """Parse one ``[scheme://][user:pass@]host:port`` proxy entry."""
    from urllib.parse import unquote

    text = raw.strip()
    if not text:
        return None
    scheme = ""
    if "://" in text:
        scheme, text = text.split("://", 1)
        scheme = scheme.lower().strip()
    text = text.strip().rstrip("/")
    username = ""
    password = ""
    if "@" in text:
        userinfo, text = text.rsplit("@", 1)
        if ":" in userinfo:
            username, password = userinfo.split(":", 1)
        else:
            username = userinfo
        username = unquote(username)
        password = unquote(password)

    host = ""
    port = 0
    if text.startswith("["):
        end = text.find("]")
        if end != -1:
            host = text[1:end]
            rest = text[end + 1 :].lstrip(":")
            if rest.isdigit():
                port = int(rest)
    else:
        phost, sep, pport = text.rpartition(":")
        if sep and pport.isdigit():
            host = phost.strip("[] ")
            port = int(pport)
        elif text.isdigit():
            host, port = "127.0.0.1", int(text)
    if not host or not 0 < port < 65536:
        return None
    proxy_type = scheme if scheme in ("socks5", "socks5h", "http", "https") else default_type
    if proxy_type == "https":
        proxy_type = "http"
    if proxy_type.startswith("socks"):
        proxy_type = "socks5"
    return {
        "host": host,
        "port": port,
        "type": proxy_type,
        "username": username,
        "password": password,
    }


def parse_proxy_specs(raw: str, default_type: str = "socks5") -> list[dict]:
    """Parse a comma/semicolon/space/newline delimited proxy pool."""
    import re

    entries = re.split(r"[,;\s\n\r]+", (raw or "").strip())
    specs = []
    for item in entries:
        spec = _parse_proxy_entry(item, default_type)
        if spec:
            specs.append(spec)
    if not specs:
        specs = [
            {
                "host": "127.0.0.1",
                "port": 10808,
                "type": default_type if default_type in ("socks5", "http") else "socks5",
                "username": "",
                "password": "",
            }
        ]
    return specs


def parse_proxy_list(raw: str) -> list[tuple[str, int]]:
    """Parse comma, semicolon, space, or newline delimited proxies."""
    return [(s["host"], s["port"]) for s in parse_proxy_specs(raw)]


def _proxy_index(total: int) -> int:
    idx = 0
    if PROXY_INDEX_FILE.is_file():
        try:
            idx = int(PROXY_INDEX_FILE.read_text(encoding="utf-8").strip())
        except Exception:
            idx = 0
    return idx % max(1, total)


def get_current_proxy_spec() -> dict:
    """Return the active custom proxy entry with type and credentials."""
    cfg = get_egress_config()
    default_type = str(cfg.get("custom_type", "socks5")).lower()
    specs = parse_proxy_specs(
        cfg.get("custom_proxy", "127.0.0.1:10808"), default_type
    )
    return specs[_proxy_index(len(specs))]


def get_current_custom_proxy() -> tuple[str, int, int, int]:
    """Return (host, port, current_index, total_count)."""
    cfg = get_egress_config()
    default_type = str(cfg.get("custom_type", "socks5")).lower()
    specs = parse_proxy_specs(
        cfg.get("custom_proxy", "127.0.0.1:10808"), default_type
    )
    idx = _proxy_index(len(specs))
    spec = specs[idx]
    return spec["host"], spec["port"], idx, len(specs)


def rotate_custom_proxy() -> tuple[bool, str]:
    """Rotate to the next working proxy node in the custom proxy pool."""
    ensure_dirs()
    cfg = get_egress_config()
    default_type = str(cfg.get("custom_type", "socks5")).lower()
    specs = parse_proxy_specs(
        cfg.get("custom_proxy", "127.0.0.1:10808"), default_type
    )
    if len(specs) <= 1:
        spec = specs[0]
        return False, (
            f"Only one proxy is configured ({spec['host']}:{spec['port']}); "
            "add another node to rotate exits."
        )

    original = _proxy_index(len(specs))
    if cfg.get("mode") != "custom":
        new_idx = (original + 1) % len(specs)
        PROXY_INDEX_FILE.write_text(str(new_idx), encoding="utf-8")
        spec = specs[new_idx]
        return True, (
            f"Switched to proxy #{new_idx + 1}/{len(specs)}: "
            f"{spec['host']}:{spec['port']}"
        )

    # Verify each candidate through the proxy itself before reporting success.
    from ouc_common import get_egress_ip

    for step in range(1, len(specs)):
        new_idx = (original + step) % len(specs)
        PROXY_INDEX_FILE.write_text(str(new_idx), encoding="utf-8")
        spec = specs[new_idx]
        exit_ip = get_egress_ip(timeout=5.0)
        if exit_ip:
            return True, (
                f"Switched to proxy #{new_idx + 1}/{len(specs)}: "
                f"{spec['host']}:{spec['port']} (exit {exit_ip})"
            )

    PROXY_INDEX_FILE.write_text(str(original), encoding="utf-8")
    current = specs[original]
    return False, (
        "None of the other proxy nodes answered; kept "
        f"{current['host']}:{current['port']} (#{original + 1}/{len(specs)})."
    )


def advance_custom_proxy() -> dict:
    """Move to the next proxy node without a blocking reachability test.

    Request-path failover has to stay fast. ``rotate_custom_proxy`` keeps the
    verification that the Next Node button needs; routers use this instead.
    """
    ensure_dirs()
    cfg = get_egress_config()
    default_type = str(cfg.get("custom_type", "socks5")).lower()
    specs = parse_proxy_specs(
        cfg.get("custom_proxy", "127.0.0.1:10808"), default_type
    )
    idx = _proxy_index(len(specs))
    new_idx = (idx + 1) % len(specs)
    try:
        PROXY_INDEX_FILE.write_text(str(new_idx), encoding="utf-8")
    except Exception:
        pass
    return specs[new_idx]


def _basic_auth_header(username: str, password: str) -> str:
    import base64

    token = base64.b64encode(
        f"{username}:{password}".encode("utf-8")
    ).decode("ascii")
    return f"Proxy-Authorization: Basic {token}\r\n"


def open_http_proxy_tunnel(
    dest_host: str,
    dest_port: int,
    proxy_host: str,
    proxy_port: int,
    timeout: float = 12.0,
    username: str = "",
    password: str = "",
) -> socket.socket:
    """Connect to an upstream HTTP proxy and negotiate CONNECT tunnel."""
    s = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        auth = _basic_auth_header(username, password) if username else ""
        req = (
            f"CONNECT {dest_host}:{dest_port} HTTP/1.1\r\n"
            f"Host: {dest_host}:{dest_port}\r\n"
            f"{auth}"
            f"Proxy-Connection: Keep-Alive\r\n\r\n"
        )
        s.sendall(req.encode("utf-8"))
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = s.recv(4096)
            if not chunk:
                raise ConnectionError("Upstream HTTP proxy closed connection.")
            resp += chunk
            if len(resp) > 65536:
                raise ConnectionError("Upstream HTTP proxy reply is too large.")
        status_line = resp.split(b"\r\n", 1)[0].decode("latin-1")
        if " 200 " not in status_line:
            raise ConnectionError(
                f"Upstream HTTP proxy rejected CONNECT: {status_line}"
            )
        s.settimeout(None)
        return s
    except Exception:
        s.close()
        raise


def open_multi_egress_upstream(host: str, port: int, warp_fallback_fn) -> socket.socket:
    """Route an outbound connection according to the active egress mode with auto-healing and failover."""
    cfg = get_egress_config()
    mode = cfg.get("mode", "warp")

    if mode == "tor":
        target = get_active_tor_target()
        if not target:
            ok, msg = start_portable_tor()
            if not ok:
                if warp_fallback_fn and not (os.environ.get("OUC_STRICT_PROXY") == "1" or (LANE_DIR / "strict_proxy.flag").is_file()):
                    return warp_fallback_fn(host, port)
                raise ConnectionError(f"Could not connect via Tor: {msg}")
            target = get_active_tor_target() or ("127.0.0.1", 9050)
        try:
            return open_socks5_tunnel(host, port, socks_host=target[0], socks_port=target[1], timeout=10.0)
        except Exception:
            if warp_fallback_fn and not (os.environ.get("OUC_STRICT_PROXY") == "1" or (LANE_DIR / "strict_proxy.flag").is_file()):
                return warp_fallback_fn(host, port)
            raise

    if mode == "custom":
        specs = parse_proxy_specs(
            cfg.get("custom_proxy", "127.0.0.1:10808"),
            str(cfg.get("custom_type", "socks5")).lower(),
        )
        tries = max(1, len(specs))
        last_err = None

        for _ in range(tries):
            spec = get_current_proxy_spec()
            phost = spec["host"]
            pport = int(spec["port"])
            ptype = spec["type"]
            puser = spec.get("username", "")
            ppass = spec.get("password", "")
            if ptype == "http":
                try:
                    return open_http_proxy_tunnel(
                        host,
                        port,
                        phost,
                        pport,
                        timeout=8.0,
                        username=puser,
                        password=ppass,
                    )
                except Exception as e:
                    last_err = e
            else:
                try:
                    return open_socks5_tunnel(
                        host,
                        port,
                        socks_host=phost,
                        socks_port=pport,
                        timeout=6.0,
                        username=puser,
                        password=ppass,
                    )
                except Exception as e:
                    last_err = e
                    # Some proxies are configured with the wrong scheme.
                    try:
                        return open_http_proxy_tunnel(
                            host,
                            port,
                            phost,
                            pport,
                            timeout=5.0,
                            username=puser,
                            password=ppass,
                        )
                    except Exception:
                        pass
            # If current node failed and we have more nodes, advance pool to next node
            if len(specs) > 1:
                advance_custom_proxy()

        if warp_fallback_fn and not (
            os.environ.get("OUC_STRICT_PROXY") == "1"
            or (LANE_DIR / "strict_proxy.flag").is_file()
        ):
            try:
                return warp_fallback_fn(host, port)
            except Exception:
                pass
        raise ConnectionError(f"All proxies in pool failed (last error: {last_err})")

    # Default: Cloudflare WARP IPv6 socket binding
    return warp_fallback_fn(host, port)
