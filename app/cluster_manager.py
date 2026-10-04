"""Multi-host cluster manager (Phase 27).

Lets one ``server-services-manager`` instance discover and
proxy to other instances on the LAN. v1 design:

  - **Manual by default.** Operators add peers by host:port
    + shared secret. This is the primary path and is what
    tests use.
  - **mDNS is opt-in.** ``cluster.enabled: true`` in
    config.yaml turns on zeroconf-based browse/advertise if
    the ``zeroconf`` package is installed. Off by default
    so a fresh install never surprises the user by joining a
    network they didn't intend to.
  - **Shared-secret auth.** Every cross-node request carries
    an ``X-SSM-Cluster-Secret`` header that must match the
    peer's configured secret. The secret is stored locally;
    the cluster section of ``config.yaml`` is the source of
    truth.
  - **HTTP-only for v1.** We do NOT auto-provision TLS. The
    README explicitly recommends running on a trusted LAN
    or fronting the app with a TLS-terminating reverse proxy
    in production.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("ClusterManager")

_LOCK = threading.RLock()

# Filesystem location of the peer registry. Mirrors the layout
# other modules in this repo use (see backup_manager, palette).
_CLUSTER_FILE = os.path.join(
    os.path.expanduser("~"),
    ".server-services-manager",
    "cluster.json",
)


class ClusterError(Exception):
    """Raised by the manager when a request can't be served."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------

def get_cluster_config(cfg_data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract the ``cluster:`` block from a parsed config dict.

    Returns a dict with safe defaults so callers don't have to
    check every key. ``enabled`` defaults to False.
    """
    block = cfg_data.get("cluster") or {}
    try:
        _port = int(str(block.get("port", 8881)).strip())
    except (TypeError, ValueError, AttributeError):
        _port = 8881
    if not (1 <= _port <= 65535):
        _port = 8881
    return {
        "enabled": bool(block.get("enabled", False)),
        # Stripped so a legacy padded value self-heals; verify
        # strips the provided side, and saves strip on write.
        "secret": str(block.get("secret", "") or "").strip(),
        "port": _port,
        "advertise": str(block.get("advertise", "") or ""),
    }


def local_identity(cfg_data: Dict[str, Any]) -> Dict[str, str]:
    """Identify this node to its peers.

    Returns ``hostname``, ``port``, and the secret the cluster
    expects incoming proxies to use. The secret is read from
    config and returned as-is — it's already configured on the
    other nodes too, so echoing it doesn't widen the attack
    surface.
    """
    cfg = get_cluster_config(cfg_data)
    return {
        "hostname": os.uname().nodename,
        "port": str(cfg["port"]),
        "secret": cfg["secret"],
    }


_MIN_CLUSTER_SECRET_LEN = 8


def build_cluster_block(
    payload: Dict[str, Any],
    existing: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Validate a cluster-settings update and return the new block.

    Pure function (no I/O) so the GUI save path is unit-testable.
    ``payload`` comes from ``PUT /api/cluster/config``; ``existing``
    is the current ``cluster:`` block from config.yaml (or {}).

    - ``secret``: absent/blank keeps the existing secret, unless
      ``clear_secret`` is truthy (which wipes it, winning over a
      simultaneously supplied secret). A new secret is stripped
      (matching the add-peer form, which trims on input) and must
      be at least 8 characters; all-whitespace is rejected.
    - ``enabled``: boolean, defaults to the existing value.
    - ``port``: integer 1-65535, defaults to the existing value.
    - ``advertise``: empty string or a hostname/IP (same charset
      rules as peer hosts).
    Unknown keys already present in ``existing`` are preserved.

    Raises :class:`ClusterError` on invalid input. Never logs or
    returns the secret itself — callers decide what to expose.
    """
    import re as _re

    base = dict(existing or {})
    _raw_port = base.get("port", 8881)
    _base_port = 8881
    if isinstance(_raw_port, bool):
        pass
    elif isinstance(_raw_port, int):
        _base_port = _raw_port
    elif isinstance(_raw_port, str) and _raw_port.strip().isdigit():
        _base_port = int(_raw_port.strip())
    # Preserve any unknown keys so a save never silently drops
    # config it doesn't understand.
    out: Dict[str, Any] = dict(base)
    out.update({
        "enabled": bool(base.get("enabled", False)),
        "secret": str(base.get("secret", "") or ""),
        "port": _base_port,
        "advertise": str(base.get("advertise", "") or ""),
    })

    if "enabled" in (payload or {}):
        out["enabled"] = bool(payload.get("enabled"))

    if "port" in (payload or {}):
        _raw_port_in = payload.get("port")
        try:
            port = int(str(_raw_port_in).strip())
        except (TypeError, ValueError):
            raise ClusterError(
                "invalid_port", f"port must be an integer (got {_raw_port_in!r})"
            )
        if not (1 <= port <= 65535):
            raise ClusterError("invalid_port", f"port out of range: {port}")
        out["port"] = port

    if "advertise" in (payload or {}):
        adv = str(payload.get("advertise") or "").strip()
        if adv:
            if len(adv) > 253 or not _re.fullmatch(
                r"[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?", adv
            ):
                raise ClusterError(
                    "invalid_advertise", f"invalid hostname or IP: {adv!r}"
                )
        out["advertise"] = adv

    if bool((payload or {}).get("clear_secret")):
        out["secret"] = ""
    elif "secret" in (payload or {}):
        _raw_secret = str(payload.get("secret") or "")
        if _raw_secret and not _raw_secret.strip():
            raise ClusterError("weak_secret", "secret must not be blank")
        _new_secret = _raw_secret.strip()
        # Note: stripped to match the add-peer form (which trims on
        # input) — otherwise a pasted trailing space would
        # permanently break verification, since verify strips only
        # the provided side.
        if _new_secret:
            if len(_new_secret) < _MIN_CLUSTER_SECRET_LEN:
                raise ClusterError(
                    "weak_secret",
                    f"secret must be at least {_MIN_CLUSTER_SECRET_LEN} characters",
                )
            out["secret"] = _new_secret

    return out


# ---------------------------------------------------------------------------
# Peer registry (manual + persisted)
# ---------------------------------------------------------------------------

def _now_ts() -> float:
    return time.time()


def _load_registry() -> List[Dict[str, Any]]:
    """Read the peer registry from disk; missing file → empty list."""
    if not os.path.isfile(_CLUSTER_FILE):
        return []
    try:
        with open(_CLUSTER_FILE) as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        logger.warning(f"cluster.json has unexpected shape: {type(data).__name__}")
        return []
    except (OSError, json.JSONDecodeError) as e:
        logger.warning(f"could not read cluster.json: {e}")
        return []


def _save_registry(peers: List[Dict[str, Any]]) -> None:
    """Persist the peer registry atomically.

    Same tempfile + os.replace pattern used elsewhere in the
    codebase (see backup_manager, ssh_manager) so a partial
    write can't corrupt the file.
    """
    dirpath = os.path.dirname(_CLUSTER_FILE)
    os.makedirs(dirpath, exist_ok=True)
    import tempfile
    fd, tmp = tempfile.mkstemp(prefix=".cluster.", dir=dirpath)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(peers, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, _CLUSTER_FILE)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _new_peer_id(host: str, port: int) -> str:
    """Stable, URL-safe id for a peer."""
    return f"{host}:{port}"


def list_peers() -> List[Dict[str, Any]]:
    """Return all known peers with their cached status.

    Each entry: ``id``, ``host``, ``port``, ``secret`` (masked
    in UI; visible to the local process), ``label``,
    ``added_at``, ``last_seen``, ``last_error``.
    """
    with _LOCK:
        return _load_registry()


def add_peer(host: str, port: int, secret: str = "", label: str = "") -> Dict[str, Any]:
    """Add (or replace) a peer.

    Refuses obviously bad input (empty host, out-of-range port)
    and refuses duplicate peers (same host:port pair). The
    secret is optional; if empty the proxy will fall back to
    the local ``cluster.secret`` from config.
    """
    import re as _re

    host = (host or "").strip()
    if not host:
        raise ClusterError("invalid_host", "host is required")
    # URL metacharacters would confuse the f"http://{host}:{port}{p}"
    # interpolation in probe/proxy (userinfo/fragment confusion).
    if any(c in host for c in ("/", " ", "@", "#", "?", ":")):
        raise ClusterError("invalid_host", f"unexpected characters in host: {host!r}")
    if any(ord(c) < 32 or ord(c) == 127 for c in host):
        raise ClusterError("invalid_host", f"unexpected characters in host: {host!r}")
    if len(host) > 253 or not _re.fullmatch(
        r"[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?", host
    ):
        raise ClusterError("invalid_host", f"invalid hostname or IP: {host!r}")
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise ClusterError("invalid_port", f"port must be an integer (got {port!r})")
    if not (1 <= port <= 65535):
        raise ClusterError("invalid_port", f"port out of range: {port}")
    # Round-trip through urlparse: a hostile host must not smuggle
    # userinfo / fragment / query into the peer URL.
    try:
        _parsed = urllib.parse.urlparse(f"http://{host}:{port}/health")
        if _parsed.hostname != host.lower():
            raise ClusterError(
                "invalid_host", f"invalid hostname or IP: {host!r}"
            )
    except ClusterError:
        raise
    except Exception:
        raise ClusterError("invalid_host", f"invalid hostname or IP: {host!r}")
    secret = (secret or "").strip()
    label = (label or "").strip() or host
    peer_id = _new_peer_id(host, port)
    with _LOCK:
        peers = _load_registry()
        for existing in peers:
            if existing.get("id") == peer_id:
                raise ClusterError("duplicate", f"peer {peer_id} already exists")
        entry = {
            "id": peer_id,
            "host": host,
            "port": port,
            "secret": secret,
            "label": label,
            "added_at": _now_ts(),
            "last_seen": 0,
            "last_error": "",
        }
        peers.append(entry)
        _save_registry(peers)
        return entry


def remove_peer(peer_id: str) -> Dict[str, Any]:
    """Remove a peer by id."""
    with _LOCK:
        peers = _load_registry()
        before = len(peers)
        peers = [p for p in peers if p.get("id") != peer_id]
        if len(peers) == before:
            raise ClusterError("not_found", f"peer {peer_id!r} not found")
        _save_registry(peers)
        return {"id": peer_id, "removed": before - len(peers)}


def get_peer(peer_id: str) -> Optional[Dict[str, Any]]:
    """Return a single peer or None if not found."""
    with _LOCK:
        for p in _load_registry():
            if p.get("id") == peer_id:
                return p
    return None


def update_peer_status(peer_id: str, *, ok: bool, error: str = "") -> None:
    """Cache the latest reachability result for a peer.

    Called by :func:`probe_peer` after each ping; we read this
    cache in :func:`list_peers_with_status` so the dashboard
    shows up-to-date indicators without re-probing on every
    page load.
    """
    with _LOCK:
        peers = _load_registry()
        changed = False
        for p in peers:
            if p.get("id") == peer_id:
                if ok:
                    p["last_seen"] = _now_ts()
                    p["last_error"] = ""
                else:
                    p["last_error"] = error or "unreachable"
                changed = True
                break
        if changed:
            _save_registry(peers)


# ---------------------------------------------------------------------------
# Reachability probe + API proxy
# ---------------------------------------------------------------------------

# Default timeout for cross-node HTTP calls. Long enough to
# tolerate slow wifi, short enough that a hung peer doesn't
# stall the dashboard.
_DEFAULT_TIMEOUT = 3.0


def probe_peer(peer: Dict[str, Any], timeout: float = _DEFAULT_TIMEOUT) -> Tuple[bool, str]:
    """HEAD /health on the peer to test reachability.

    Returns ``(ok, error)``. On success, marks the peer's
    ``last_seen``; on failure, records the error string.

    The /health endpoint is the only one that doesn't require
    authentication, which makes it a perfect liveness probe.
    """
    peer_id = peer.get("id", "?")
    host = peer.get("host", "")
    port = int(peer.get("port", 0))
    if not host or not port:
        return False, "invalid peer"
    url = f"http://{host}:{port}/health"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ok = 200 <= resp.status < 400
        if ok:
            update_peer_status(peer_id, ok=True)
        else:
            update_peer_status(peer_id, ok=False, error=f"HTTP {resp.status}")
        return ok, "" if ok else f"HTTP {resp.status}"
    except urllib.error.URLError as e:
        err = str(e.reason) if hasattr(e, "reason") else str(e)
        update_peer_status(peer_id, ok=False, error=err)
        return False, err
    except (OSError, TimeoutError) as e:
        update_peer_status(peer_id, ok=False, error=str(e) or type(e).__name__)
        return False, str(e) or type(e).__name__


def _local_secret(cfg_data: Dict[str, Any]) -> str:
    return get_cluster_config(cfg_data).get("secret", "") or ""


def verify_cluster_secret(provided: str | None, cfg_data: Dict[str, Any]) -> bool:
    """Check an inbound ``X-SSM-Cluster-Secret`` value.

    Returns True only when both the configured ``cluster.secret``
    and the provided value are non-empty and equal (constant-time
    compare). Empty-on-either-side never verifies, so a node with
    no secret configured accepts no peer requests.
    """
    expected = _local_secret(cfg_data)
    given = (provided or "").strip()
    if not expected or not given:
        return False
    return hmac.compare_digest(given, expected)


def _resolve_secret(peer: Dict[str, Any], cfg_data: Dict[str, Any]) -> str:
    """Pick the secret to send: per-peer first, then local cluster.secret."""
    s = (peer.get("secret") or "").strip()
    if s:
        return s
    return _local_secret(cfg_data)


def proxy_request(
    peer: Dict[str, Any],
    path: str,
    method: str = "GET",
    body: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
    cfg_data: Optional[Dict[str, Any]] = None,
    timeout: float = 5.0,
) -> Tuple[int, Dict[str, str], bytes]:
    """Forward ``method path`` to ``peer`` and return its response.

    The ``X-SSM-Cluster-Secret`` header is added automatically
    so the peer can verify the request came from a trusted
    node. The peer's session cookie (if any) is forwarded so
    the user appears logged in on the remote side.

    Returns ``(status, headers, body)`` so the Flask caller
    can stream the body verbatim to the browser.
    """
    host = peer.get("host", "")
    port = int(peer.get("port", 0))
    if not host or not port:
        raise ClusterError("invalid_peer", "peer is missing host/port")
    # Build the URL. ``path`` should start with a /; we strip
    # any double slashes that would come from /api/cluster/
    # node/<id>/proxy/<rest>.
    p = "/" + (path or "").lstrip("/")
    url = f"http://{host}:{port}{p}"
    req_headers = dict(headers or {})
    secret = _resolve_secret(peer, cfg_data or {})
    if secret:
        req_headers["X-SSM-Cluster-Secret"] = secret
    req = urllib.request.Request(url, data=body, method=method, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return (
                resp.status,
                dict(resp.headers.items()),
                resp.read(),
            )
    except urllib.error.HTTPError as e:
        # HTTPError is also a valid response — return it so
        # the caller can surface the same status to the user.
        return e.code, dict(e.headers.items()), e.read() or b""
    except urllib.error.URLError as e:
        raise ClusterError(
            "peer_unreachable",
            f"can't reach {host}:{port} — {getattr(e, 'reason', e)}",
        )
    except (OSError, TimeoutError) as e:
        raise ClusterError(
            "peer_unreachable",
            f"can't reach {host}:{port} — {e or type(e).__name__}",
        )


# ---------------------------------------------------------------------------
# Convenience: list peers with cached status
# ---------------------------------------------------------------------------

def list_peers_with_status() -> Dict[str, Any]:
    """Return peers plus a quick summary block for the dashboard.

    The summary counts reachable / unreachable peers based on
    the cached ``last_error`` field. We don't ping on every
    read — the UI is expected to call ``probe_all_peers()``
    separately when it wants fresh data.
    """
    peers = list_peers()
    reachable = sum(1 for p in peers if p.get("last_seen") and not p.get("last_error"))
    return {
        "peers": peers,
        "count": len(peers),
        "reachable": reachable,
        "unreachable": len(peers) - reachable,
    }


def probe_all_peers(timeout: float = _DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """Run :func:`probe_peer` against every peer, sequentially.

    Probing is sequential and short-lived — no thread pool —
    so a single hung peer can't pin a thread. Returns a
    per-peer result list.
    """
    peers = list_peers()
    results: List[Dict[str, Any]] = []
    for p in peers:
        ok, err = probe_peer(p, timeout=timeout)
        results.append({"id": p.get("id"), "ok": ok, "error": err})
    return {"results": results}


# ---------------------------------------------------------------------------
# Optional mDNS browse/advertise (zeroconf). Disabled unless
# ``cluster.enabled: true`` AND the zeroconf package is importable.
# ---------------------------------------------------------------------------

def try_mdns_browse(service_type: str = "_ssm-manager._tcp.local.",
                    timeout: float = 2.0) -> List[Dict[str, Any]]:
    """Best-effort mDNS browse; returns [] on any failure.

    We never raise out of this function — mDNS is purely
    additive and the manager must work without it. The caller
    is expected to merge the returned entries into the
    peer registry manually (operators should still confirm
    the secret before adding).
    """
    try:
        from zeroconf import ServiceBrowser, ServiceListener, Zeroconf  # type: ignore
    except ImportError:
        logger.debug("zeroconf not installed; mDNS browse skipped")
        return []
    found: List[Dict[str, Any]] = []
    class _L(ServiceListener):  # type: ignore[misc]
        def update_service(self, zc, t, name):  # noqa: ARG002
            info = zc.get_service_info(t, name)
            if info is None:
                return
            addr = ""
            if info.addresses:
                try:
                    addr = ".".join(str(b) for b in info.addresses[0])
                except Exception:
                    addr = ""
            port = info.port or 0
            props = {k.decode() if isinstance(k, bytes) else k:
                     (v.decode() if isinstance(v, bytes) else v)
                     for k, v in (info.properties or {}).items()}
            found.append({
                "name": name,
                "host": addr,
                "port": port,
                "txt": props,
            })
        def remove_service(self, *_): pass
        def add_service(self, *_): pass
    try:
        zc = Zeroconf()
        listener = _L()
        browser = ServiceBrowser(zc, service_type, listener)
        time.sleep(timeout)
        browser.cancel()
        zc.close()
    except Exception as e:  # noqa: BLE001
        logger.debug(f"mDNS browse failed: {e}")
        return []
    return found