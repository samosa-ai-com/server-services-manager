"""Tests for app.cluster_manager (Phase 27).

All filesystem state is sandboxed under ``tempfile.mkdtemp()``
by monkey-patching ``_CLUSTER_FILE``. Cross-node HTTP probes
and proxies are exercised with a real local http.server so we
verify the actual wire format the browser / a peer will see.
"""
import http.server
import json
import os
import shutil
import socketserver
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from app import cluster_manager as cm


def _sandbox_registry():
    """Point cm._CLUSTER_FILE at a temp file
     return (patcher, path)."""
    tmp = tempfile.mkdtemp()
    path = os.path.join(tmp, "cluster.json")
    p = patch.object(cm, "_CLUSTER_FILE", path)
    p.start()
    return p, tmp, path


class TestGetClusterConfig(unittest.TestCase):
    def test_empty_config_returns_defaults(self):
        cfg = cm.get_cluster_config({})
        assert cfg["enabled"] is False
        assert cfg["secret"] == ""
        assert cfg["port"] == 8881
        assert cfg["advertise"] == ""

    def test_full_config(self):
        cfg = cm.get_cluster_config({
            "cluster": {
                "enabled": True,
                "secret": "topsecret",
                "port": 9000,
                "advertise": "192.168.1.50",
            }
        })
        assert cfg["enabled"] is True
        assert cfg["secret"] == "topsecret"
        assert cfg["port"] == 9000
        assert cfg["advertise"] == "192.168.1.50"

    def test_partial_config(self):
        cfg = cm.get_cluster_config({"cluster": {"enabled": True}})
        assert cfg["enabled"] is True
        assert cfg["secret"] == ""
        assert cfg["port"] == 8881


class TestRegistryOps(unittest.TestCase):
    def setUp(self):
        self._patcher, self.tmp, self.path = _sandbox_registry()
        self.addCleanup(self._patcher.stop)
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def test_add_returns_expected_fields(self):
        p = cm.add_peer("192.168.1.10", 8881, secret="s", label="node-1")
        assert p["id"] == "192.168.1.10:8881"
        assert p["host"] == "192.168.1.10"
        assert p["port"] == 8881
        assert p["secret"] == "s"
        assert p["label"] == "node-1"
        assert p["added_at"] > 0
        assert p["last_seen"] == 0
        assert p["last_error"] == ""

    def test_add_persists_to_disk(self):
        cm.add_peer("192.168.1.10", 8881, label="n1")
        assert os.path.isfile(self.path)
        with open(self.path) as f:
            data = json.load(f)
        assert isinstance(data, list)
        assert data[0]["host"] == "192.168.1.10"

    def test_list_empty(self):
        assert cm.list_peers() == []

    def test_list_multiple(self):
        cm.add_peer("a", 8881, label="A")
        cm.add_peer("b", 8882, label="B")
        cm.add_peer("c", 8883, label="C")
        peers = cm.list_peers()
        assert len(peers) == 3
        ids = {p["id"] for p in peers}
        assert ids == {"a:8881", "b:8882", "c:8883"}

    def test_duplicate_rejected(self):
        cm.add_peer("a", 8881)
        with self.assertRaises(cm.ClusterError) as ctx:
            cm.add_peer("a", 8881)
        assert ctx.exception.code == "duplicate"

    def test_empty_host_rejected(self):
        with self.assertRaises(cm.ClusterError) as ctx:
            cm.add_peer("", 8881)
        assert ctx.exception.code == "invalid_host"

    def test_whitespace_in_host_rejected(self):
        with self.assertRaises(cm.ClusterError) as ctx:
            cm.add_peer("bad host", 8881)
        assert ctx.exception.code == "invalid_host"

    def test_slash_in_host_rejected(self):
        with self.assertRaises(cm.ClusterError) as ctx:
            cm.add_peer("bad/host", 8881)
        assert ctx.exception.code == "invalid_host"

    def test_non_int_port_rejected(self):
        with self.assertRaises(cm.ClusterError) as ctx:
            cm.add_peer("a", "not-a-port")
        assert ctx.exception.code == "invalid_port"

    def test_out_of_range_port_rejected(self):
        with self.assertRaises(cm.ClusterError) as ctx:
            cm.add_peer("a", 99999)
        assert ctx.exception.code == "invalid_port"

    def test_remove(self):
        cm.add_peer("a", 8881)
        out = cm.remove_peer("a:8881")
        assert out["removed"] == 1
        assert cm.list_peers() == []

    def test_remove_unknown(self):
        with self.assertRaises(cm.ClusterError) as ctx:
            cm.remove_peer("nope:1234")
        assert ctx.exception.code == "not_found"

    def test_get_peer(self):
        cm.add_peer("a", 8881, label="A")
        p = cm.get_peer("a:8881")
        assert p is not None
        assert p["label"] == "A"
        assert cm.get_peer("nope") is None

    def test_default_label_is_host(self):
        p = cm.add_peer("onlyhost", 9000)
        assert p["label"] == "onlyhost"

    def test_secret_optional(self):
        p = cm.add_peer("a", 8881)
        assert p["secret"] == ""


class TestUpdatePeerStatus(unittest.TestCase):
    def setUp(self):
        self._patcher, self.tmp, self.path = _sandbox_registry()
        self.addCleanup(self._patcher.stop)
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def test_success_marks_last_seen(self):
        cm.add_peer("a", 8881)
        before = cm.list_peers()[0]["last_seen"]
        time.sleep(0.01)
        cm.update_peer_status("a:8881", ok=True)
        after = cm.list_peers()[0]
        assert after["last_seen"] > before
        assert after["last_error"] == ""

    def test_failure_records_error(self):
        cm.add_peer("a", 8881)
        cm.update_peer_status("a:8881", ok=False, error="connection refused")
        p = cm.list_peers()[0]
        assert p["last_error"] == "connection refused"

    def test_unknown_id_is_noop(self):
        # Doesn't raise; doesn't touch the registry.
        cm.update_peer_status("nope:1", ok=True)
        assert cm.list_peers() == []


class TestListPeersWithStatus(unittest.TestCase):
    def setUp(self):
        self._patcher, self.tmp, self.path = _sandbox_registry()
        self.addCleanup(self._patcher.stop)
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def test_empty(self):
        out = cm.list_peers_with_status()
        assert out["count"] == 0
        assert out["reachable"] == 0
        assert out["unreachable"] == 0
        assert out["peers"] == []

    def test_reachable_counter(self):
        cm.add_peer("a", 8881)
        cm.add_peer("b", 8882)
        cm.update_peer_status("a:8881", ok=True)
        out = cm.list_peers_with_status()
        # Only `a` has been seen.
        assert out["count"] == 2
        assert out["reachable"] == 1
        assert out["unreachable"] == 1


class TestProbeAndProxy(unittest.TestCase):
    """Spin up a local HTTP server, then probe / proxy to it."""

    @classmethod
    def setUpClass(cls):
        # A tiny server that handles /health (200) and /api/probe-echo
        # (200 with the body we sent). It also refuses /api/no (404).
        class _H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_): pass  # silence stderr

            def do_GET(self):
                if self.path == "/health":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"ok")
                elif self.path == "/api/echo":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"hello":"world"}')
                elif self.path == "/api/no":
                    self.send_response(404)
                    self.end_headers()
                else:
                    self.send_response(418)
                    self.end_headers()

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length) if length else b""
                if self.path == "/api/echo":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"got":' + body + b'}')
                else:
                    self.send_response(404)
                    self.end_headers()

        cls._httpd = socketserver.TCPServer(("127.0.0.1", 0), _H)
        cls._port = cls._httpd.server_address[1]
        cls._thread = threading.Thread(target=cls._httpd.serve_forever, daemon=True)
        cls._thread.start()

    @classmethod
    def tearDownClass(cls):
        cls._httpd.shutdown()
        cls._httpd.server_close()

    def setUp(self):
        self._patcher, self.tmp, self.path = _sandbox_registry()
        self.addCleanup(self._patcher.stop)
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def test_probe_success(self):
        peer = cm.add_peer("127.0.0.1", self._port)
        ok, err = cm.probe_peer(peer, timeout=2.0)
        assert ok is True
        assert err == ""
        p = cm.get_peer(peer["id"])
        assert p["last_seen"] > 0

    def test_probe_404_is_failure(self):
        # The test server returns 404 for /api/no. The probe
        # checks for 200-399, so this should be marked down.
        peer = cm.add_peer("127.0.0.1", self._port)
        # Override the URL by patching urlopen — easier than
        # adding a new endpoint just for this test.
        with patch("app.cluster_manager.urllib.request.urlopen") as fake:
            from urllib.error import HTTPError
            fake.side_effect = HTTPError(
                "http://x/api/no", 404, "Not Found", {}, io_bytes(b"")
            )
            ok, err = cm.probe_peer(peer, timeout=2.0)
        # Note: HTTPError.status is a property; urlopen raised.
        # Our handler catches HTTPError via URLError branch, so
        # we expect failure.
        assert ok is False

    def test_probe_unreachable(self):
        # Port that's definitely closed.
        peer = cm.add_peer("127.0.0.1", 1)
        ok, err = cm.probe_peer(peer, timeout=0.5)
        assert ok is False
        assert err  # non-empty

    def test_proxy_get(self):
        peer = cm.add_peer("127.0.0.1", self._port)
        status, hdrs, body = cm.proxy_request(
            peer, "/api/echo", method="GET", cfg_data={},
        )
        assert status == 200
        assert json.loads(body) == {"hello": "world"}

    def test_proxy_post_with_body(self):
        peer = cm.add_peer("127.0.0.1", self._port)
        status, hdrs, body = cm.proxy_request(
            peer, "/api/echo", method="POST",
            body=b'{"x":1}', cfg_data={},
        )
        assert status == 200
        assert json.loads(body) == {"got": {"x": 1}}

    def test_proxy_adds_secret_header(self):
        captured = {}

        class _H2(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                captured["secret"] = self.headers.get("X-SSM-Cluster-Secret", "")
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
        # Start a one-shot server on a free port.
        srv = socketserver.TCPServer(("127.0.0.1", 0), _H2)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            peer = cm.add_peer("127.0.0.1", port, secret="mysecret")
            status, _, _ = cm.proxy_request(
                peer, "/anything", method="GET", cfg_data={},
            )
            assert status == 200
            assert captured["secret"] == "mysecret"
        finally:
            srv.shutdown()
            srv.server_close()

    def test_proxy_falls_back_to_local_secret(self):
        captured = {}

        class _H2(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                captured["secret"] = self.headers.get("X-SSM-Cluster-Secret", "")
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
        srv = socketserver.TCPServer(("127.0.0.1", 0), _H2)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            # No per-peer secret; fall back to cluster.secret.
            peer = cm.add_peer("127.0.0.1", port)
            status, _, _ = cm.proxy_request(
                peer, "/anything", method="GET",
                cfg_data={"cluster": {"secret": "fallback"}},
            )
            assert status == 200
            assert captured["secret"] == "fallback"
        finally:
            srv.shutdown()
            srv.server_close()

    def test_proxy_no_secret_means_no_header(self):
        captured = {}

        class _H2(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                captured["secret"] = self.headers.get("X-SSM-Cluster-Secret", "<missing>")
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
        srv = socketserver.TCPServer(("127.0.0.1", 0), _H2)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            peer = cm.add_peer("127.0.0.1", port)
            status, _, _ = cm.proxy_request(peer, "/anything", cfg_data={})
            assert status == 200
            assert captured["secret"] == "<missing>"
        finally:
            srv.shutdown()
            srv.server_close()

    def test_proxy_unreachable_raises(self):
        peer = cm.add_peer("127.0.0.1", 1)
        with self.assertRaises(cm.ClusterError) as ctx:
            cm.proxy_request(peer, "/x", cfg_data={}, timeout=0.5)
        assert ctx.exception.code == "peer_unreachable"

    def test_proxy_invalid_peer(self):
        with self.assertRaises(cm.ClusterError) as ctx:
            cm.proxy_request({"host": "", "port": 0}, "/x", cfg_data={})
        assert ctx.exception.code == "invalid_peer"

    def test_proxy_strips_extra_leading_slashes(self):
        peer = cm.add_peer("127.0.0.1", self._port)
        status, _, body = cm.proxy_request(
            peer, "///api/echo", method="GET", cfg_data={},
        )
        assert status == 200


class TestProbeAllPeers(unittest.TestCase):
    def setUp(self):
        self._patcher, self.tmp, self.path = _sandbox_registry()
        self.addCleanup(self._patcher.stop)
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def test_empty(self):
        out = cm.probe_all_peers()
        assert out["results"] == []

    def test_runs_against_each_peer(self):
        cm.add_peer("127.0.0.1", 1)        # closed
        cm.add_peer("127.0.0.1", 2)        # closed
        out = cm.probe_all_peers(timeout=0.3)
        assert len(out["results"]) == 2
        assert all(r["ok"] is False for r in out["results"])


class TestTryMdnsBrowse(unittest.TestCase):
    def test_returns_empty_when_zeroconf_missing(self):
        # Force ImportError on the zeroconf import.
        import sys
        saved = sys.modules.get("zeroconf")
        sys.modules["zeroconf"] = None  # type: ignore
        try:
            out = cm.try_mdns_browse(timeout=0.1)
            assert out == []
        finally:
            if saved is not None:
                sys.modules["zeroconf"] = saved
            else:
                sys.modules.pop("zeroconf", None)


class TestBuildClusterBlock(unittest.TestCase):
    def test_empty_payload_keeps_existing(self):
        out = cm.build_cluster_block(
            {}, {"enabled": True, "secret": "old-secret", "port": 9000,
                 "advertise": "10.0.0.1"})
        assert out == {"enabled": True, "secret": "old-secret",
                       "port": 9000, "advertise": "10.0.0.1"}

    def test_empty_existing_gives_defaults(self):
        out = cm.build_cluster_block({}, {})
        assert out == {"enabled": False, "secret": "", "port": 8881,
                       "advertise": ""}

    def test_new_secret_replaces(self):
        out = cm.build_cluster_block({"secret": "brand-new-secret"}, {})
        assert out["secret"] == "brand-new-secret"

    def test_blank_secret_keeps_existing(self):
        out = cm.build_cluster_block({"secret": ""}, {"secret": "keep-me"})
        assert out["secret"] == "keep-me"

    def test_clear_secret_wipes(self):
        out = cm.build_cluster_block(
            {"clear_secret": True}, {"secret": "old-secret"})
        assert out["secret"] == ""

    def test_weak_secret_rejected(self):
        with self.assertRaises(cm.ClusterError) as ctx:
            cm.build_cluster_block({"secret": "short"}, {})
        assert ctx.exception.code == "weak_secret"

    def test_bad_port_rejected(self):
        for bad in ("abc", 0, 70000):
            with self.assertRaises(cm.ClusterError) as ctx:
                cm.build_cluster_block({"port": bad}, {})
            assert ctx.exception.code == "invalid_port"

    def test_bad_advertise_rejected(self):
        with self.assertRaises(cm.ClusterError) as ctx:
            cm.build_cluster_block({"advertise": "not a host!"}, {})
        assert ctx.exception.code == "invalid_advertise"

    def test_valid_fields_applied(self):
        out = cm.build_cluster_block(
            {"enabled": True, "port": "9000", "advertise": "node-1"}, {})
        assert out["enabled"] is True
        assert out["port"] == 9000
        assert out["advertise"] == "node-1"

    def test_padded_secret_is_stripped(self):
        out = cm.build_cluster_block({"secret": "  padded-secret  "}, {})
        assert out["secret"] == "padded-secret"

    def test_all_whitespace_secret_rejected(self):
        with self.assertRaises(cm.ClusterError) as ctx:
            cm.build_cluster_block({"secret": "        "}, {})
        assert ctx.exception.code == "weak_secret"

    def test_exactly_8_chars_accepted(self):
        out = cm.build_cluster_block({"secret": "12345678"}, {})
        assert out["secret"] == "12345678"

    def test_clear_wins_over_supplied_secret(self):
        out = cm.build_cluster_block(
            {"secret": "brand-new-secret", "clear_secret": True},
            {"secret": "old-secret"})
        assert out["secret"] == ""

    def test_unknown_keys_preserved(self):
        out = cm.build_cluster_block(
            {"port": 9000}, {"secret": "s3cret-s3cret", "future_opt": True})
        assert out["future_opt"] is True
        assert out["secret"] == "s3cret-s3cret"
        assert out["port"] == 9000

    def test_non_numeric_port_falls_back_to_default(self):
        cfg = cm.get_cluster_config({"cluster": {"port": "not-a-port"}})
        assert cfg["port"] == 8881

    def test_config_secret_is_stripped(self):
        cfg = cm.get_cluster_config({"cluster": {"secret": "  padded  "}})
        assert cfg["secret"] == "padded"

    def test_padded_config_secret_verifies(self):
        cfg_data = {"cluster": {"secret": "  padded-secret  "}}
        assert cm.verify_cluster_secret("padded-secret", cfg_data) is True


def io_bytes(b):
    """Helper for HTTPError body."""
    import io
    return io.BytesIO(b)


if __name__ == "__main__":
    unittest.main()