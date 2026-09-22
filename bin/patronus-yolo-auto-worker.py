#!/usr/bin/env python3
"""External Patronus Ark worker for pi-sentinel yolo-auto.

Ark remains an external GPL/commercial runtime. This adapter only speaks the
MIT extension's length-delimited Unix-socket protocol and downloads missing model assets during startup, before serving permission requests.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import socket
import socketserver
import sys
import threading
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = 1
MAX_FRAME_BYTES = 1024 * 1024
PIPELINES = ("source_sensitive", "source_untrusted", "sink_external")
MAX_PROVENANCE_LENGTH = 128
CATEGORIES = ("injection", "tool_class", "tool_action", "tool_tags")
NEUTRAL_CLASSES = {"safe", "benign"}

# Pinned Ark package revisions and manifest digests. Ark performs the actual
# download; this adapter refuses to serve a cache that no longer matches it.
L2_CACHE_SPECS = {
    "injection/l2_ntdb/injection_current": (
        "142fadc5474163d4c483cb761d5a6b02e3aa1741",
        "9a0e1b3d0a3494774d7da529b312e6247d79640dc8d55f66bbccbdddef2d0b28",
    ),
    "tool_class/l2_ntdb/tool_class_current": (
        "286be0dae164ac189bb79cfcb4f60cedd81aaa58",
        "6e1d82aae41af917e78e6b5bfdb12be1e40ca842c8cfaa9af00011185f1a0fdc",
    ),
    "tool_action/l2_ntdb/tool_action_current": (
        "54a95e983d0df6d13ceb2ce675bde7200238170b",
        "46e48ead0bc3058ce6d9807b33282c95f32e0fecc112fb4224b6558a7d17c46d",
    ),
    "tool_tags/l2_ntdb/tool_tags_sink_external_current": (
        "66bb4bdd76f57aacba7a4e39e0368e35701b2244",
        "db6a2e576b197170a2fd2c07ff7bef147537b2b28bd063eec26f023c116020f0",
    ),
    "tool_tags/l2_ntdb/tool_tags_source_sensitive_current": (
        "66bb4bdd76f57aacba7a4e39e0368e35701b2244",
        "231878d4baeb844364fcc69426c45e5147fe75e515c8bf14fd1d9ca7ca092452",
    ),
    "tool_tags/l2_ntdb/tool_tags_source_untrusted_current": (
        "66bb4bdd76f57aacba7a4e39e0368e35701b2244",
        "5ed2a759aaf13f325ff4af2c7f572607755add3428bafa1de1a4cb7f5f112684",
    ),
}


def verify_cached_l2_assets(model_dir: str | Path) -> None:
    root = Path(model_dir)
    for relative_path, (expected_revision, expected_manifest_sha256) in L2_CACHE_SPECS.items():
        package = root / relative_path
        revision_path = package / ".patronus-revision"
        if not revision_path.is_file():
            raise ValueError(f"missing cached Patronus revision at {revision_path}")
        revision = revision_path.read_text(encoding="utf-8").strip()
        if revision != expected_revision:
            raise ValueError(f"Patronus revision mismatch at {package}: {revision!r}")
        manifest_path = package / "manifest.json"
        if not manifest_path.is_file():
            raise ValueError(f"missing cached Patronus manifest at {manifest_path}")
        try:
            json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise ValueError(f"malformed Patronus manifest at {manifest_path}") from error
        digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        if digest != expected_manifest_sha256:
            raise ValueError(f"Patronus manifest integrity mismatch at {manifest_path}")


@contextlib.contextmanager
def startup_cache_lock(model_dir: str | Path):
    """Serialize Ark cache preparation across concurrently starting workers."""
    lock_path = Path(model_dir) / ".pi-sentinel-yolo-auto.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+") as lock_file:
        os.chmod(lock_path, 0o600)
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def payload_text(payload: dict[str, Any]) -> str:
    """Serialize only the bounded classifier payload, never raw tool content."""
    safe_payload = {
        "toolName": payload.get("toolName"),
        "operation": payload.get("operation"),
        "workspaceRelativePath": payload.get("workspaceRelativePath"),
        "metadata": payload.get("metadata", {}),
    }
    return json.dumps(safe_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _decision_status(result: dict[str, Any]) -> tuple[bool, bool]:
    decision = result.get("decision") or {}
    terminality = decision.get("terminality") or {}
    completion = terminality.get("completion", "complete")
    degraded = bool(terminality.get("degraded", result.get("degraded", False)))
    return completion == "complete", degraded


def _provenance(result: dict[str, Any]) -> str | None:
    decision = result.get("decision") or {}
    provenance = decision.get("provenance") or {}
    candidate = provenance.get("model") or result.get("model")
    if not isinstance(candidate, str) or len(candidate) > MAX_PROVENANCE_LENGTH:
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in candidate):
        return None
    return candidate


def map_l1_result(result: dict[str, Any] | None) -> dict[str, Any]:
    if not result or result.get("category") != "injection" or result.get("level") != "L1":
        return {"verdict": "unknown", "accepted": False, "complete": False, "degraded": True}
    complete, degraded = _decision_status(result)
    class_name = result.get("class_name")
    confidence = result.get("confidence")
    threshold = 0.96
    layers = result.get("layers") or []
    if layers and isinstance(layers[0], dict):
        threshold = (layers[0].get("thresholds") or {}).get("acceptance", threshold)
    safe = class_name in NEUTRAL_CLASSES and isinstance(confidence, (int, float)) and confidence >= threshold
    verdict = "safe" if safe else "unsafe" if complete and not degraded else "unknown"
    return {
        "verdict": verdict,
        "accepted": bool(safe and complete and not degraded),
        "complete": complete,
        "degraded": degraded,
        **({"provenance": _provenance(result)} if _provenance(result) else {}),
    }


def map_l2_results(raw_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    mapped: list[dict[str, Any]] = []
    tag_index = 0
    for result in raw_results:
        if result.get("level") != "L2" or result.get("category") not in CATEGORIES:
            continue
        category = result["category"]
        class_name = result.get("class_name")
        if category == "injection" and class_name == "benign":
            class_name = "safe"
        complete, degraded = _decision_status(result)
        item: dict[str, Any] = {
            "category": category,
            "className": class_name,
            "accepted": complete and not degraded,
            "complete": complete,
            "degraded": degraded,
        }
        if category == "tool_tags":
            if tag_index < len(PIPELINES):
                item["pipeline"] = PIPELINES[tag_index]
            tag_index += 1
        provenance = _provenance(result)
        if provenance:
            item["provenance"] = provenance
        mapped.append(item)
    return mapped


def _contains_escalation(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"route_to_l3", "promote_to_l3", "promoted", "l3_pending", "escalation_required"} and item is True:
                return True
            if _contains_escalation(item):
                return True
    elif isinstance(value, list):
        return any(_contains_escalation(item) for item in value)
    return False


def map_l2_response(raw_results: list[dict[str, Any]]) -> dict[str, Any]:
    return {"results": map_l2_results(raw_results), "escalated": _contains_escalation(raw_results)}


def map_l3_response(raw_results: list[dict[str, Any]]) -> dict[str, Any]:
    provenance = next((_provenance(result) for result in raw_results if _provenance(result)), None)
    return {
        "recommendation": "prompt",
        **({"provenance": provenance} if provenance else {}),
    }


class PatronusProvider:
    def __init__(self, model_dir: str, site_packages: str | None, download_files: bool = True) -> None:
        if site_packages:
            sys.path.insert(0, site_packages)
        try:
            from patronus_ark import SecurityGateway
        except ImportError as error:
            raise RuntimeError(
                "Install Patronus Ark externally or set PI_SENTINEL_PATRONUS_SITE_PACKAGES."
            ) from error
        self._gateway_type = SecurityGateway
        self._model_dir = str(Path(model_dir).expanduser().resolve())
        self._download_files = download_files
        self._l2_gateway: Any | None = None
        self._l3_gateway: Any | None = None
        self._lock = threading.RLock()

    def _create_gateway(self, max_level: str, *, l3_strategy: str | None = None) -> Any:
        options: dict[str, Any] = {
            "categories": list(CATEGORIES),
            "max_level": max_level,
            "model_dir": self._model_dir,
            "download_files": self._download_files,
            "download_categories": list(CATEGORIES),
        }
        if l3_strategy is not None:
            options["l3_strategy"] = l3_strategy
        return self._gateway_type(**options)

    def _get_l2_gateway(self) -> Any:
        if self._l2_gateway is None:
            self._l2_gateway = self._create_gateway("l2")
        return self._l2_gateway

    def warm_l1(self) -> None:
        self._get_l2_gateway()

    def warm_all(self, *, cache_lock_held: bool = False) -> None:
        """Download/verify and warm every enabled Patronus phase before serving."""
        if cache_lock_held:
            self._warm_all()
            return
        with startup_cache_lock(self._model_dir):
            self._warm_all()

    def _warm_all(self) -> None:
        self.warm_l1()
        self.warm_l2()
        self.warm_l3()
        verify_cached_l2_assets(self._model_dir)

    def warm_l2(self) -> None:
        with self._lock:
            self._get_l2_gateway().warmup()

    def evaluate_l1(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            results = self._get_l2_gateway().scan_category("injection", payload_text(payload))
        return map_l1_result(next((result for result in results if result.get("level") == "L1"), None))

    def evaluate_l2(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            results = self._get_l2_gateway().scan_all(payload_text(payload))
        return map_l2_response(results)

    def warm_l3(self) -> None:
        with self._lock:
            if self._l3_gateway is None:
                self._l3_gateway = self._create_gateway("l3", l3_strategy="multi")
            self._l3_gateway.warmup()

    def evaluate_l3(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            if self._l3_gateway is None:
                self.warm_l3()
            results = self._l3_gateway.scan_all(payload_text(payload))
        return map_l3_response(results)

    def close(self) -> None:
        with self._lock:
            if self._l3_gateway is not None:
                self._l3_gateway.stop_l3_models()


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise ConnectionError("worker socket closed")
        chunks.extend(chunk)
    return bytes(chunks)


def read_frame(connection: socket.socket) -> dict[str, Any]:
    length = int.from_bytes(_recv_exact(connection, 4), "big")
    if length > MAX_FRAME_BYTES:
        raise ValueError("worker frame is too large")
    value = json.loads(_recv_exact(connection, length).decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("worker frame must be an object")
    return value


def write_frame(connection: socket.socket, value: dict[str, Any]) -> None:
    frame = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(frame) > MAX_FRAME_BYTES:
        raise ValueError("worker frame is too large")
    connection.sendall(len(frame).to_bytes(4, "big") + frame)


def cleanup_worker_socket(socket_path: Path, *, owns_socket: bool) -> None:
    if owns_socket and socket_path.exists():
        socket_path.unlink()


def remove_stale_socket(socket_path: Path) -> None:
    if not os.path.lexists(socket_path):
        return
    if socket_path.is_symlink() or not socket_path.is_socket():
        raise RuntimeError(f"Refusing non-socket worker path: {socket_path}")
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.settimeout(0.25)
        probe.connect(str(socket_path))
    except (ConnectionRefusedError, FileNotFoundError):
        socket_path.unlink()
    else:
        raise RuntimeError(f"Worker socket is already active: {socket_path}")
    finally:
        probe.close()


class WorkerHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = self.server
        try:
            handshake = read_frame(self.request)
            if handshake.get("type") != "handshake" or handshake.get("protocolVersion") != PROTOCOL_VERSION:
                write_frame(self.request, {"type": "handshake", "protocolVersion": PROTOCOL_VERSION, "status": "failed", "error": "unsupported_protocol"})
                return
            write_frame(self.request, {
                "type": "handshake",
                "protocolVersion": PROTOCOL_VERSION,
                "status": "ready",
                "capabilities": {"l1Ready": True, "l2Ready": True, "l3Available": True, "l3Strategy": "multi"},
            })
            while True:
                request = read_frame(self.request)
                response = server.handle_request(request)
                write_frame(self.request, response)
        except (ConnectionError, OSError, ValueError, json.JSONDecodeError):
            return


class WorkerServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, socket_path: str, provider: PatronusProvider) -> None:
        self.provider = provider
        super().__init__(socket_path, WorkerHandler)

    def handle_request(self, request: dict[str, Any]) -> dict[str, Any]:
        request_id = request.get("requestId", "")
        phase = request.get("phase")
        deadline = request.get("deadlineMs")
        if (
            request.get("protocolVersion") != PROTOCOL_VERSION
            or phase not in {"l1", "l2", "l3"}
            or not isinstance(request.get("payload"), dict)
            or not isinstance(deadline, (int, float))
            or isinstance(deadline, bool)
            or not 0 < deadline <= 10_000
        ):
            return {"requestId": request_id, "phase": phase if phase in {"l1", "l2", "l3"} else "l1", "completion": "failed", "error": "invalid_request"}
        try:
            payload = request["payload"]
            if phase == "l1":
                value = self.provider.evaluate_l1(payload)
                return {"requestId": request_id, "phase": phase, "completion": "complete", "l1": value}
            if phase == "l2":
                value = self.provider.evaluate_l2(payload)
                return {"requestId": request_id, "phase": phase, "completion": "complete", "l2": value}
            value = self.provider.evaluate_l3(payload)
            return {"requestId": request_id, "phase": phase, "completion": "complete", "l3": value}
        except Exception as error:  # fail closed; details stay local to worker logs
            return {"requestId": request_id, "phase": phase, "completion": "failed", "error": type(error).__name__}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", default=os.environ.get("PI_SENTINEL_YOLO_AUTO_SOCKET", os.path.expanduser("~/.pi/agent/runtime/pi-sentinel/yolo-auto.sock")))
    parser.add_argument("--model-dir", default=os.environ.get("PI_SENTINEL_PATRONUS_MODEL_DIR", os.path.expanduser("~/.pi/agent/runtime/pi-sentinel/patronus/models")))
    parser.add_argument("--site-packages", default=os.environ.get("PI_SENTINEL_PATRONUS_SITE_PACKAGES"))
    parser.add_argument(
        "--download-files",
        action=argparse.BooleanOptionalAction,
        default=os.environ.get("PI_SENTINEL_PATRONUS_DOWNLOAD_FILES", "1").lower() not in {"0", "false", "no", "off"},
        help="Download missing Patronus assets during startup (default: enabled).",
    )
    args = parser.parse_args()

    model_dir = str(Path(args.model_dir).expanduser().resolve())
    socket_path = Path(args.socket).expanduser()
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(socket_path.parent, 0o700)
    provider: PatronusProvider | None = None
    server: WorkerServer | None = None
    try:
        with startup_cache_lock(model_dir):
            remove_stale_socket(socket_path)
            provider = PatronusProvider(model_dir, args.site_packages, args.download_files)
            provider.warm_all(cache_lock_held=True)
            server = WorkerServer(str(socket_path), provider)
            os.chmod(socket_path, 0o600)
            print("Patronus worker ready", file=sys.stderr, flush=True)
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    except Exception as error:
        print(f"Patronus worker unavailable: {error}", file=sys.stderr)
        return 1
    finally:
        if server is not None:
            server.server_close()
            cleanup_worker_socket(socket_path, owns_socket=True)
        if provider is not None:
            provider.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
