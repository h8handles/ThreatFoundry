from __future__ import annotations

import json
import sys
import traceback
from datetime import datetime, timezone
from typing import Any

from mcp_server import __version__


class JsonRpcError(Exception):
    def __init__(self, code: int, message: str, data: Any | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


class StdioMcpServer:
    def __init__(self) -> None:
        self._running = True

    def serve_forever(self) -> None:
        while self._running:
            message = self._read_message()
            if message is None:
                return
            self._handle_message(message)

    def _handle_message(self, message: dict[str, Any]) -> None:
        request_id = message.get("id")
        method = message.get("method")
        params = message.get("params") or {}
        if not method:
            if request_id is not None:
                self._send_error(request_id, -32600, "Invalid Request")
            return

        try:
            result = self._dispatch(method, params)
            if request_id is not None:
                self._send_result(request_id, result)
        except JsonRpcError as exc:
            if request_id is not None:
                self._send_error(request_id, exc.code, exc.message, exc.data)
        except Exception as exc:  # pragma: no cover - defensive runtime guard
            if request_id is not None:
                self._send_error(
                    request_id,
                    -32603,
                    "Internal error",
                    {"message": str(exc), "traceback": traceback.format_exc(limit=8)},
                )

    def _dispatch(self, method: str, params: dict[str, Any]) -> Any:
        if method == "initialize":
            print(
                f"[ioc-project-mcp] before_initialize ts={datetime.now(timezone.utc).isoformat()}",
                file=sys.stderr,
                flush=True,
            )
            return self._initialize()
        if method == "ping":
            return {}
        if method == "shutdown":
            self._running = False
            return {}
        if method == "notifications/initialized":
            return None
        if method == "resources/list":
            from mcp_server.resources import list_resources

            return list_resources()
        if method == "resources/read":
            from mcp_server.resources import read_resource

            uri = params.get("uri")
            if not isinstance(uri, str):
                raise JsonRpcError(-32602, "Invalid params", {"expected": "uri:string"})
            return read_resource(uri)
        if method == "tools/list":
            from mcp_server.tools import list_tools

            return list_tools()
        if method == "tools/call":
            from mcp_server.tools import call_tool

            name = params.get("name")
            if not isinstance(name, str):
                raise JsonRpcError(-32602, "Invalid params", {"expected": "name:string"})
            arguments = params.get("arguments") or {}
            if not isinstance(arguments, dict):
                raise JsonRpcError(-32602, "Invalid params", {"expected": "arguments:object"})
            return call_tool(name, arguments)
        if method == "prompts/list":
            from mcp_server.prompts import list_prompts

            return list_prompts()
        if method == "prompts/get":
            from mcp_server.prompts import get_prompt

            name = params.get("name")
            if not isinstance(name, str):
                raise JsonRpcError(-32602, "Invalid params", {"expected": "name:string"})
            arguments = params.get("arguments") or {}
            if not isinstance(arguments, dict):
                raise JsonRpcError(-32602, "Invalid params", {"expected": "arguments:object"})
            return get_prompt(name, arguments)

        raise JsonRpcError(-32601, "Method not found", {"method": method})

    def _initialize(self) -> dict[str, Any]:
        return {
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "ioc-project-mcp", "version": __version__},
            "capabilities": {
                "resources": {},
                "tools": {},
                "prompts": {},
            },
            "instructions": (
                "Use compact JSON outputs. Use allowlisted safe tools only. "
                "Avoid assumptions about missing secrets; check source_health first."
            ),
        }

    def _read_message(self) -> dict[str, Any] | None:
        headers: dict[str, str] = {}
        while True:
            line = sys.stdin.buffer.readline()
            if not line:
                return None
            if line in (b"\r\n", b"\n"):
                break
            text = line.decode("utf-8", errors="replace").strip()
            if ":" not in text:
                continue
            key, value = text.split(":", 1)
            headers[key.strip().lower()] = value.strip()

        if "content-length" not in headers:
            raise JsonRpcError(-32700, "Parse error", {"reason": "missing Content-Length"})
        try:
            content_length = int(headers["content-length"])
        except ValueError as exc:
            raise JsonRpcError(-32700, "Parse error", {"reason": "invalid Content-Length"}) from exc

        payload = sys.stdin.buffer.read(content_length)
        if len(payload) != content_length:
            return None
        try:
            return json.loads(payload.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise JsonRpcError(-32700, "Parse error", {"reason": str(exc)}) from exc

    def _send_result(self, request_id: Any, result: Any) -> None:
        message = {"jsonrpc": "2.0", "id": request_id, "result": result}
        self._write_message(message)

    def _send_error(self, request_id: Any, code: int, message: str, data: Any | None = None) -> None:
        error: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        payload = {"jsonrpc": "2.0", "id": request_id, "error": error}
        self._write_message(payload)

    def _write_message(self, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True, default=str).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        sys.stdout.buffer.write(header)
        sys.stdout.buffer.write(body)
        sys.stdout.buffer.flush()
