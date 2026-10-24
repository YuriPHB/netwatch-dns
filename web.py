"""Painel web protegido por senha + API + auditoria (HTTP puro, sem dependências)."""
from __future__ import annotations

import csv
import io
import json
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from auth import (
    MIN_LENGTH,
    hash_password,
    new_token,
    password_problem,
    token_hash,
    verify_password,
)

BASE = Path(__file__).resolve().parent
STATIC = BASE / "static"
COOKIE_NAME = "nw_session"

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'"
    ),
}


class NetWatchHandler(BaseHTTPRequestHandler):
    server_version = "NetWatch/1.1"
    sys_version = ""
    store = None       # injetado
    info: dict = {}    # injetado
    cfg: dict = {}     # injetado

    # ------------------------------------------------------------------ helpers

    def log_message(self, fmt, *args):  # silencia o log padrão
        pass

    def _ip(self) -> str:
        return self.client_address[0] if self.client_address else ""

    def _ua(self) -> str:
        return (self.headers.get("User-Agent") or "")[:160]

    def _cookies(self) -> dict[str, str]:
        raw = self.headers.get("Cookie") or ""
        jar: dict[str, str] = {}
        for part in raw.split(";"):
            if "=" in part:
                key, value = part.split("=", 1)
                jar[key.strip()] = value.strip()
        return jar

    def _session(self) -> dict | None:
        token = self._cookies().get(COOKIE_NAME)
        if not token:
            return None
        return self.store.session_valid(token_hash(token))

    def _send(self, code: int, body: bytes, content_type: str, extra: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in SECURITY_HEADERS.items():
            self.send_header(key, value)
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, obj, code: int = 200, extra: dict | None = None) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self._send(code, body, "application/json; charset=utf-8", extra)

    def _redirect(self, location: str) -> None:
        self._send(302, b"", "text/plain; charset=utf-8", {"Location": location})

    def _page(self, filename: str, code: int = 200) -> None:
        try:
            body = (STATIC / filename).read_bytes()
        except OSError:
            self._send(500, b"arquivo nao encontrado", "text/plain; charset=utf-8")
            return
        self._send(code, body, "text/html; charset=utf-8")

    def _read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
            raw = self.rfile.read(length) if length else b"{}"
            return json.loads(raw.decode("utf-8") or "{}")
        except (ValueError, OSError):
            return {}

    def _unauthorized(self, api: bool) -> None:
        if api:
            self._json({"error": "nao autenticado"}, 401)
        else:
            self._redirect("/login")

    def _audit_once(self, action: str, detail: str, window: int) -> None:
        """Evita encher a auditoria com o mesmo evento repetido."""
        ip = self._ip()
        if time.time() - self.store.last_action_ts(ip, action) >= window:
            self.store.audit(ip, action, detail, self._ua())

    # ------------------------------------------------------------------ GET

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        session = self._session()

        if path == "/favicon.ico":
            self._send(204, b"", "image/x-icon")
            return

        if path == "/login":
            if session:
                self._redirect("/")
            else:
                self._page("login.html")
            return

        if session is None:
            self._unauthorized(path.startswith("/api/"))
            return

        if path in ("/", "/index.html"):
            self._audit_once("painel_aberto", "painel carregado", 3600)
            self._page("index.html")
            return

        if path == "/api/logs":
            try:
                after_id = int(qs.get("after_id", ["0"])[0])
                limit = int(qs.get("limit", ["200"])[0])
            except ValueError:
                after_id, limit = 0, 200
            search = (qs.get("q", [""])[0] or "").strip()
            ip = (qs.get("ip", [""])[0] or "").strip()
            rows = self.store.recent(after_id=after_id, limit=limit, search=search, ip=ip)
            self._json({"rows": rows, "count": len(rows)})
            return

        if path == "/api/stats":
            self._json(self.store.stats())
            return

        if path == "/api/info":
            self._json(self.info)
            return

        if path == "/api/session":
            self._json({
                "ip": self._ip(),
                "expires": session.get("expires"),
                "since": session.get("created"),
                "agent": session.get("user_agent", ""),
                "https": bool(self.info.get("https")),
            })
            return

        if path == "/api/audit":
            try:
                limit = int(qs.get("limit", ["120"])[0])
            except ValueError:
                limit = 120
            action = (qs.get("action", [""])[0] or "").strip()
            self._json({
                "rows": self.store.audit_list(limit=limit, action=action),
                "actions": self.store.audit_actions(),
            })
            return

        if path == "/api/audit.csv":
            self.store.audit(self._ip(), "auditoria_exportada", "CSV de auditoria", self._ua())
            buf = io.StringIO()
            writer = csv.writer(buf, delimiter=";")
            writer.writerow(["data_hora", "ip", "acao", "detalhe", "dispositivo"])
            for row in self.store.audit_rows():
                stamp = datetime.fromtimestamp(row["ts"]).strftime("%Y-%m-%d %H:%M:%S")
                writer.writerow([stamp, row["ip"], row["action"], row["detail"], row["user_agent"]])
            body = buf.getvalue().encode("utf-8-sig")
            self._send(200, body, "text/csv; charset=utf-8", {
                "Content-Disposition": 'attachment; filename="netwatch-auditoria.csv"',
            })
            return

        if path == "/api/export.csv":
            self.store.audit(self._ip(), "log_exportado", "CSV de consultas", self._ua())
            buf = io.StringIO()
            writer = csv.writer(buf, delimiter=";")
            writer.writerow(["data_hora", "ip", "dispositivo", "host", "dominio", "tipo"])
            for row in self.store.export_rows():
                stamp = datetime.fromtimestamp(row["ts"]).strftime("%Y-%m-%d %H:%M:%S")
                writer.writerow([stamp, row["ip"], row["name"], row["host"], row["domain"], row["qtype"]])
            body = buf.getvalue().encode("utf-8-sig")
            self._send(200, body, "text/csv; charset=utf-8", {
                "Content-Disposition": 'attachment; filename="netwatch-log.csv"',
            })
            return

        self._json({"error": "rota nao encontrada"}, 404)

    # ------------------------------------------------------------------ POST

    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/api/login":
            self._login()
            return

        session = self._session()
        if session is None:
            self._json({"error": "nao autenticado"}, 401)
            return

        if path == "/api/logout":
            token = self._cookies().get(COOKIE_NAME, "")
            self.store.delete_session(token_hash(token))
            self.store.audit(self._ip(), "logout", "sessao encerrada", self._ua())
            self._json({"ok": True}, extra={
                "Set-Cookie": f"{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
            })
            return

        if path == "/api/devices/name":
            payload = self._read_json()
            ip = str(payload.get("ip", "")).strip()
            name = str(payload.get("name", "")).strip()
            if not ip:
                self._json({"ok": False, "error": "ip obrigatorio"}, 400)
                return
            self.store.set_device_name(ip, name)
            self.store.audit(self._ip(), "aparelho_renomeado", f"{ip} -> {name or '(vazio)'}", self._ua())
            self._json({"ok": True})
            return

        if path == "/api/password":
            self._change_password(session)
            return

        if path == "/api/reset":
            self.store.reset()
            self.store.audit(self._ip(), "dados_apagados", "historico de consultas limpo", self._ua())
            self._json({"ok": True})
            return

        self._json({"error": "rota nao encontrada"}, 404)

    # ------------------------------------------------------------------ login / senha

    def _login(self) -> None:
        ip, ua = self._ip(), self._ua()
        window = int(self.cfg.get("login_window_minutes", 10)) * 60
        limit = int(self.cfg.get("login_max_attempts", 8))

        if self.store.recent_failures(ip, window) >= limit:
            self.store.audit(ip, "login_bloqueado", "limite de tentativas excedido", ua)
            self._json(
                {"ok": False, "error": "Muitas tentativas erradas. Aguarde alguns minutos."},
                429,
            )
            return

        password = str(self._read_json().get("password", ""))
        stored = self.store.get_setting("password_hash")
        if not stored:
            self._json({"ok": False, "error": "Senha nao configurada no servidor."}, 500)
            return

        if not verify_password(password, stored):
            self.store.audit(ip, "login_fail", "senha incorreta", ua)
            self._json({"ok": False, "error": "Senha incorreta."}, 401)
            return

        token = new_token()
        hours = float(self.cfg.get("session_hours", 12))
        self.store.create_session(token_hash(token), hours, ip, ua)
        self.store.audit(ip, "login_ok", "sessao iniciada", ua)

        cookie = (
            f"{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Strict; "
            f"Max-Age={int(hours * 3600)}"
        )
        if self.info.get("https"):
            cookie += "; Secure"
        self._json(
            {"ok": True, "expires_in": int(hours * 3600), "ip": ip},
            extra={"Set-Cookie": cookie},
        )

    def _change_password(self, session: dict) -> None:
        payload = self._read_json()
        current = str(payload.get("current", ""))
        new = str(payload.get("new", ""))

        stored = self.store.get_setting("password_hash")
        if not stored or not verify_password(current, stored):
            self.store.audit(self._ip(), "senha_alterada_falha", "senha atual incorreta", self._ua())
            self._json({"ok": False, "error": "Senha atual incorreta."}, 403)
            return

        problem = password_problem(new)
        if problem:
            self._json({"ok": False, "error": problem}, 400)
            return

        self.store.set_setting("password_hash", hash_password(new))
        # derruba todas as outras sessões abertas
        token = self._cookies().get(COOKIE_NAME, "")
        self.store.delete_other_sessions(token_hash(token))
        self.store.audit(self._ip(), "senha_alterada", f"sessao de {session.get('ip','?')}", self._ua())
        self._json({"ok": True})


def make_server(store, host: str, port: int, info: dict, cfg: dict) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (NetWatchHandler,), {"store": store, "info": info, "cfg": cfg})
    ThreadingHTTPServer.allow_reuse_address = True
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server
