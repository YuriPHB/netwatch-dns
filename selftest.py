"""Teste ponta a ponta do NetWatch (sem admin, sem porta 53).

    python selftest.py
"""
from __future__ import annotations

import http.cookiejar
import json
import os
import socket
import struct
import tempfile
import threading
import time
import urllib.error
import urllib.request

from auth import hash_password, verify_password
from db import Store
from dns_proxy import DNSServer, parse_question
from web import make_server

BASE_URL = "http://127.0.0.1:8099"
PASSWORD = "SenhaForte123"


def build_query(name: str, qtype: int = 1, qid: int = 0x4242) -> bytes:
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.split(".")) + b"\x00"
    return header + qname + struct.pack("!HH", qtype, 1)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def call(opener, path: str, payload: dict | None = None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        BASE_URL + path,
        data=data,
        headers={"Content-Type": "application/json"} if data else {},
        method="POST" if data is not None else "GET",
    )
    try:
        with opener.open(req, timeout=8) as res:
            return res.status, res.read(), dict(res.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers)


def main() -> int:
    # 1) parser + hash
    parsed = parse_question(build_query("www.exemplo.com.br"))
    assert parsed == ("www.exemplo.com.br", "A"), parsed
    print("[ok] parser DNS:", parsed)

    stored = hash_password(PASSWORD)
    assert stored.startswith("scrypt$") and PASSWORD not in stored
    assert verify_password(PASSWORD, stored) and not verify_password("errada", stored)
    print("[ok] hash scrypt com salt (senha nao fica em texto puro)")

    db_path = os.path.join(tempfile.gettempdir(), f"netwatch-selftest-{os.getpid()}.db")
    store = Store(db_path)
    store.set_setting("password_hash", stored)

    dns = DNSServer(store, host="127.0.0.1", port=5353, upstreams=("1.1.1.1",), dedupe_seconds=0)
    dns.start()

    cfg = {"session_hours": 12, "login_max_attempts": 8, "login_window_minutes": 10}
    server = make_server(store, "127.0.0.1", 8099, {"lan_ip": "127.0.0.1", "dns_port": 5353}, cfg)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    jar = http.cookiejar.CookieJar()
    auth = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    # 2) acesso sem senha
    status, body, _ = call(urllib.request.build_opener(), "/api/stats")
    assert status == 401, status
    print("[ok] API sem login bloqueada (401)")

    status, body, _ = call(urllib.request.build_opener(NoRedirect), "/")
    assert status == 302, status
    print("[ok] painel sem login redireciona para /login")

    status, body, _ = call(urllib.request.build_opener(), "/login")
    assert status == 200 and b"Senha" in body
    print("[ok] tela de login disponivel")

    # 3) senha errada
    status, body, _ = call(auth, "/api/login", {"password": "chute errado"})
    assert status == 401, status
    print("[ok] senha errada rejeitada (401)")

    # 4) senha correta
    status, body, headers = call(auth, "/api/login", {"password": PASSWORD})
    assert status == 200 and json.loads(body)["ok"], (status, body)
    cookie = headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie, cookie
    print("[ok] login ok | cookie:", cookie.split(";")[0][:24] + "… (HttpOnly, SameSite=Strict)")

    status, _, _ = call(auth, "/api/stats")
    assert status == 200, status
    print("[ok] painel/API liberados com sessao")

    # 5) consultas DNS (UDP + TCP)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    for domain in ("www.exemplo.com.br", "api.github.com", "cdn.exemplo.net"):
        sock.sendto(build_query(domain), ("127.0.0.1", 5353))
        try:
            sock.recvfrom(4096)
        except socket.timeout:
            pass
    sock.close()

    with socket.create_connection(("127.0.0.1", 5353), timeout=3) as tcp:
        payload = build_query("tcp.exemplo.org")
        tcp.sendall(struct.pack("!H", len(payload)) + payload)
        try:
            tcp.settimeout(1.0)
            tcp.recv(2)
        except OSError:
            pass

    deadline = time.time() + 5
    while time.time() < deadline:
        if store.stats()["today_total"] >= 4:
            break
        time.sleep(0.2)

    status, body, _ = call(auth, "/api/logs?limit=20")
    rows = json.loads(body)["rows"]
    domains = sorted({r["domain"] for r in rows})
    assert "api.github.com" in domains and "tcp.exemplo.org" in domains, domains
    print("[ok] DNS UDP+TCP registrados:", domains)

    # 6) auditoria com IP
    status, body, _ = call(auth, "/api/audit?limit=50")
    audit = json.loads(body)
    actions = {r["action"] for r in audit["rows"]}
    assert {"login_ok", "login_fail"} <= actions, actions
    assert all(r["ip"] == "127.0.0.1" for r in audit["rows"])
    print("[ok] auditoria registra IP:", [r["action"] for r in audit["rows"]][:4])

    status, body, _ = call(auth, "/api/audit.csv")
    assert b"ip" in body and b"127.0.0.1" in body
    print("[ok] auditoria exportavel em CSV")

    # 7) troca de senha
    status, _, _ = call(auth, "/api/password", {"current": "errada", "new": "NovaSenha456"})
    assert status == 403, status
    status, _, _ = call(auth, "/api/password", {"current": PASSWORD, "new": "fraca"})
    assert status == 400, status
    status, _, _ = call(auth, "/api/password", {"current": PASSWORD, "new": "NovaSenha456"})
    assert status == 200, status
    print("[ok] troca de senha validada (atual errada/fraco bloqueados)")

    other = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    status, _, _ = call(other, "/api/login", {"password": PASSWORD})
    assert status == 401, status
    status, _, _ = call(other, "/api/login", {"password": "NovaSenha456"})
    assert status == 200, status
    print("[ok] senha antiga nao vale mais; nova entra")

    # 8) logout
    status, _, _ = call(auth, "/api/logout", {})
    assert status == 200, status
    status, _, _ = call(auth, "/api/stats")
    assert status == 401, status
    print("[ok] logout encerra a sessao")

    server.shutdown()
    server.server_close()
    dns.stop()
    try:
        os.remove(db_path)
        for suffix in ("-wal", "-shm"):
            if os.path.exists(db_path + suffix):
                os.remove(db_path + suffix)
    except OSError:
        pass

    print("\nTudo certo: login, auditoria, DNS e API funcionando.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
