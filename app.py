#!/usr/bin/env python3
"""NetWatch — registra quais sites (domínios) a rede local está acessando.

Uso:
    python app.py                 # DNS na porta 53 (precisa de admin) + painel em 8080
    python app.py --dns-port 5353 # porta alternativa, sem admin
    python app.py --demo          # dados de exemplo no painel, sem precisar configurar DNS
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import random
import socket
import sys
import threading
import time
from pathlib import Path

from auth import generate_password, hash_password, password_problem
from db import Store
from dns_proxy import DNSServer
from web import make_server

BASE = Path(__file__).resolve().parent

DEFAULT_CONFIG = {
    "dns_port": 53,
    "web_port": 8080,
    "upstreams": ["1.1.1.1", "8.8.8.8"],
    "dedupe_seconds": 45,
    "retention_days": 30,
    "session_hours": 12,
    "login_max_attempts": 8,
    "login_window_minutes": 10,
}


def load_config(path: Path) -> dict:
    cfg = dict(DEFAULT_CONFIG)
    if path.exists():
        try:
            cfg.update(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError) as exc:
            print(f"[!] config.json invalido ({exc}); usando padroes.")
    return cfg


def ensure_password(store: Store) -> None:
    """Primeira execução: pede uma senha (ou gera uma forte e mostra uma vez)."""
    if store.has_password():
        return

    password = None
    if sys.stdin.isatty():
        print()
        print("  Primeira execucao: defina a senha do painel.")
        print("  Minimo 8 caracteres, com maiuscula, minuscula e numero.")
        while True:
            first = getpass.getpass("  Senha: ")
            problem = password_problem(first)
            if problem:
                print("  !", problem)
                continue
            if first != getpass.getpass("  Confirme a senha: "):
                print("  ! As senhas nao conferem.")
                continue
            password = first
            break

    if password is None:
        password = generate_password()
        print()
        print("  " + "=" * 52)
        print("  SENHA INICIAL DO PAINEL:  " + password)
        print("  Anote agora: ela nao sera exibida de novo.")
        print("  Troque depois com: python app.py --set-password")
        print("  " + "=" * 52)

    store.set_setting("password_hash", hash_password(password))
    store.audit("console", "senha_inicial", "definida na primeira execucao", "")


def set_password_flow(store: Store) -> int:
    if not sys.stdin.isatty():
        print("[!] Abra um terminal interativo para definir a senha.")
        return 1
    first = getpass.getpass("Nova senha: ")
    problem = password_problem(first)
    if problem:
        print("[!]", problem)
        return 1
    if first != getpass.getpass("Confirme: "):
        print("[!] As senhas nao conferem.")
        return 1
    store.set_setting("password_hash", hash_password(first))
    store.delete_all_sessions()
    store.audit("console", "senha_alterada", "definida via --set-password", "")
    print("[ok] Senha atualizada (hash scrypt). Sessoes antigas encerradas.")
    return 0


def lan_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"
    finally:
        s.close()


def resolve_hostnames(store: Store, stop: threading.Event) -> None:
    """Preenche o hostname dos aparelhos via DNS reverso (best effort)."""
    while not stop.wait(25):
        try:
            devices = store.stats().get("devices", [])
        except Exception:
            continue
        for dev in devices:
            ip = dev.get("ip", "")
            if not ip or dev.get("host") or not ip.startswith(("192.168.", "10.", "172.")):
                continue
            if stop.is_set():
                return
            try:
                host = socket.gethostbyaddr(ip)[0]
            except (OSError, socket.herror):
                host = ""
            if host and host != ip:
                store.set_device_host(ip, host)


def cleanup_loop(store: Store, days: int, stop: threading.Event) -> None:
    while not stop.wait(3600):
        try:
            removed = store.cleanup(days)
            if removed:
                print(f"[i] retencao: {removed} registros antigos removidos")
        except Exception:
            pass


DEMO_DOMAINS = [
    "www.google.com", "www.youtube.com", "i.ytimg.com", "www.instagram.com",
    "scontent.cdninstagram.com", "web.whatsapp.com", "mmg.whatsapp.net",
    "www.tiktok.com", "api.tiktok.com", "www.netflix.com", "ipv4-c001.netflix.com",
    "www.amazon.com.br", "m.media-amazon.com", "www.mercadolivre.com.br",
    "http2.mlstatic.com", "www.globo.com", "g1.globo.com", "s2.glbimg.com",
    "www.uol.com.br", "www.microsoft.com", "login.microsoftonline.com",
    "outlook.office365.com", "github.com", "api.github.com",
    "www.twitch.tv", "static.twitchcdn.net", "discord.com", "cdn.discordapp.com",
    "open.spotify.com", "i.scdn.co", "www.reddit.com", "steamcommunity.com",
]


def demo_loop(store: Store, stop: threading.Event) -> None:
    names = ["Celular da sala", "Notebook", "TV", "Tablet", "PC trabalho"]
    ips = [f"192.168.31.{n}" for n in (101, 102, 103, 104, 120)]
    for ip, name in zip(ips, names):
        store.set_device_name(ip, name)

    while not stop.wait(random.uniform(1.0, 3.0)):
        ip = random.choice(ips)
        domain = random.choice(DEMO_DOMAINS)
        store.add_query(ip, domain, "A")


def main() -> int:
    parser = argparse.ArgumentParser(description="Monitor de sites acessados na rede local")
    parser.add_argument("--dns-port", type=int, default=None, help="porta do DNS (padrao: 53)")
    parser.add_argument("--web-port", type=int, default=None, help="porta do painel (padrao: 8080)")
    parser.add_argument("--db", default=None, help="arquivo do banco SQLite")
    parser.add_argument("--config", default=str(BASE / "config.json"))
    parser.add_argument("--demo", action="store_true", help="gera trafego de exemplo")
    parser.add_argument("--no-open", action="store_true", help="nao abrir o navegador")
    parser.add_argument("--set-password", action="store_true", help="define/troca a senha do painel")
    parser.add_argument("--cert", default=None, help="certificado TLS (PEM) para servir HTTPS")
    parser.add_argument("--key", default=None, help="chave TLS (PEM) correspondente")
    args = parser.parse_args()

    cfg = load_config(Path(args.config))
    dns_port = args.dns_port or int(cfg["dns_port"])
    web_port = args.web_port or int(cfg["web_port"])
    db_path = args.db or str(BASE / ("netwatch-demo.db" if args.demo else "netwatch.db"))

    store = Store(db_path)

    if args.set_password:
        return set_password_flow(store)

    ensure_password(store)

    dns = DNSServer(
        store,
        host="0.0.0.0",
        port=dns_port,
        upstreams=tuple(cfg["upstreams"]),
        dedupe_seconds=int(cfg["dedupe_seconds"]),
    )
    try:
        dns.start()
    except OSError as exc:
        print()
        print("[!] Nao foi possivel abrir a porta DNS", dns_port, "-", exc)
        if os.name == "nt":
            print("    A porta 53 exige privilegios de administrador e precisa estar livre.")
            print("    Feche outros servidores DNS/Pi-hole e abra o terminal como administrador,")
            print("    ou teste com: python app.py --dns-port 5353")
        else:
            print("    Rode com sudo ou use --dns-port 5353")
        print()
        return 1

    ip = lan_ip()
    info = {
        "lan_ip": ip,
        "dns_port": dns_port,
        "web_port": web_port,
        "upstreams": list(cfg["upstreams"]),
        "db": db_path,
        "demo": bool(args.demo),
    }

    scheme = "http"
    if args.cert and args.key:
        import ssl

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(args.cert, args.key)
        info["https"] = True
        scheme = "https"

    try:
        server = make_server(store, "0.0.0.0", web_port, info, cfg)
    except OSError as exc:
        print(f"[!] Nao foi possivel abrir o painel na porta {web_port}: {exc}")
        dns.stop()
        return 1

    if scheme == "https":
        server.socket = context.wrap_socket(server.socket, server_side=True)

    web_thread = threading.Thread(target=server.serve_forever, name="web", daemon=True)
    web_thread.start()

    stop = threading.Event()
    threading.Thread(target=resolve_hostnames, args=(store, stop), daemon=True).start()
    threading.Thread(
        target=cleanup_loop, args=(store, int(cfg["retention_days"]), stop), daemon=True
    ).start()
    if args.demo:
        threading.Thread(target=demo_loop, args=(store, stop), daemon=True).start()

    url = f"{scheme}://{ip}:{web_port}"
    print()
    print("  NetWatch no ar")
    print("  " + "-" * 52)
    print(f"  Painel:      {url}")
    print("  Acesso:      protegido por senha (hash scrypt)")
    print(f"  DNS local:   {ip}:{dns_port}")
    print(f"  Banco:       {db_path}")
    print(f"  Upstream:    {', '.join(cfg['upstreams'])}")
    if args.demo:
        print("  Modo demo:   gerando consultas de exemplo")
    print("  " + "-" * 52)
    print("  Aponte o DNS do roteador (ou dos aparelhos) para o IP acima.")
    print("  Ctrl+C para encerrar.")
    print()

    if not args.no_open:
        try:
            import webbrowser

            webbrowser.open(url)
        except Exception:
            pass

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nEncerrando…")
    finally:
        stop.set()
        server.shutdown()
        server.server_close()
        dns.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
