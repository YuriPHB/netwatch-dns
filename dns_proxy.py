"""Proxy DNS local: registra o domínio consultado e repassa para o DNS upstream."""
from __future__ import annotations

import logging
import socket
import struct
import threading
import time

log = logging.getLogger("netwatch.dns")

QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
    28: "AAAA", 33: "SRV", 35: "NAPTR", 43: "DS", 46: "RRSIG", 48: "DNSKEY",
    52: "TLSA", 64: "SVCB", 65: "HTTPS", 255: "ANY",
}

# Domínios de ruído que o sistema operacional consulta o tempo todo.
IGNORED_SUFFIXES = (
    ".arpa",
    "localhost",
    "_msdcs",
    "wpad",
)

SKIP_TYPES = {12, 33, 35, 43, 46, 48, 52}  # PTR/SRV/etc: muito ruído, pouco valor


def qtype_name(value: int) -> str:
    return QTYPES.get(value, str(value))


def parse_question(data: bytes) -> tuple[str, str] | None:
    """Extrai (domínio, tipo) da primeira pergunta de um pacote DNS."""
    if len(data) < 12:
        return None
    try:
        qdcount = struct.unpack("!H", data[4:6])[0]
        if qdcount < 1:
            return None

        i = 12
        labels: list[str] = []
        while True:
            if i >= len(data):
                return None
            length = data[i]
            if length == 0:
                i += 1
                break
            if length & 0xC0:  # ponteiro de compressão (não deveria ocorrer aqui)
                i += 2
                break
            i += 1
            label = data[i:i + length]
            if len(label) < length:
                return None
            labels.append(label.decode("ascii", "replace"))
            i += length

        qtype = 0
        if i + 2 <= len(data):
            qtype = struct.unpack("!H", data[i:i + 2])[0]

        name = ".".join(labels).strip(".").lower()
        if not name:
            return None
        return name, qtype_name(qtype)
    except (struct.error, IndexError, UnicodeError):
        return None


class DNSServer:
    def __init__(
        self,
        store,
        host: str = "0.0.0.0",
        port: int = 53,
        upstreams: tuple[str, ...] = ("1.1.1.1", "8.8.8.8"),
        dedupe_seconds: int = 45,
        timeout: float = 3.0,
    ):
        self.store = store
        self.host = host
        self.port = port
        self.upstreams = upstreams
        self.dedupe_seconds = max(0, dedupe_seconds)
        self.timeout = timeout

        self._sock: socket.socket | None = None
        self._tcp_sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = False
        self._seen: dict[tuple[str, str, str], float] = {}
        self._seen_lock = threading.Lock()

    # ---------------------------------------------------------------- ciclo de vida

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.settimeout(0.5)
        self._sock = sock
        self._running = True
        self._thread = threading.Thread(target=self._loop, name="dns-server", daemon=True)
        self._thread.start()

        # DNS sobre TCP (respostas grandes / truncadas) — opcional.
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            tcp.bind((self.host, self.port))
            tcp.listen(32)
            tcp.settimeout(0.5)
            self._tcp_sock = tcp
            threading.Thread(target=self._tcp_loop, name="dns-tcp", daemon=True).start()
        except OSError as exc:
            log.warning("DNS/TCP indisponivel na porta %s: %s", self.port, exc)
            tcp.close()

        log.info("DNS ouvindo em %s:%s (UDP+TCP)", self.host, self.port)

    def stop(self) -> None:
        self._running = False
        for sock in (self._sock, self._tcp_sock):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        if self._thread is not None:
            self._thread.join(timeout=2)

    # ---------------------------------------------------------------- interno

    def _loop(self) -> None:
        assert self._sock is not None
        while self._running:
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle, args=(data, addr), daemon=True
            ).start()

    def _tcp_loop(self) -> None:
        assert self._tcp_sock is not None
        while self._running:
            try:
                conn, addr = self._tcp_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle_tcp, args=(conn, addr[0]), daemon=True
            ).start()

    @staticmethod
    def _recv_exact(conn: socket.socket, size: int) -> bytes | None:
        buf = b""
        while len(buf) < size:
            chunk = conn.recv(size - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def _handle_tcp(self, conn: socket.socket, client_ip: str) -> None:
        conn.settimeout(5.0)
        try:
            while self._running:
                head = self._recv_exact(conn, 2)
                if not head:
                    return
                length = struct.unpack("!H", head)[0]
                if not length:
                    return
                data = self._recv_exact(conn, length)
                if not data:
                    return
                if len(data) >= 4 and not (data[2] & 0x80):
                    self._record(data, client_ip)
                response = self._forward_tcp(data)
                if response is None:
                    return
                conn.sendall(struct.pack("!H", len(response)) + response)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _handle(self, data: bytes, addr: tuple[str, int]) -> None:
        # Só consultas (QR=0) entram no log.
        if len(data) >= 4 and not (data[2] & 0x80):
            self._record(data, addr[0])
        self._forward(data, addr)

    def _record(self, data: bytes, client_ip: str) -> None:
        parsed = parse_question(data)
        if not parsed:
            return
        domain, qtype = parsed
        if qtype in {str(t) for t in SKIP_TYPES}:
            return
        if domain.endswith(IGNORED_SUFFIXES):
            return

        key = (client_ip, domain, qtype)
        now = time.time()
        with self._seen_lock:
            last = self._seen.get(key, 0.0)
            if now - last < self.dedupe_seconds:
                return
            self._seen[key] = now
            if len(self._seen) > 8000:  # limpeza ocasional
                cutoff = now - max(self.dedupe_seconds, 120)
                for k, ts in list(self._seen.items()):
                    if ts < cutoff:
                        del self._seen[k]

        try:
            self.store.add_query(client_ip, domain, qtype, now)
        except Exception:  # banco nunca deve derrubar o DNS
            log.exception("falha ao gravar consulta %s", domain)

    def _forward_tcp(self, data: bytes) -> bytes | None:
        for upstream in self.upstreams:
            try:
                with socket.create_connection((upstream, 53), timeout=self.timeout) as conn:
                    conn.sendall(struct.pack("!H", len(data)) + data)
                    head = self._recv_exact(conn, 2)
                    if not head:
                        continue
                    length = struct.unpack("!H", head)[0]
                    if not length:
                        continue
                    return self._recv_exact(conn, length)
            except OSError:
                continue
        return None

    def _forward(self, data: bytes, addr: tuple[str, int]) -> None:
        upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream_sock.settimeout(self.timeout)
        try:
            for upstream in self.upstreams:
                try:
                    upstream_sock.sendto(data, (upstream, 53))
                    response, _ = upstream_sock.recvfrom(4096)
                    if self._sock is not None:
                        self._sock.sendto(response, addr)
                    return
                except (socket.timeout, OSError):
                    continue
        finally:
            upstream_sock.close()
