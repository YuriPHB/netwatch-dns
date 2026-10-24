"""Senhas, tokens de sessão e utilidades de autenticação.

A senha nunca é gravada em texto puro: usamos scrypt (derivação de chave
resistente a hardware dedicado) com salt aleatório por senha.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import string

SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 64 * 1024 * 1024
MIN_LENGTH = 8


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def hash_password(password: str) -> str:
    """Gera `scrypt$n$r$p$salt$hash`, com salt novo a cada chamada."""
    salt = os.urandom(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt,
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32, maxmem=SCRYPT_MAXMEM,
    )
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    """Compara em tempo constante; qualquer formato inválido conta como falha."""
    try:
        algo, n, r, p, salt_b64, hash_b64 = stored.split("$")
        if algo != "scrypt":
            return False
        expected = _unb64(hash_b64)
        digest = hashlib.scrypt(
            password.encode("utf-8"), salt=_unb64(salt_b64),
            n=int(n), r=int(r), p=int(p), dklen=len(expected), maxmem=SCRYPT_MAXMEM,
        )
        return hmac.compare_digest(digest, expected)
    except (ValueError, TypeError):
        return False


def password_problem(password: str) -> str | None:
    """Regras mínimas; retorna a mensagem de erro ou None se estiver ok."""
    if len(password) < MIN_LENGTH:
        return f"A senha precisa ter pelo menos {MIN_LENGTH} caracteres."
    if password.lower() == password or password.upper() == password:
        return "Use pelo menos uma letra maiúscula e uma minúscula."
    if not any(ch.isdigit() for ch in password):
        return "Inclua pelo menos um número."
    if password.lower() in {
        "senha123", "netwatch", "admin123", "12345678", "password", "qwerty123",
    }:
        return "Essa senha é fácil demais de adivinhar."
    return None


def new_token() -> str:
    """Token de sessão opaco (256 bits)."""
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    """No banco guardamos só o SHA-256 do token (vazamento não permite reuso)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_password() -> str:
    """Senha inicial aleatória, legível, com maiúscula, minúscula e número."""
    alphabet = string.ascii_lowercase + string.digits
    while True:
        core = "".join(secrets.choice(alphabet) for _ in range(12))
        pwd = secrets.choice(string.ascii_uppercase) + core + secrets.choice("23456789")
        if password_problem(pwd) is None:
            return pwd
