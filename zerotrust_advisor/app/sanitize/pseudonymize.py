"""Assigns stable, opaque tokens to real device/network identifiers.

Real IPs, MACs and hostnames live only in the local `identities` table.
Everything that can reach the LLM client — local or remote — goes through
`Pseudonymizer.token_for()` first and gets back a token like `device-3f9a1b2c`
instead. Tokens are derived with HMAC-SHA256 from a per-install random salt
rather than a simple counter: that keeps assignment race-free under
concurrent writers (the syslog and NetFlow receivers can both discover a new
device at the same instant, and `INSERT OR IGNORE` on a derived key needs no
read-then-write) and means the DB alone, without the salt file, isn't enough
to correlate a token back to a raw IP or MAC.
"""
from __future__ import annotations

import hashlib
import hmac
import sqlite3
from pathlib import Path

from app.config import read_secret, write_secret

_SALT_NAME = "pseudonym_salt"


def load_or_create_salt() -> bytes:
    existing = read_secret(_SALT_NAME)
    if existing:
        return bytes.fromhex(existing)
    salt = __import__("os").urandom(32)
    write_secret(_SALT_NAME, salt.hex())
    return salt


class Pseudonymizer:
    def __init__(self, conn: sqlite3.Connection, salt: bytes):
        self._conn = conn
        self._salt = salt

    def _derive(self, prefix: str, real_key: str) -> str:
        digest = hmac.new(self._salt, real_key.encode(), hashlib.sha256).hexdigest()
        return f"{prefix}-{digest[:8]}"

    def token_for(self, real_key: str, kind: str) -> str:
        """`kind` is "device" or "network"; `real_key` should already
        combine kind-relevant identity (e.g. a MAC, or a CIDR string) so
        two different real things never collide on the same key."""
        prefix = "device" if kind == "device" else "net"
        token = self._derive(prefix, real_key)
        self._conn.execute(
            "INSERT OR IGNORE INTO pseudonym_map(real_key, token, kind) VALUES (?, ?, ?)",
            (real_key, token, kind),
        )
        self._conn.commit()
        return token

    def real_key_for(self, token: str) -> str | None:
        row = self._conn.execute(
            "SELECT real_key FROM pseudonym_map WHERE token = ?", (token,)
        ).fetchone()
        return row[0] if row else None
