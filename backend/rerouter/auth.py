"""Local administrator accounts and session tokens.

Passwords are hashed with scrypt. Sessions are random tokens stored in the
database and sent as an HttpOnly, SameSite=Strict cookie (or as a Bearer
token for scripted API access).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
import time

from .db import Database

log = logging.getLogger(__name__)

_N, _R, _P = 2**14, 8, 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(digest).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, salt_b64, digest_b64 = stored.split("$")
    except ValueError:
        return False
    if algo != "scrypt":
        return False
    salt, expected = base64.b64decode(salt_b64), base64.b64decode(digest_b64)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=len(expected))
    return hmac.compare_digest(digest, expected)


class Auth:
    def __init__(self, db: Database, ttl_hours: int = 12):
        self.db = db
        self.ttl = ttl_hours * 3600
        self._failures: dict[str, list[float]] = {}

    def ensure_admin(self, password: str | None) -> str | None:
        """Create the initial admin account. Returns a generated password if
        one had to be invented (it is logged once)."""
        if self.db.query_one("SELECT 1 FROM users LIMIT 1"):
            if password:  # explicit env password always wins (recovery path)
                self.db.execute("UPDATE users SET password=? WHERE username='admin'",
                                (hash_password(password),))
            return None
        generated = None
        if not password:
            password = generated = secrets.token_urlsafe(12)
        self.db.execute("INSERT INTO users(username, password, created) VALUES (?,?,?)",
                        ("admin", hash_password(password), time.time()))
        return generated

    def throttled(self, client: str) -> bool:
        now = time.time()
        recent = [t for t in self._failures.get(client, []) if now - t < 300]
        self._failures[client] = recent
        return len(recent) >= 10

    async def login(self, username: str, password: str, client: str) -> str | None:
        if self.throttled(client):
            return None
        row = await self.db.aquery_one("SELECT password FROM users WHERE username=?",
                                       (username,))
        ok = row is not None and await self.db.run(verify_password, password, row["password"])
        if not ok:
            self._failures.setdefault(client, []).append(time.time())
            return None
        self._failures.pop(client, None)
        token = secrets.token_urlsafe(32)
        await self.db.aexecute("INSERT INTO sessions(token, username, expires) VALUES (?,?,?)",
                               (token, username, time.time() + self.ttl))
        return token

    async def logout(self, token: str) -> None:
        await self.db.aexecute("DELETE FROM sessions WHERE token=?", (token,))

    async def user_for(self, token: str | None) -> str | None:
        if not token:
            return None
        row = await self.db.aquery_one(
            "SELECT username FROM sessions WHERE token=? AND expires > ?", (token, time.time()))
        return row["username"] if row else None

    async def change_password(self, username: str, old: str, new: str) -> bool:
        row = await self.db.aquery_one("SELECT password FROM users WHERE username=?",
                                       (username,))
        if not row or not await self.db.run(verify_password, old, row["password"]):
            return False
        await self.db.aexecute("UPDATE users SET password=? WHERE username=?",
                               (await self.db.run(hash_password, new), username))
        await self.db.aexecute("DELETE FROM sessions WHERE username=?", (username,))
        return True
