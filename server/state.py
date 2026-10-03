"""Bounded, process-local session storage; no credentials are persisted."""

from contextlib import contextmanager
from dataclasses import dataclass, field
import secrets
import threading
import time


@dataclass
class Session:
    expires: float
    csrf: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    token: str | None = field(default=None, repr=False)
    user: dict | None = None
    oauth: dict | None = field(default=None, repr=False)


class StateFull(Exception):
    pass


class MemoryState:
    def __init__(self, ttl=28800, maximum=4096, clock=time.monotonic):
        self.ttl = ttl
        self.maximum = maximum
        self.clock = clock
        self.lock = threading.RLock()
        self.sessions = {}
        self.rates = {}
        self.user_locks = {}

    def _purge(self):
        now = self.clock()
        for sid in [sid for sid, s in self.sessions.items() if s.expires <= now]:
            del self.sessions[sid]
        for key in [key for key, (_, until) in self.rates.items() if until <= now]:
            del self.rates[key]
        for key in [key for key, (lock, users, until) in self.user_locks.items()
                    if until <= now and not users]:
            del self.user_locks[key]

    def get(self, sid):
        with self.lock:
            self._purge()
            return self.sessions.get(sid)

    def new(self):
        with self.lock:
            self._purge()
            if len(self.sessions) >= self.maximum:
                raise StateFull()
            sid = secrets.token_urlsafe(32)
            session = Session(self.clock() + self.ttl)
            self.sessions[sid] = session
            return sid, session

    def delete(self, sid):
        with self.lock:
            self.sessions.pop(sid, None)

    def allowed(self, key, count, window):
        with self.lock:
            self._purge()
            if key not in self.rates:
                if len(self.rates) >= self.maximum * 2:
                    return False
                self.rates[key] = (0, self.clock() + window)
            n, until = self.rates[key]
            if n >= count:
                return False
            self.rates[key] = (n + 1, until)
            return True

    @contextmanager
    def for_user(self, user_id):
        with self.lock:
            self._purge()
            lock, users, _ = self.user_locks.setdefault(user_id, (threading.Lock(), 0, 0))
            self.user_locks[user_id] = (lock, users + 1, self.clock() + self.ttl)
        try:
            with lock:
                yield
        finally:
            with self.lock:
                _, users, _ = self.user_locks[user_id]
                self.user_locks[user_id] = (lock, users - 1, self.clock() + self.ttl)
