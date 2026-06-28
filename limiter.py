"""
limiter.py — Shared slowapi Limiter instance.

Imported by main.py (to attach to app.state) and by individual routers
(to decorate rate-limited endpoints).  Defined here to avoid circular imports
between main.py and routers.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
