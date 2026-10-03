"""Opaque KDBX synchronization service. Decryption belongs exclusively to the browser."""

from .app import create_app

__all__ = ["create_app"]
