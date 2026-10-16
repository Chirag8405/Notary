"""Cassette keys: each lane has its own recordings."""

import hashlib

from notary_core.models import Lane


def cassette_key(lane: Lane, prompt: str) -> str:
    """sha256 of the lane and the exact prompt, so the same prompt on two lanes never collides."""
    return hashlib.sha256(f"{lane}\n{prompt}".encode()).hexdigest()
